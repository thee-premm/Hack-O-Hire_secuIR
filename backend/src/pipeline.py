import pandas as pd
import pickle
import numpy as np
import os
import uuid
from datetime import datetime
from collections import defaultdict

# Base directory for resolving relative paths (src/)
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
from state.session_manager import SessionManager
from state.baseline_manager import BaselineManager
from state.risk_memory import RiskMemory
from features.core_builder import CoreFeatureBuilder
from features.extended_builder import ExtendedFeatureBuilder
from ingestion.normalizer import LogNormalizer
from ingestion.deduplicator import Deduplicator
from ingestion.reorderer import TimestampReorderer
from response.engine import ResponseEngine, Action
from response.playbook import PlaybookGenerator

class DetectionPipeline:
    def __init__(self):
        # Ingestion components
        self.normalizer = LogNormalizer()
        self.deduplicator = Deduplicator(window_seconds=60)
        self.reorderer = TimestampReorderer(buffer_seconds=5)
        
        # Response components
        self.response_engine = ResponseEngine()
        self.playbook_gen = PlaybookGenerator()
        
        # Existing components
        self.session_mgr = SessionManager()
        self.baseline_mgr = BaselineManager()
        self.risk_memory = RiskMemory()
        self.core_builder = CoreFeatureBuilder(self.session_mgr, self.baseline_mgr, self.risk_memory)
        self.ext_builder = ExtendedFeatureBuilder(self.risk_memory)
        
        # Load models (resolve relative to src/ directory)
        with open(os.path.join(_BASE_DIR, 'models', 'lr_model.pkl'), 'rb') as f:
            self.lr_model, self.lr_scaler = pickle.load(f)
        with open(os.path.join(_BASE_DIR, 'models', 'iso_model.pkl'), 'rb') as f:
            self.iso_model, self.iso_scaler = pickle.load(f)
        
        # Track processed events for evidence
        self.evidence_store = {}
    
    def process_event(self, event):
        """Legacy method: process a pre-normalized event dict (backward compatible)"""
        # 1. Update state
        session = self.session_mgr.get_or_create_session(event['user_id'], event['session_id'], event['timestamp'])
        self.session_mgr.update_session(event['session_id'], event)
        self.baseline_mgr.update(event['user_id'], event)
        
        # 2. Core features
        core_feat = self.core_builder.build(event, session)
        # Convert to vector
        core_vector = self._build_core_vector(core_feat)
        core_vector_scaled = self.lr_scaler.transform(core_vector)
        
        # 3. Lightweight model
        micro_risk = self.lr_model.predict_proba(core_vector_scaled)[0][1]
        print(f"Micro risk: {micro_risk:.3f}")
        
        # 4. Control layer
        bypass = (micro_risk >= 0.7) or (core_feat.get('is_new_payee', 0) == 1 and core_feat.get('country_risk', 0) > 0.7)
        
        # 5. Decide if deep models needed
        final_risk = micro_risk
        incident_type = 'benign'
        if bypass or micro_risk >= 0.3:
            # Build extended features
            ext_feat = self.ext_builder.build(event['user_id'], event)
            # For isolation forest, use core scaled
            anomaly_score = self.iso_model.decision_function(core_vector_scaled)[0]
            # Convert to [0,1] where higher is more anomalous
            anomaly_score = 1 / (1 + np.exp(-anomaly_score))
            # Combine
            final_risk = 0.7 * micro_risk + 0.3 * anomaly_score
            incident_type = 'suspicious' if final_risk > 0.5 else 'low_risk'
            print(f"Deep analysis: anomaly={anomaly_score:.3f}, final_risk={final_risk:.3f}")
        else:
            print("Benign, no deep analysis.")
        
        # 6. Update risk memory
        self.risk_memory.update(event['user_id'], micro_risk)
        
        # 7. Simple decision rule (legacy)
        if final_risk > 0.7:
            action = "BLOCK"
        elif final_risk > 0.4:
            action = "MFA_CHALLENGE"
        else:
            action = "LOG_ONLY"
        print(f"Action: {action}\n")
        return {'action': action, 'risk': final_risk, 'type': incident_type}
    
    def process_raw_log(self, raw_log: dict, format_type: str = 'json') -> dict:
        """
        Process raw log from any source with full enhancement pipeline.
        Handles normalization, deduplication, reordering, detection, and response.
        """
        # 1. Normalize to canonical schema
        normalized = self.normalizer.normalize(raw_log, format_type)
        
        # 2. Deduplicate
        if self.deduplicator.is_duplicate(normalized):
            return {
                'status': 'duplicate',
                'action': 'ignored',
                'message': 'Duplicate event detected and ignored'
            }
        
        # 3. Reorder by timestamp
        self.reorderer.add_event(normalized)
        
        # 4. Process events in order
        results = []
        for event in self.reorderer.get_ordered_events():
            result = self._process_event(event)
            results.append(result)
        
        # If no events were ready (still buffered), flush to ensure processing
        if not results:
            for event in self.reorderer.flush():
                result = self._process_event(event)
                results.append(result)
        
        # Return latest result if any
        return results[-1] if results else {'status': 'buffered'}
    
    def _process_event(self, event: dict) -> dict:
        """Process a single normalized event through detection + response pipeline"""
        
        # Generate incident ID
        event['incident_id'] = str(uuid.uuid4())[:8]
        
        # Update state
        session = self.session_mgr.get_or_create_session(
            event['user_id'], event['session_id'], event['timestamp']
        )
        self.session_mgr.update_session(event['session_id'], event)
        self.baseline_mgr.update(event['user_id'], event)
        
        # Build core features
        core_feat = self.core_builder.build(event, session)
        
        # Build core vector
        core_vector = self._build_core_vector(core_feat)
        core_vector_scaled = self.lr_scaler.transform(core_vector)
        
        # Lightweight model
        micro_risk = self.lr_model.predict_proba(core_vector_scaled)[0][1]
        
        # Control layer
        bypass = (micro_risk >= 0.7) or (core_feat.get('is_new_payee', 0) == 1 and core_feat.get('country_risk', 0) > 0.7)
        
        # Deep analysis if needed
        final_risk = micro_risk
        incident_type = 'benign'
        anomaly_score = 0
        
        if bypass or micro_risk >= 0.3:
            ext_feat = self.ext_builder.build(event['user_id'], event)
            anomaly_score = self.iso_model.decision_function(core_vector_scaled)[0]
            anomaly_score = 1 / (1 + np.exp(-anomaly_score))
            final_risk = 0.7 * micro_risk + 0.3 * anomaly_score
            incident_type = 'suspicious' if final_risk > 0.5 else 'low_risk'
        
        # Heuristic risk boosters for patterns ML may miss
        # Large transaction to new payee
        event_amount = event.get('amount') or 0
        if event_amount > 10000:
            final_risk = max(final_risk, 0.85)
            incident_type = 'suspicious'
        
        # New payee in high-risk country
        if event.get('is_new_payee', False) and event.get('payee_country') in ['NG', 'RU', 'CN', 'KP', 'IR']:
            final_risk = max(final_risk, 0.75)
            incident_type = 'suspicious'
        
        # Insider threat pattern: employee exporting sensitive data
        if event.get('user_type') == 'employee' and event.get('admin_action') == 'export_customers':
            final_risk = max(final_risk, 0.8)
            incident_type = 'insider_threat'
        
        # Failed login attempts (from event metadata or core features)
        failed_attempts = event.get('failed_attempts_last_minute', 0) or core_feat.get('failed_attempts_last_minute', 0)
        if failed_attempts >= 5:
            final_risk = max(final_risk, 0.6)
            incident_type = 'credential_stuffing'
        
        # Update risk memory
        self.risk_memory.update(event['user_id'], micro_risk)
        
        # Build incident object
        incident = {
            'incident_id': event['incident_id'],
            'timestamp': event['timestamp'],
            'user_id': event['user_id'],
            'user_type': event.get('user_type', 'customer'),
            'user_tier': event.get('account_tier', 'basic'),
            'event_type': event['event_type'],
            'final_risk': final_risk,
            'micro_risk': micro_risk,
            'anomaly_score': anomaly_score,
            'incident_type': incident_type,
            'is_new_payee': core_feat.get('is_new_payee', 0) or event.get('is_new_payee', False),
            'country_risk': core_feat.get('country_risk', 0),
            'device_match_score': core_feat.get('device_match_score', 1),
            'location_deviation_km': core_feat.get('location_deviation_km', 0),
            'failed_attempts_last_minute': failed_attempts,
            'amount': event_amount,
            'core_features': core_feat,
            'raw_event': event
        }
        
        # Get user context for response
        user_context = self._get_user_context(event['user_id'], event)
        
        # Response engine decision
        decision = self.response_engine.decide(incident, user_context)
        
        # Collect evidence
        evidence = self._collect_evidence(incident, event, session, core_feat)
        
        # Generate playbook
        playbook = self.playbook_gen.generate(incident, decision, evidence)
        
        # Store evidence for audit
        self.evidence_store[incident['incident_id']] = {
            'incident': incident,
            'decision': decision,
            'playbook': playbook,
            'timestamp': datetime.now()
        }
        
        return {
            'status': 'processed',
            'incident': incident,
            'decision': decision,
            'playbook': playbook
        }
    
    def _build_core_vector(self, core_feat: dict) -> np.ndarray:
        """Build core vector from features"""
        return np.array([
            core_feat['hour_of_day'],
            core_feat['day_of_week'],
            core_feat['session_event_count'],
            core_feat['session_entropy'],
            core_feat['session_avg_rate'],
            core_feat['login_hour_deviation'],
            core_feat['device_match_score'],
            core_feat['location_deviation_km'],
            core_feat['cumulative_risk'],
            core_feat['last_window_risk'],
            core_feat['transaction_amount_zscore']
        ]).reshape(1, -1)
    
    def _get_user_context(self, user_id: str, event: dict = None) -> dict:
        """Get user context for response decisions"""
        baseline = self.baseline_mgr.user_baseline.get(user_id, {})
        # Tier: check event first (current request), then baseline, then default
        tier = 'basic'
        if event and event.get('account_tier'):
            tier = event['account_tier']
        elif baseline.get('account_tier'):
            tier = baseline['account_tier']
        return {
            'user_id': user_id,
            'tier': tier,
            'user_type': event.get('user_type', 'customer') if event else 'customer',
            'has_history': len(baseline.get('login_hours', [])) > 0,
            'device_count': len(baseline.get('devices', set())),
            'location_count': len(baseline.get('locations', set()))
        }
    
    def _collect_evidence(self, incident: dict, event: dict, session: dict, core_feat: dict) -> dict:
        """Collect evidence for playbook"""
        return {
            'core_features': {k: v for k, v in core_feat.items() if isinstance(v, (int, float))},
            'session_info': {
                'event_count': session.get('event_count', 0),
                'duration_minutes': (event['timestamp'] - session.get('start_time', event['timestamp'])).total_seconds() / 60
            },
            'model_outputs': {
                'micro_risk': incident.get('micro_risk'),
                'final_risk': incident.get('final_risk'),
                'anomaly_score': incident.get('anomaly_score')
            },
            'raw_event_summary': {
                'event_type': event.get('event_type'),
                'user_id': event.get('user_id'),
                'timestamp': event.get('timestamp').isoformat() if event.get('timestamp') else None,
                'amount': event.get('amount'),
                'is_new_payee': core_feat.get('is_new_payee')
            }
        }
