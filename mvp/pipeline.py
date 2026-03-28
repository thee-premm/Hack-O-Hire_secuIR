import pandas as pd
import pickle
import numpy as np
from collections import defaultdict
from state.session_manager import SessionManager
from state.baseline_manager import BaselineManager
from state.risk_memory import RiskMemory
from features.core_builder import CoreFeatureBuilder
from features.extended_builder import ExtendedFeatureBuilder

class DetectionPipeline:
    def __init__(self):
        self.session_mgr = SessionManager()
        self.baseline_mgr = BaselineManager()
        self.risk_memory = RiskMemory()
        self.core_builder = CoreFeatureBuilder(self.session_mgr, self.baseline_mgr, self.risk_memory)
        self.ext_builder = ExtendedFeatureBuilder(self.risk_memory)
        # Load models
        with open('models/lr_model.pkl', 'rb') as f:
            self.lr_model, self.lr_scaler = pickle.load(f)
        with open('models/iso_model.pkl', 'rb') as f:
            self.iso_model, self.iso_scaler = pickle.load(f)
        # We'll also need to track user's last event for geo-velocity etc. For MVP we skip.
    
    def process_event(self, event):
        # 1. Update state
        session = self.session_mgr.get_or_create_session(event['user_id'], event['session_id'], event['timestamp'])
        self.session_mgr.update_session(event['session_id'], event)
        self.baseline_mgr.update(event['user_id'], event)
        
        # 2. Core features
        core_feat = self.core_builder.build(event, session)
        # Convert to vector
        core_vector = np.array([
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
        core_vector_scaled = self.lr_scaler.transform(core_vector)
        
        # 3. Lightweight model
        micro_risk = self.lr_model.predict_proba(core_vector_scaled)[0][1]
        print(f"Micro risk: {micro_risk:.3f}")
        
        # 4. Control layer
        bypass = (micro_risk >= 0.7) or (core_feat['is_new_payee'] == 1 and core_feat['country_risk'] > 0.7)
        
        # 5. Decide if deep models needed
        final_risk = micro_risk
        incident_type = 'benign'
        if bypass or micro_risk >= 0.3:
            # Build extended features
            ext_feat = self.ext_builder.build(event['user_id'], event)
            # For MVP, just use extended trend with the core vector
            ext_vector = np.hstack([core_vector_scaled[0], ext_feat['risk_trend']]).reshape(1, -1)
            # For isolation forest, we need to use the same scaler (we'll just use core scaled for now)
            anomaly_score = self.iso_model.decision_function(core_vector_scaled)[0]  # negative if anomaly
            # Convert to [0,1] where higher is more anomalous
            anomaly_score = 1 / (1 + np.exp(-anomaly_score))  # sigmoid
            # Combine
            final_risk = 0.7 * micro_risk + 0.3 * anomaly_score
            incident_type = 'suspicious' if final_risk > 0.5 else 'low_risk'
            print(f"Deep analysis: anomaly={anomaly_score:.3f}, final_risk={final_risk:.3f}")
        else:
            print("Benign, no deep analysis.")
        
        # 6. Update risk memory
        self.risk_memory.update(event['user_id'], micro_risk)
        
        # 7. Simple decision rule (mock)
        if final_risk > 0.7:
            action = "BLOCK"
        elif final_risk > 0.4:
            action = "MFA_CHALLENGE"
        else:
            action = "LOG_ONLY"
        print(f"Action: {action}\n")
        return {'action': action, 'risk': final_risk, 'type': incident_type}
