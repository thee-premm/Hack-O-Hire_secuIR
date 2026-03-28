import numpy as np
from datetime import datetime

class CoreFeatureBuilder:
    def __init__(self, session_manager, baseline_manager, risk_memory):
        self.session_mgr = session_manager
        self.baseline_mgr = baseline_manager
        self.risk_memory = risk_memory
    
    def build(self, event, session):
        features = {}
        # Event-level
        features['hour_of_day'] = event['timestamp'].hour
        features['day_of_week'] = event['timestamp'].weekday()
        # Session-level
        sess_feat = self.session_mgr.get_session_features(session['session_id'])
        if sess_feat:
            features['session_event_count'] = sess_feat['event_count']
            features['session_entropy'] = sess_feat['entropy']
            features['session_avg_rate'] = sess_feat['avg_rate']
        else:
            features['session_event_count'] = 0
            features['session_entropy'] = 0
            features['session_avg_rate'] = 0
        # Baseline deviation
        baseline = self.baseline_mgr.get_baseline_features(event['user_id'], event)
        features['login_hour_deviation'] = baseline['login_hour_deviation']
        features['device_match_score'] = baseline['device_match']
        features['location_deviation_km'] = 0  # simplified; we can compute from lat/lon later
        # Risk memory
        risk_feat = self.risk_memory.get_features(event['user_id'])
        features['cumulative_risk'] = risk_feat['cumulative_risk']
        features['last_window_risk'] = risk_feat['last_window_risk']
        # Transaction features if present
        if event['event_type'] == 'transaction':
            amount = event.get('amount', 0)
            avg = baseline.get('avg_transaction_amount', 0)
            if avg > 0:
                features['transaction_amount_zscore'] = (amount - avg) / (np.std(baseline.get('transaction_amounts', [1])) or 1)
            else:
                features['transaction_amount_zscore'] = 0
            features['is_new_payee'] = 1 if event.get('is_new_payee', False) else 0
            features['country_risk'] = event.get('country_risk', 0)
        else:
            features['transaction_amount_zscore'] = 0
            features['is_new_payee'] = 0
            features['country_risk'] = 0
        return features
