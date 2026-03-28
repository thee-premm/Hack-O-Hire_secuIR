import numpy as np
from collections import deque, defaultdict

class RiskMemory:
    def __init__(self, decay_factor=0.95, window_size=10):
        self.user_risk = {}  # user_id -> current risk
        self.risk_window = defaultdict(lambda: deque(maxlen=window_size))  # last N risks
        self.decay = decay_factor
    
    def update(self, user_id, event_risk):
        current = self.user_risk.get(user_id, 0)
        current = current * self.decay + event_risk
        self.user_risk[user_id] = current
        self.risk_window[user_id].append(event_risk)
        return current
    
    def get_features(self, user_id):
        current = self.user_risk.get(user_id, 0)
        window = list(self.risk_window.get(user_id, []))
        last_window_avg = np.mean(window) if window else 0
        return {
            'cumulative_risk': current,
            'last_window_risk': last_window_avg
        }
