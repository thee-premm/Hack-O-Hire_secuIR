from collections import deque, defaultdict

class ExtendedFeatureBuilder:
    def __init__(self, risk_memory):
        self.risk_memory = risk_memory
        self.user_risk_history = defaultdict(lambda: deque(maxlen=10))
    
    def build(self, user_id, event):
        # For now, we'll just add a simple trend feature
        risk_hist = self.user_risk_history[user_id]
        current_risk = self.risk_memory.user_risk.get(user_id, 0)
        risk_hist.append(current_risk)
        if len(risk_hist) >= 2:
            trend = risk_hist[-1] - risk_hist[-2]
        else:
            trend = 0
        # Could add more extended features, but for MVP we keep it simple
        extended = {
            'risk_trend': trend,
            # We can add more later
        }
        return extended
