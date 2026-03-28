from collections import defaultdict, Counter
import numpy as np

class BaselineManager:
    def __init__(self):
        self.user_baseline = {}  # user_id -> baseline dict
    
    def update(self, user_id, event):
        if user_id not in self.user_baseline:
            self.user_baseline[user_id] = {
                'login_hours': [],
                'devices': set(),
                'locations': set(),
                'payees': set(),
                'transaction_amounts': [],
                'session_durations': []
            }
        bl = self.user_baseline[user_id]
        if event['event_type'] == 'login':
            bl['login_hours'].append(event['timestamp'].hour)
            bl['devices'].add(event['device_id'])
            bl['locations'].add(event['location_country'])
        elif event['event_type'] == 'transaction':
            bl['payees'].add(event.get('payee_id'))
            if event.get('amount'):
                bl['transaction_amounts'].append(event['amount'])
    
    def get_baseline_features(self, user_id, event):
        bl = self.user_baseline.get(user_id)
        if not bl:
            return {'login_hour_deviation': 0, 'device_match': 1, 'location_match': 1}
        # Login hour deviation (z-score)
        if bl['login_hours']:
            mean_hour = np.mean(bl['login_hours'])
            std_hour = np.std(bl['login_hours']) or 1
            hour = event['timestamp'].hour
            hour_dev = abs(hour - mean_hour) / std_hour
        else:
            hour_dev = 0
        # Device match
        device_match = 1 if event['device_id'] in bl['devices'] else 0
        # Location match
        location_match = 1 if event['location_country'] in bl['locations'] else 0
        # Avg transaction amount (for transaction events)
        avg_amount = np.mean(bl['transaction_amounts']) if bl['transaction_amounts'] else 0
        return {
            'login_hour_deviation': hour_dev,
            'device_match': device_match,
            'location_match': location_match,
            'avg_transaction_amount': avg_amount
        }
