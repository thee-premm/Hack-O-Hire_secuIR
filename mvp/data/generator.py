import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import uuid

class SyntheticDataGenerator:
    def __init__(self):
        self.users = []
        self.events = []
    
    def create_users(self, num_customers=10, num_vip=2, num_employees=2):
        for i in range(num_customers):
            self.users.append({
                'user_id': f'cust_{i}',
                'user_type': 'customer',
                'account_tier': 'basic',
                'account_age_days': random.randint(30, 1000),
                'avg_transaction': random.uniform(100, 2000),
                'std_transaction': random.uniform(50, 500),
                'usual_login_hours': list(range(8, 22)),
                'usual_devices': [f'dev_{random.randint(1,3)}' for _ in range(1,3)],
                'usual_countries': ['US', 'GB', 'CA'],
                'usual_payees': [f'payee_{i}_{j}' for j in range(5)]
            })
        for i in range(num_vip):
            self.users.append({
                'user_id': f'vip_{i}',
                'user_type': 'customer',
                'account_tier': 'vip',
                'account_age_days': random.randint(500, 3000),
                'avg_transaction': random.uniform(1000, 10000),
                'std_transaction': random.uniform(500, 2000),
                'usual_login_hours': list(range(8, 22)),
                'usual_devices': [f'dev_{random.randint(1,3)}' for _ in range(1,3)],
                'usual_countries': ['US', 'GB', 'CA', 'FR', 'DE'],
                'usual_payees': [f'payee_{i}_{j}' for j in range(10)]
            })
        for i in range(num_employees):
            self.users.append({
                'user_id': f'emp_{i}',
                'user_type': 'employee',
                'account_tier': None,
                'account_age_days': random.randint(100, 2000),
                'avg_transaction': 0,
                'std_transaction': 0,
                'usual_login_hours': list(range(9, 18)),
                'usual_devices': [f'work_laptop_{i}', 'work_phone'],
                'usual_countries': ['US'],
                'usual_payees': []
            })
    
    def generate_normal_events(self, days=30):
        start_date = datetime(2026, 3, 1)
        for user in self.users:
            for day in range(days):
                sessions_per_day = random.randint(2, 5)
                for _ in range(sessions_per_day):
                    session_id = str(uuid.uuid4())
                    session_start = start_date + timedelta(days=day, hours=random.choice(user['usual_login_hours']), minutes=random.randint(0,59))
                    session_duration = random.randint(5, 30)
                    num_events = random.randint(5, 20)
                    for i in range(num_events):
                        event_time = session_start + timedelta(minutes=random.randint(0, session_duration))
                        event_type = random.choices(['login', 'api_call', 'transaction'], weights=[0.2, 0.5, 0.3])[0]
                        if event_type == 'login':
                            event = self._login_event(user, event_time, session_id, success=True)
                        elif event_type == 'api_call':
                            event = self._api_event(user, event_time, session_id, success=True)
                        else:
                            event = self._transaction_event(user, event_time, session_id, success=True)
                        self.events.append(event)
    
    def _login_event(self, user, timestamp, session_id, success=True):
        device = random.choice(user['usual_devices'])
        country = random.choice(user['usual_countries'])
        return {
            'timestamp': timestamp,
            'user_id': user['user_id'],
            'user_type': user['user_type'],
            'event_type': 'login',
            'success': success,
            'device_id': device,
            'ip_address': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'location_country': country,
            'location_city': 'SomeCity',
            'session_id': session_id,
            'user_agent': 'Mozilla/5.0',
            'failure_reason': None,
            'login_method': random.choice(['password','otp']),
            'mfa_success': True,
            'account_tier': user.get('account_tier'),
            'account_age_days': user['account_age_days']
        }
    
    def _api_event(self, user, timestamp, session_id, success=True):
        device = random.choice(user['usual_devices'])
        country = random.choice(user['usual_countries'])
        endpoints = ['/api/balance', '/api/transfer', '/api/statement', '/api/profile']
        endpoint = random.choice(endpoints)
        return {
            'timestamp': timestamp,
            'user_id': user['user_id'],
            'user_type': user['user_type'],
            'event_type': 'api_call',
            'success': success,
            'device_id': device,
            'ip_address': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'location_country': country,
            'location_city': 'SomeCity',
            'session_id': session_id,
            'endpoint': endpoint,
            'http_method': 'GET' if 'balance' in endpoint else 'POST',
            'response_status': 200 if success else random.choice([400,401,403,500]),
            'response_time_ms': random.randint(10, 500),
            'user_agent': 'Mozilla/5.0',
            'failure_reason': None if success else 'auth_error',
            'account_tier': user.get('account_tier'),
            'account_age_days': user['account_age_days']
        }
    
    def _transaction_event(self, user, timestamp, session_id, success=True):
        device = random.choice(user['usual_devices'])
        country = random.choice(user['usual_countries'])
        payee = random.choice(user['usual_payees'] + [f'new_payee_{random.randint(100,999)}'])
        is_new = payee not in user['usual_payees']
        amount = np.random.normal(user['avg_transaction'], user['std_transaction'])
        amount = max(10, min(amount, 100000))
        payee_country = random.choice(['US','GB','NG','RU'])
        return {
            'timestamp': timestamp,
            'user_id': user['user_id'],
            'user_type': user['user_type'],
            'event_type': 'transaction',
            'success': success,
            'device_id': device,
            'ip_address': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'location_country': country,
            'location_city': 'SomeCity',
            'session_id': session_id,
            'transaction_id': str(uuid.uuid4()),
            'amount': amount,
            'payee_id': payee,
            'payee_country': payee_country,
            'user_agent': 'Mozilla/5.0',
            'failure_reason': None,
            'transaction_type': random.choice(['transfer','withdrawal','payment']),
            'channel': random.choice(['web','mobile']),
            'is_new_payee': is_new,
            'country_risk': 0.8 if payee_country in ['NG','RU'] else 0.2,
            'payee_account_age': random.randint(1, 1000) if not is_new else 0,
            'account_tier': user.get('account_tier'),
            'account_age_days': user['account_age_days']
        }
    
    def generate_attacks(self, num_attack_events=200):
        for _ in range(num_attack_events):
            user = random.choice(self.users)
            attack_type = random.choice(['account_takeover', 'credential_stuffing', 'insider_threat'])
            if attack_type == 'account_takeover':
                # Unusual hour, new device, high amount
                event = self._transaction_event(user, datetime.now() + timedelta(hours=random.choice([0,1,2,3,4,23])), str(uuid.uuid4()), success=True)
                event['device_id'] = 'unknown_device'
                event['location_country'] = random.choice(['NG','RU','CN'])
                event['amount'] = random.uniform(10000, 50000)
                event['payee_id'] = f'unknown_payee_{random.randint(1,100)}'
                event['is_new_payee'] = True
                event['country_risk'] = 0.9
                self.events.append(event)
            elif attack_type == 'credential_stuffing':
                for i in range(random.randint(5,15)):
                    ev = self._login_event(user, datetime.now() + timedelta(seconds=i*10), str(uuid.uuid4()), success=False)
                    ev['failure_reason'] = 'wrong_password'
                    self.events.append(ev)
            elif attack_type == 'insider_threat' and user['user_type'] == 'employee':
                ev = self._api_event(user, datetime.now(), str(uuid.uuid4()), success=True)
                ev['endpoint'] = '/admin/customers'
                ev['response_status'] = 200
                ev['resource_count'] = random.randint(1000, 10000)
                self.events.append(ev)
    
    def to_dataframe(self):
        df = pd.DataFrame(self.events)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.sort_values('timestamp', inplace=True)
        return df

if __name__ == '__main__':
    gen = SyntheticDataGenerator()
    gen.create_users(num_customers=10, num_vip=2, num_employees=2)
    gen.generate_normal_events(days=7)
    gen.generate_attacks(num_attack_events=50)
    df = gen.to_dataframe()
    df.to_csv('synthetic_logs.csv', index=False)
    print(f"Generated {len(df)} events")
