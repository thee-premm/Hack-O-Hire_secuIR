from collections import defaultdict, deque
import numpy as np

class SessionManager:
    def __init__(self, session_timeout_minutes=30):
        self.sessions = {}  # session_id -> dict
        self.user_sessions = defaultdict(list)  # user_id -> list of session_ids
        self.session_timeout = session_timeout_minutes * 60  # seconds
    
    def get_or_create_session(self, user_id, session_id, timestamp):
        if session_id in self.sessions:
            session = self.sessions[session_id]
            # Check if session expired
            if (timestamp - session['last_event']).total_seconds() > self.session_timeout:
                # Start new session with same id? Better create new
                session = self._new_session(user_id, session_id, timestamp)
        else:
            session = self._new_session(user_id, session_id, timestamp)
        self.sessions[session_id] = session
        return session
    
    def _new_session(self, user_id, session_id, timestamp):
        return {
            'session_id': session_id,
            'user_id': user_id,
            'start_time': timestamp,
            'last_event': timestamp,
            'event_count': 0,
            'endpoints': [],   # list of endpoint names
            'request_times': [],  # list of timestamps
            'transactions': []    # list of transaction amounts
        }
    
    def update_session(self, session_id, event):
        session = self.sessions[session_id]
        session['last_event'] = event['timestamp']
        session['event_count'] += 1
        if event['event_type'] == 'api_call':
            session['endpoints'].append(event.get('endpoint', 'unknown'))
        if event['event_type'] == 'transaction':
            session['transactions'].append(event.get('amount', 0))
        session['request_times'].append(event['timestamp'])
        return session
    
    def get_session_features(self, session_id):
        session = self.sessions.get(session_id)
        if not session:
            return None
        # Compute entropy of endpoints
        if session['endpoints']:
            counts = defaultdict(int)
            for ep in session['endpoints']:
                counts[ep] += 1
            total = len(session['endpoints'])
            entropy = -sum((c/total) * np.log2(c/total) for c in counts.values())
        else:
            entropy = 0
        # Average request rate (events per minute)
        if len(session['request_times']) > 1:
            duration = (session['last_event'] - session['start_time']).total_seconds() / 60
            rate = len(session['request_times']) / max(duration, 0.1)
        else:
            rate = 0
        return {
            'event_count': session['event_count'],
            'entropy': entropy,
            'avg_rate': rate
        }
