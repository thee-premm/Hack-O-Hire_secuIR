import hashlib
import json
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Optional

class Deduplicator:
    """Remove duplicate and near-duplicate alerts"""
    
    def __init__(self, window_seconds: int = 60):
        self.seen_hashes = deque()
        self.hash_timestamps = deque()
        self.window_seconds = window_seconds
    
    def is_duplicate(self, event: Dict) -> bool:
        """Check if event is duplicate within time window"""
        event_hash = self._compute_event_hash(event)
        
        # Clean old entries
        self._clean_old_entries()
        
        if event_hash in self.seen_hashes:
            return True
        
        # Add to seen
        self.seen_hashes.append(event_hash)
        self.hash_timestamps.append(datetime.now())
        return False
    
    def _compute_event_hash(self, event: Dict) -> str:
        """Create hash from key fields (excluding timestamp)"""
        key_fields = {
            'user_id': event.get('user_id'),
            'event_type': event.get('event_type'),
            'session_id': event.get('session_id'),
            'device_id': event.get('device_id'),
            'ip_address': event.get('ip_address'),
            'amount': event.get('amount'),
            'payee_id': event.get('payee_id'),
            'endpoint': event.get('endpoint')
        }
        # Remove None values
        key_fields = {k: v for k, v in key_fields.items() if v is not None}
        content = json.dumps(key_fields, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _clean_old_entries(self):
        """Remove entries older than window"""
        now = datetime.now()
        while self.hash_timestamps and (now - self.hash_timestamps[0]) > timedelta(seconds=self.window_seconds):
            self.hash_timestamps.popleft()
            self.seen_hashes.popleft()
