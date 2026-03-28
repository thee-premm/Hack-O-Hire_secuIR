import heapq
from datetime import datetime, timedelta
from typing import List, Dict, Optional

class TimestampReorderer:
    """Buffer and reorder events by timestamp"""
    
    def __init__(self, buffer_seconds: int = 5):
        self.buffer = []  # heap of (timestamp, event)
        self.buffer_seconds = buffer_seconds
        self.processed_count = 0
    
    def add_event(self, event: Dict):
        """Add event to buffer"""
        ts = event.get('timestamp')
        if isinstance(ts, str):
            from datetime import datetime
            ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        # Ensure timezone-naive for consistent comparison
        if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        heapq.heappush(self.buffer, (ts, self.processed_count, event))
        self.processed_count += 1
    
    def get_ordered_events(self) -> List[Dict]:
        """Get events that are ready to process"""
        if not self.buffer:
            return []
        
        now = datetime.now()
        ready = []
        
        while self.buffer:
            ts, _, event = self.buffer[0]
            # Check if event is old enough (buffer window passed)
            if (now - ts).total_seconds() > self.buffer_seconds:
                heapq.heappop(self.buffer)
                ready.append(event)
            else:
                break
        
        return ready
    
    def flush(self) -> List[Dict]:
        """Force flush all remaining events"""
        ready = []
        while self.buffer:
            _, _, event = heapq.heappop(self.buffer)
            ready.append(event)
        return ready
