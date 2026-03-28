"""
Redis Baseline Manager
Hierarchical baseline storage for user behavior patterns.

Hierarchy:
    1. User Baseline  (if user has history in Redis/memory)
    2. Global Baseline (aggregate of all users)
    3. Default Values  (safe fallback)

Supports both Redis and in-memory backends transparently.
"""

import json
import numpy as np
import os
import sys
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict
import logging

# Add src/ to path for sibling imports
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from config.redis_config import redis_config

logger = logging.getLogger(__name__)


class RedisBaselineManager:
    """
    Hierarchical baseline management with Redis + in-memory fallback.

    Redis Key Structure (when Redis is available):
        secuir:user:{user_id}:login_hours     -> Sorted set [hour: count]
        secuir:user:{user_id}:devices         -> Set of device/proc IDs
        secuir:user:{user_id}:locations       -> Set of geo/country values
        secuir:user:{user_id}:sources         -> Set of log sources
        secuir:user:{user_id}:events          -> Sorted set [event_type: count]
        secuir:user:{user_id}:stats           -> Hash (event_count, first_seen, etc.)
        secuir:global:login_hours             -> Sorted set
        secuir:global:stats                   -> Hash
    """

    def __init__(self):
        self.redis = redis_config.client
        # In-memory stores (always populated; primary if Redis unavailable)
        self._user_baselines = defaultdict(lambda: {
            'login_hours': [],
            'devices': set(),
            'locations': set(),
            'sources': set(),
            'events': defaultdict(int),
            'ips': set(),
            'severities': [],
            'event_count': 0,
            'first_seen': None,
            'last_seen': None,
        })
        self._global_stats = {
            'total_events': 0,
            'login_hours': defaultdict(int),
            'severity_counts': defaultdict(int),
            'source_counts': defaultdict(int),
            'event_counts': defaultdict(int),
            'unique_users': set(),
        }
        self._global_cache = None

    # =============================================================
    # USER BASELINE UPDATE
    # =============================================================

    def update_user_baseline(self, user_id: str, event: Dict) -> None:
        """Update user baseline with a new event (both Redis and in-memory)."""
        if not user_id:
            return

        # --- Parse timestamp hour ---
        hour = self._extract_hour(event)

        # --- In-memory update (always) ---
        ub = self._user_baselines[user_id]
        ub['login_hours'].append(hour)
        if len(ub['login_hours']) > 200:
            ub['login_hours'] = ub['login_hours'][-200:]
        ub['event_count'] += 1
        now = datetime.now()
        if ub['first_seen'] is None:
            ub['first_seen'] = now
        ub['last_seen'] = now

        # Device / proc
        device = event.get('device_id') or event.get('proc') or event.get('host')
        if device:
            ub['devices'].add(str(device))

        # Location / geo
        loc = event.get('location_country') or event.get('geo')
        if loc and str(loc) != 'nan':
            ub['locations'].add(str(loc))

        # Source
        source = event.get('source')
        if source:
            ub['sources'].add(str(source))

        # Event type
        ev_type = event.get('event_type') or event.get('event')
        if ev_type:
            ub['events'][str(ev_type)] += 1

        # IP
        ip = event.get('ip_address') or event.get('ip')
        if ip and str(ip) != 'nan':
            ub['ips'].add(str(ip))

        # Severity
        sev = event.get('severity')
        if sev:
            ub['severities'].append(str(sev))
            if len(ub['severities']) > 200:
                ub['severities'] = ub['severities'][-200:]

        # --- Redis update (if available) ---
        if self.redis:
            try:
                pfx = redis_config.get_key('user', user_id)
                self.redis.zincrby(f'{pfx}:login_hours', 1, hour)
                if device:
                    self.redis.sadd(f'{pfx}:devices', str(device))
                if loc and str(loc) != 'nan':
                    self.redis.sadd(f'{pfx}:locations', str(loc))
                if source:
                    self.redis.sadd(f'{pfx}:sources', str(source))
                if ev_type:
                    self.redis.zincrby(f'{pfx}:events', 1, str(ev_type))
                self.redis.hincrby(f'{pfx}:stats', 'event_count', 1)
                self.redis.hset(f'{pfx}:stats', 'last_seen', now.isoformat())
                # Set TTL
                for suffix in ['login_hours', 'devices', 'locations', 'sources', 'events', 'stats']:
                    self.redis.expire(f'{pfx}:{suffix}', redis_config.user_ttl)
            except Exception as e:
                logger.debug(f"Redis write error for {user_id}: {e}")

        # --- Update global stats ---
        self._update_global(event, hour, user_id)
        self._global_cache = None  # invalidate

    # =============================================================
    # USER BASELINE GETTER
    # =============================================================

    def get_user_baseline(self, user_id: str) -> Dict:
        """Get user-specific baseline. Returns empty dict if user unknown."""
        # Check in-memory first (faster, always populated)
        if user_id in self._user_baselines:
            return self._build_user_baseline_from_memory(user_id)

        # Check Redis
        if self.redis:
            try:
                stats_key = redis_config.get_key('user', user_id, 'stats')
                if self.redis.exists(stats_key):
                    return self._build_user_baseline_from_redis(user_id)
            except Exception:
                pass

        return {}

    def _build_user_baseline_from_memory(self, user_id: str) -> Dict:
        ub = self._user_baselines[user_id]
        if ub['event_count'] == 0:
            return {}

        hours = ub['login_hours']
        if hours:
            avg_hour = float(np.mean(hours))
            std_hour = float(np.std(hours)) if len(hours) > 1 else 4.0
        else:
            avg_hour, std_hour = 12.0, 4.0

        # Severity risk score
        sev_map = {'LOW': 0.1, 'MEDIUM': 0.4, 'HIGH': 0.7, 'CRITICAL': 1.0, 'UNKNOWN': 0.3}
        sev_scores = [sev_map.get(s, 0.3) for s in ub['severities']]
        avg_severity = float(np.mean(sev_scores)) if sev_scores else 0.2

        return {
            'exists': True,
            'type': 'user',
            'user_id': user_id,
            'login_hours': hours[-50:],
            'avg_login_hour': avg_hour,
            'std_login_hour': std_hour,
            'devices': list(ub['devices']),
            'locations': list(ub['locations']),
            'sources': list(ub['sources']),
            'ips': list(ub['ips'])[:20],
            'event_count': ub['event_count'],
            'unique_events': len(ub['events']),
            'top_events': dict(sorted(ub['events'].items(), key=lambda x: -x[1])[:5]),
            'avg_severity_score': avg_severity,
            'first_seen': ub['first_seen'].isoformat() if ub['first_seen'] else None,
            'last_seen': ub['last_seen'].isoformat() if ub['last_seen'] else None,
        }

    def _build_user_baseline_from_redis(self, user_id: str) -> Dict:
        pfx = redis_config.get_key('user', user_id)
        hours_raw = self.redis.zrange(f'{pfx}:login_hours', 0, -1, withscores=True)
        login_hours = [int(h) for h, _ in hours_raw]
        hour_weights = [int(w) for _, w in hours_raw]

        if login_hours:
            total = sum(hour_weights)
            avg_hour = sum(h * w for h, w in zip(login_hours, hour_weights)) / total
            variance = sum(w * (h - avg_hour) ** 2 for h, w in zip(login_hours, hour_weights)) / total
            std_hour = float(np.sqrt(variance)) if variance > 0 else 4.0
        else:
            avg_hour, std_hour = 12.0, 4.0

        devices = list(self.redis.smembers(f'{pfx}:devices') or [])
        locations = list(self.redis.smembers(f'{pfx}:locations') or [])
        sources = list(self.redis.smembers(f'{pfx}:sources') or [])
        event_count = int(self.redis.hget(f'{pfx}:stats', 'event_count') or 0)
        last_seen = self.redis.hget(f'{pfx}:stats', 'last_seen')

        return {
            'exists': True,
            'type': 'user',
            'user_id': user_id,
            'login_hours': login_hours,
            'avg_login_hour': avg_hour,
            'std_login_hour': std_hour,
            'devices': devices,
            'locations': locations,
            'sources': sources,
            'event_count': event_count,
            'last_seen': last_seen,
        }

    # =============================================================
    # GLOBAL BASELINE
    # =============================================================

    def _update_global(self, event: Dict, hour: int, user_id: str) -> None:
        gs = self._global_stats
        gs['total_events'] += 1
        gs['login_hours'][hour] += 1
        gs['unique_users'].add(user_id)
        sev = event.get('severity')
        if sev:
            gs['severity_counts'][str(sev)] += 1
        src = event.get('source')
        if src:
            gs['source_counts'][str(src)] += 1
        ev = event.get('event_type') or event.get('event')
        if ev:
            gs['event_counts'][str(ev)] += 1

        # Also push to Redis
        if self.redis:
            try:
                self.redis.zincrby(redis_config.get_key('global', 'login_hours'), 1, hour)
                self.redis.hincrby(redis_config.get_key('global', 'stats'), 'total_events', 1)
            except Exception:
                pass

    def get_global_baseline(self) -> Dict:
        """Global baseline aggregated across all known users."""
        if self._global_cache:
            return self._global_cache

        gs = self._global_stats
        hours_dict = gs['login_hours']
        if hours_dict:
            total = sum(hours_dict.values())
            avg_hour = sum(h * c for h, c in hours_dict.items()) / total
            variance = sum(c * (h - avg_hour) ** 2 for h, c in hours_dict.items()) / total
            std_hour = float(np.sqrt(variance)) if variance > 0 else 4.0
        else:
            avg_hour, std_hour = 12.0, 4.0

        self._global_cache = {
            'exists': True,
            'type': 'global',
            'avg_login_hour': avg_hour,
            'std_login_hour': std_hour,
            'total_events': gs['total_events'],
            'unique_users': len(gs['unique_users']),
            'severity_distribution': dict(gs['severity_counts']),
            'source_distribution': dict(gs['source_counts']),
            'top_events': dict(sorted(gs['event_counts'].items(), key=lambda x: -x[1])[:10]),
        }
        return self._global_cache

    # =============================================================
    # HIERARCHICAL GETTER (Main API)
    # =============================================================

    def get_baseline(self, user_id: str) -> Dict:
        """
        Main API. Returns baseline with hierarchical fallback:
          1. User baseline (if user exists)
          2. Global baseline (if user is new)
          3. Default values
        """
        user_bl = self.get_user_baseline(user_id)
        if user_bl:
            return user_bl

        global_bl = self.get_global_baseline()
        if global_bl.get('exists'):
            result = dict(global_bl)
            result['is_new_user'] = True
            result['devices'] = []
            result['locations'] = []
            return result

        return self._get_default()

    def get_baseline_features(self, user_id: str, event: Dict) -> Dict:
        """
        Compute baseline deviation features for a single event.
        Compatible with existing CoreFeatureBuilder interface.
        """
        baseline = self.get_baseline(user_id)
        hour = self._extract_hour(event)

        # Login hour deviation (z-score)
        avg_h = baseline.get('avg_login_hour', 12.0)
        std_h = baseline.get('std_login_hour', 4.0)
        login_hour_dev = abs(hour - avg_h) / max(std_h, 1.0)

        # Device match
        device = event.get('device_id') or event.get('proc') or event.get('host')
        known_devices = baseline.get('devices', [])
        device_match = 1.0 if (device and str(device) in known_devices) else 0.0

        # Location match
        loc = event.get('location_country') or event.get('geo')
        known_locs = baseline.get('locations', [])
        loc_match = 1.0 if (loc and str(loc) in known_locs) else 0.0

        return {
            'login_hour_deviation': float(login_hour_dev),
            'device_match': float(device_match),
            'location_match': float(loc_match),
            'is_new_user': 1.0 if baseline.get('is_new_user') or baseline.get('type') != 'user' else 0.0,
            'baseline_type': baseline.get('type', 'default'),
            'avg_transaction_amount': baseline.get('avg_transaction_amount', 0),
            'avg_login_hour': avg_h,
            'std_login_hour': std_h,
        }

    def _get_default(self) -> Dict:
        return {
            'exists': False,
            'type': 'default',
            'is_new_user': True,
            'avg_login_hour': 14.0,
            'std_login_hour': 4.0,
            'devices': [],
            'locations': [],
            'avg_transaction_amount': 0,
            'std_transaction_amount': 1,
        }

    # =============================================================
    # BULK POPULATION (from training data)
    # =============================================================

    def populate_from_dataframe(self, df, user_col='user', batch_log_every=5000) -> dict:
        """
        Populate baselines from a training DataFrame.

        The dataset uses columns: ts, host, user, event, severity, ip, message, source, ...
        We map these to the internal event schema.

        Returns summary dict.
        """
        logger.info(f"Populating baselines from {len(df)} rows, {df[user_col].nunique()} unique users...")

        count = 0
        for _, row in df.iterrows():
            raw = row.to_dict()

            # Map dataset columns -> internal event dict
            user_id = str(raw.get(user_col, 'unknown'))
            if user_id == 'nan' or not user_id:
                continue

            event = {
                'user_id': user_id,
                'event_type': raw.get('event'),
                'severity': raw.get('severity'),
                'ip': raw.get('ip'),
                'host': raw.get('host'),
                'proc': raw.get('proc'),
                'geo': raw.get('geo'),
                'source': raw.get('source'),
                'message': raw.get('message'),
            }

            # Parse timestamp
            ts = raw.get('ts')
            if isinstance(ts, str):
                try:
                    event['timestamp'] = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except Exception:
                    # Use hour column if available
                    event['timestamp'] = None
            else:
                event['timestamp'] = None

            # Use pre-computed hour if timestamp unavailable
            if event['timestamp'] is None and 'hour' in raw:
                h = raw['hour']
                if not (isinstance(h, float) and np.isnan(h)):
                    event['_hour_override'] = int(h)

            self.update_user_baseline(user_id, event)
            count += 1

            if count % batch_log_every == 0:
                logger.info(f"  Processed {count} events ({len(self._user_baselines)} users)...")

        summary = {
            'events_processed': count,
            'users_populated': len(self._user_baselines),
            'global_events': self._global_stats['total_events'],
            'redis_mode': redis_config.is_available(),
        }
        logger.info(f"Baseline population complete: {summary}")
        return summary

    # =============================================================
    # HELPERS
    # =============================================================

    def _extract_hour(self, event: Dict) -> int:
        """Extract hour from event (with multiple fallbacks)."""
        # Direct override (used during bulk population)
        if '_hour_override' in event:
            return int(event['_hour_override'])

        ts = event.get('timestamp')
        if ts is not None:
            if hasattr(ts, 'hour'):
                return ts.hour
            if isinstance(ts, str):
                try:
                    return datetime.fromisoformat(ts.replace('Z', '+00:00')).hour
                except Exception:
                    pass

        # Pre-computed hour column
        h = event.get('hour')
        if h is not None and not (isinstance(h, float) and np.isnan(h)):
            return int(h)

        return 12  # default noon

    def stats(self) -> Dict:
        """Get baseline system stats."""
        return {
            'users_in_memory': len(self._user_baselines),
            'global_events': self._global_stats['total_events'],
            'global_unique_users': len(self._global_stats['unique_users']),
            'redis_available': redis_config.is_available(),
            'redis_health': redis_config.health(),
        }

    def clear(self) -> None:
        """Clear all baselines (for testing)."""
        self._user_baselines.clear()
        self._global_stats = {
            'total_events': 0,
            'login_hours': defaultdict(int),
            'severity_counts': defaultdict(int),
            'source_counts': defaultdict(int),
            'event_counts': defaultdict(int),
            'unique_users': set(),
        }
        self._global_cache = None
        if self.redis:
            try:
                keys = self.redis.keys('secuir:*')
                if keys:
                    self.redis.delete(*keys)
            except Exception:
                pass


# Singleton
baseline_manager = RedisBaselineManager()
