import hashlib
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional

class LogNormalizer:
    """Handles heterogeneous log formats and field name variations"""
    
    # Field name aliases mapping
    FIELD_ALIASES = {
        'user_id': ['userId', 'username', 'user', 'uid', 'account_id', 'accountId'],
        'event_type': ['eventType', 'event', 'type', 'action', 'event_name'],
        'timestamp': ['time', '@timestamp', 'date', 'datetime', 'event_time', 'created_at'],
        'device_id': ['deviceId', 'device', 'user_agent_hash', 'fingerprint', 'device_fingerprint'],
        'ip_address': ['ip', 'source_ip', 'src_ip', 'client_ip', 'ipAddress'],
        'location_country': ['country', 'countryCode', 'country_code', 'location', 'country_name'],
        'session_id': ['sessionId', 'session', 'sid', 'session_token'],
        'amount': ['amt', 'transaction_amount', 'value', 'amount_usd', 'transactionValue'],
        'payee_id': ['payeeId', 'beneficiary', 'recipient', 'to_account'],
        'payee_country': ['payeeCountry', 'beneficiaryCountry', 'recipientCountry'],
        'success': ['status', 'result', 'outcome', 'is_success', 'succeeded'],
        'endpoint': ['api_endpoint', 'path', 'route', 'url'],
        'http_method': ['method', 'httpMethod', 'request_method'],
        'response_status': ['status_code', 'http_status', 'responseCode']
    }
    
    # Default values for missing fields
    DEFAULTS = {
        'success': True,
        'device_id': 'unknown_device',
        'location_country': 'unknown',
        'session_id': 'unknown_session',
        'user_type': 'customer',
        'event_type': 'unknown',
        'user_id': 'unknown_user'
    }
    
    def __init__(self):
        self.reverse_mapping = self._build_reverse_mapping()
    
    def _build_reverse_mapping(self):
        """Build reverse mapping from alias to canonical field"""
        mapping = {}
        for canonical, aliases in self.FIELD_ALIASES.items():
            for alias in aliases:
                mapping[alias.lower()] = canonical
            mapping[canonical] = canonical
        return mapping
    
    def normalize(self, raw_log: Dict[str, Any], format_type: str = 'json') -> Dict[str, Any]:
        """Convert any log format to canonical schema"""
        normalized = {}
        
        # Map fields using aliases; preserve unmapped fields as-is
        for raw_key, value in raw_log.items():
            key_lower = str(raw_key).lower()
            if key_lower in self.reverse_mapping:
                canonical_key = self.reverse_mapping[key_lower]
                normalized[canonical_key] = self._clean_value(value)
            else:
                # Preserve unmapped fields (e.g. account_tier, admin_action,
                # is_new_payee, failed_attempts_last_minute, payee_country)
                normalized[raw_key] = value
        
        # Apply defaults for missing required fields
        for field, default in self.DEFAULTS.items():
            if field not in normalized or normalized[field] is None:
                normalized[field] = default
        
        # Normalize timestamp
        normalized['timestamp'] = self._normalize_timestamp(
            normalized.get('timestamp', datetime.now().isoformat())
        )
        
        # Infer event_type if still missing or unknown
        if normalized['event_type'] == 'unknown':
            normalized['event_type'] = self._infer_event_type(raw_log)
        
        # Ensure all canonical fields exist
        return self._ensure_all_fields(normalized)
    
    def _clean_value(self, value):
        """Clean and type-convert values"""
        if isinstance(value, str):
            value = value.strip()
            if value.lower() in ['true', 'false', 'yes', 'no']:
                return value.lower() in ['true', 'yes']
            if value.isdigit():
                return int(value)
        return value
    
    def _normalize_timestamp(self, ts) -> datetime:
        """Parse various timestamp formats. Always returns timezone-naive datetime
        for consistency with the rest of the pipeline."""
        if isinstance(ts, datetime):
            # Strip timezone info if present
            return ts.replace(tzinfo=None)
        if isinstance(ts, (int, float)):
            # Unix timestamp
            if ts > 1e12:
                ts = ts / 1000  # milliseconds to seconds
            return datetime.fromtimestamp(ts)
        try:
            # Try ISO format
            dt = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
            return dt.replace(tzinfo=None)  # strip tz for consistency
        except:
            try:
                # Try common syslog format: "Mar 28 14:23:17"
                return datetime.strptime(str(ts), '%b %d %H:%M:%S')
            except:
                # Return current time as fallback
                return datetime.now()
    
    def _infer_event_type(self, raw_log):
        """Infer event type from log content"""
        log_str = json.dumps(raw_log).lower()
        if 'amount' in log_str or 'transaction' in log_str:
            return 'transaction'
        if 'login' in log_str or 'auth' in log_str or 'mfa' in log_str:
            return 'login'
        if 'api' in log_str or 'endpoint' in log_str or 'request' in log_str:
            return 'api_call'
        if 'admin' in log_str or 'employee' in log_str:
            return 'admin_action'
        return 'unknown'
    
    def _ensure_all_fields(self, normalized):
        """Ensure all canonical fields exist with proper defaults"""
        all_fields = ['timestamp', 'user_id', 'user_type', 'event_type', 'success',
                     'device_id', 'ip_address', 'location_country', 'session_id',
                     'amount', 'payee_id', 'payee_country', 'endpoint', 'http_method',
                     'response_status', 'failure_reason', 'account_tier', 'account_age_days']
        for field in all_fields:
            if field not in normalized:
                normalized[field] = None
        return normalized
