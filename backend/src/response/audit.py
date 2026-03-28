"""
Audit Logger
Writes structured JSON audit entries for every decision.
One JSONL file per day in logs/audit/.
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

_SENSITIVE_KEYS = {'password', 'token', 'secret', 'key', 'authorization'}


class AuditLogger:
    """Append-only JSON Lines audit trail."""

    def __init__(self, log_dir: str = None):
        if log_dir is None:
            # Default: <backend>/logs/audit
            _backend = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            log_dir = os.path.join(_backend, 'logs', 'audit')
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    # ------------------------------------------------------------------

    def log(
        self,
        incident: Dict,
        decision: Dict,
        final_actions: List,
        playbook: Dict,
        user_context: Dict,
    ) -> str:
        """
        Write one audit entry.  Returns the log file path.
        """
        entry = {
            'audit_timestamp': datetime.now().isoformat(),
            'incident_id': incident.get('incident_id'),
            'user_id': incident.get('user_id', incident.get('entity_id')),
            'user_tier': user_context.get('tier'),
            'risk_score': incident.get('final_risk'),
            'risk_band': incident.get('risk_band'),
            'incident_type': incident.get('incident_type'),
            'rule_triggered': decision.get('rule_name'),
            'rule_priority': decision.get('rule_priority'),
            'policies_applied': decision.get('applied_policies', []),
            'actions_executed': [
                (a.value if hasattr(a, 'value') else str(a))
                for a in final_actions
            ],
            'requires_approval': decision.get('requires_approval', False),
            'is_threat': decision.get('is_threat', False),
            'justification': decision.get('justification', ''),
            'playbook_id': playbook.get('playbook_id'),
            'incident_snapshot': self._sanitize(incident),
            'user_context': self._sanitize(user_context),
        }

        today = datetime.now().strftime('%Y%m%d')
        path = os.path.join(self.log_dir, f'audit_{today}.jsonl')
        try:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, default=str) + '\n')
        except Exception as exc:
            logger.error("Audit write failed: %s", exc)
        return path

    # ------------------------------------------------------------------

    @classmethod
    def _sanitize(cls, data: Dict) -> Dict:
        """Redact sensitive fields recursively."""
        out = {}
        for k, v in data.items():
            if any(s in k.lower() for s in _SENSITIVE_KEYS):
                out[k] = '[REDACTED]'
            elif isinstance(v, dict):
                out[k] = cls._sanitize(v)
            elif isinstance(v, (list, set)):
                out[k] = str(v)[:200]          # truncate long lists
            else:
                out[k] = v
        return out
