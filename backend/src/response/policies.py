"""
Policy Override Engine
Applies business policies that can modify, add, or replace
actions decided by the rule engine.

In production these would be loaded from PostgreSQL;
here they are defined in code for portability.
"""

from typing import Dict, List, Any
from .engine import Action


class PolicyOverride:
    """Single policy definition."""

    def __init__(self, name: str, description: str, condition, modifications: Dict[str, Any]):
        self.name = name
        self.description = description
        self.condition = condition          # (incident, user_context, current_actions) -> bool
        self.modifications = modifications  # dict of changes to apply


class PolicyEngine:
    """
    Evaluates all policies in order and applies modifications
    to the action list produced by the rule engine.
    """

    def __init__(self):
        self.policies = self._load_policies()

    # ------------------------------------------------------------------
    # POLICY DEFINITIONS
    # ------------------------------------------------------------------

    def _load_policies(self) -> List[PolicyOverride]:
        return [
            # P1: VIP users are never auto-blocked
            PolicyOverride(
                name='vip_no_auto_block',
                description='VIP users cannot be auto-blocked; route to manual review',
                condition=lambda i, u, a: (
                    u.get('tier') == 'vip' and
                    Action.BLOCK_TRANSACTION in a
                ),
                modifications={
                    'replace_actions': [Action.DELAY_TRANSACTION, Action.NOTIFY_MANAGER],
                    'add_notify': ['security_manager'],
                },
            ),

            # P2: High-risk countries require compliance report
            PolicyOverride(
                name='high_risk_country_compliance',
                description='Transactions involving high-risk countries trigger compliance',
                condition=lambda i, u, a: (
                    i.get('country_risk_band') in ('HIGH', 'CRITICAL')
                ),
                modifications={
                    'add_actions': [Action.REPORT_TO_COMPLIANCE],
                    'add_notify': ['compliance_department'],
                },
            ),

            # P3: Large transactions require manager approval
            PolicyOverride(
                name='large_transaction_approval',
                description='Transactions >100K require manager sign-off',
                condition=lambda i, u, a: i.get('amount', 0) > 100_000,
                modifications={
                    'add_actions': [Action.MANUAL_REVIEW],
                    'requires_approval': True,
                },
            ),

            # P4: Insider threats always involve HR
            PolicyOverride(
                name='insider_threat_hr',
                description='Insider threat incidents are forwarded to HR',
                condition=lambda i, u, a: (
                    i.get('incident_type') == 'insider_threat' and
                    u.get('user_type') == 'employee'
                ),
                modifications={
                    'add_notify': ['hr_department'],
                    'requires_approval': True,
                },
            ),

            # P5: System/service accounts are log-only
            PolicyOverride(
                name='system_account_readonly',
                description='System accounts never get blocking actions',
                condition=lambda i, u, a: u.get('user_type') == 'system',
                modifications={
                    'replace_actions': [Action.LOG_ONLY],
                    'requires_approval': False,
                },
            ),
        ]

    # ------------------------------------------------------------------
    # EVALUATION
    # ------------------------------------------------------------------

    def apply(
        self,
        incident: Dict,
        user_context: Dict,
        primary_actions: List[Action],
        requires_approval: bool,
    ) -> Dict:
        """
        Evaluate all matching policies and return modified decision.

        Returns dict with:
            actions, requires_approval, additional_notify, applied_policies
        """
        actions = list(primary_actions)
        approval = requires_approval
        notify: List[str] = []
        applied: List[str] = []

        for pol in self.policies:
            try:
                if pol.condition(incident, user_context, actions):
                    applied.append(pol.name)
                    m = pol.modifications

                    if 'replace_actions' in m:
                        actions = list(m['replace_actions'])
                    if 'add_actions' in m:
                        for a in m['add_actions']:
                            if a not in actions:
                                actions.append(a)
                    if 'remove_actions' in m:
                        actions = [a for a in actions if a not in m['remove_actions']]
                    if 'requires_approval' in m:
                        approval = m['requires_approval']
                    if 'add_notify' in m:
                        notify.extend(m['add_notify'])
            except Exception:
                continue

        return {
            'actions': actions,
            'requires_approval': approval,
            'additional_notify': list(set(notify)),
            'applied_policies': applied,
        }
