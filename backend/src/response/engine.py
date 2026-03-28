"""
Response Engine - Main Orchestrator
====================================
Integrates:
  1. BandEnricher   - personalized categorical bands
  2. Rule Engine    - priority-based rule evaluation (built-in)
  3. PolicyEngine   - business policy overrides
  4. PlaybookGen    - structured playbook (template / Ollama)
  5. AuditLogger    - JSONL audit trail

Backward-compatible: the existing ``decide()`` method keeps working
for the current pipeline.  The new ``process()`` method runs the full
enrichment -> rules -> policies -> playbook -> audit pipeline.
"""

from enum import Enum
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)


# =====================================================================
#  Action enum  (used everywhere)
# =====================================================================

class Action(Enum):
    """Available response actions"""
    LOG_ONLY = "LOG_ONLY"
    MFA_CHALLENGE = "MFA_CHALLENGE"
    DELAY_TRANSACTION = "DELAY_TRANSACTION"
    RESTRICT_SESSION = "RESTRICT_SESSION"
    BLOCK_TRANSACTION = "BLOCK_TRANSACTION"
    FREEZE_ACCOUNT = "FREEZE_ACCOUNT"
    TERMINATE_SESSION = "TERMINATE_SESSION"
    NOTIFY_SOC = "NOTIFY_SOC"
    NOTIFY_MANAGER = "NOTIFY_MANAGER"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    REPORT_TO_COMPLIANCE = "REPORT_TO_COMPLIANCE"


# =====================================================================
#  Rule dataclass
# =====================================================================

@dataclass
class Rule:
    """Rule definition for response engine"""
    priority: int                    # Lower number = higher priority
    name: str                        # Unique rule identifier
    description: str                 # Human-readable description
    condition: Callable              # Function that returns boolean
    action: Action                   # Primary action to take
    requires_approval: bool          # Whether human approval needed
    justification: str               # Why this rule was triggered
    user_tier_override: Optional[Dict[str, Action]] = None  # Tier-specific overrides
    additional_actions: Optional[List[Action]] = None        # Extra actions (new)


# =====================================================================
#  ResponseEngine
# =====================================================================

class ResponseEngine:
    """
    Deterministic rule-based response engine.

    Features
    --------
    - Priority-based rule evaluation
    - VIP user protection (never auto-block)
    - Regulatory compliance flags
    - Approval workflow integration
    - Complete audit trail
    - NEW: ``process()`` method orchestrates enrichment + policies + playbook + audit
    """

    def __init__(self, baseline_manager=None):
        self.rules = self._load_rules()
        self.decision_history: list = []
        self._validate_rules()

        # --- New subsystems (lazy-loaded to avoid circular imports) ---
        self._baseline_manager = baseline_manager
        self._band_enricher = None
        self._policy_engine = None
        self._audit_logger = None

    # ------------------------------------------------------------------
    #  Lazy loaders for new subsystems
    # ------------------------------------------------------------------

    @property
    def band_enricher(self):
        if self._band_enricher is None:
            from .bands import BandEnricher
            self._band_enricher = BandEnricher(self._baseline_manager)
        return self._band_enricher

    @property
    def policy_engine(self):
        if self._policy_engine is None:
            from .policies import PolicyEngine
            self._policy_engine = PolicyEngine()
        return self._policy_engine

    @property
    def audit_logger(self):
        if self._audit_logger is None:
            from .audit import AuditLogger
            self._audit_logger = AuditLogger()
        return self._audit_logger

    # ==================================================================
    #  RULES
    # ==================================================================

    def _validate_rules(self):
        priorities = [r.priority for r in self.rules]
        if len(priorities) != len(set(priorities)):
            raise ValueError("Duplicate rule priorities detected")

    def _load_rules(self) -> List[Rule]:
        """Load all response rules with priorities"""
        return [
            # Priority 100: Critical threats (highest priority)
            Rule(
                priority=100,
                name="critical_risk_block",
                description="Block any transaction with critical risk score",
                condition=lambda i, u: i.get('final_risk', 0) > 0.9,
                action=Action.BLOCK_TRANSACTION,
                requires_approval=False,
                justification="Critical risk score (>0.9) detected. Auto-blocking transaction.",
                user_tier_override={
                    'vip': Action.MANUAL_REVIEW,
                    'employee': Action.NOTIFY_MANAGER
                }
            ),

            # Priority 200: Account takeover detection
            Rule(
                priority=200,
                name="account_takeover_detected",
                description="Account takeover pattern detected",
                condition=lambda i, u: (
                    i.get('incident_type') == 'account_takeover' and
                    i.get('final_risk', 0) > 0.7
                ),
                action=Action.TERMINATE_SESSION,
                requires_approval=False,
                justification="Account takeover pattern detected. Terminating all active sessions.",
                user_tier_override={'vip': Action.MANUAL_REVIEW},
                additional_actions=[Action.NOTIFY_SOC],
            ),

            # Priority 300: High risk VIP handling
            Rule(
                priority=300,
                name="vip_high_risk_review",
                description="High risk VIP requires manual review",
                condition=lambda i, u: (
                    u.get('tier') == 'vip' and
                    i.get('final_risk', 0) > 0.8
                ),
                action=Action.MANUAL_REVIEW,
                requires_approval=True,
                justification="VIP user with high risk activity requires security manager review."
            ),

            # Priority 400: Insider threat detection
            Rule(
                priority=400,
                name="insider_threat_detected",
                description="Potential insider threat detected",
                condition=lambda i, u: (
                    u.get('user_type') == 'employee' and
                    i.get('incident_type') == 'insider_threat'
                ),
                action=Action.FREEZE_ACCOUNT,
                requires_approval=True,
                justification="Potential insider threat detected. Freezing account pending HR review.",
                user_tier_override={'admin': Action.NOTIFY_SOC},
                additional_actions=[Action.NOTIFY_SOC],
            ),

            # Priority 500: High risk with new payee
            Rule(
                priority=500,
                name="high_risk_new_payee",
                description="High risk transaction to new payee",
                condition=lambda i, u: (
                    i.get('is_new_payee', False) and
                    i.get('country_risk', 0) > 0.7 and
                    i.get('final_risk', 0) > 0.6
                ),
                action=Action.DELAY_TRANSACTION,
                requires_approval=False,
                justification="High-risk transaction to new payee. Delaying for review."
            ),

            # Priority 550: High risk general (covers 0.7-0.9 gap)
            Rule(
                priority=550,
                name="high_risk_general",
                description="High risk requires MFA challenge",
                condition=lambda i, u: 0.7 < i.get('final_risk', 0) <= 0.9,
                action=Action.MFA_CHALLENGE,
                requires_approval=False,
                justification="High risk activity detected. Requiring step-up authentication.",
                user_tier_override={'vip': Action.MANUAL_REVIEW}
            ),

            # Priority 600: Medium risk MFA challenge
            Rule(
                priority=600,
                name="medium_risk_mfa",
                description="Medium risk requires step-up authentication",
                condition=lambda i, u: 0.5 < i.get('final_risk', 0) <= 0.7,
                action=Action.MFA_CHALLENGE,
                requires_approval=False,
                justification="Medium risk activity detected. Requiring MFA verification."
            ),

            # Priority 700: Suspicious location
            Rule(
                priority=700,
                name="suspicious_location",
                description="Login from suspicious location",
                condition=lambda i, u: (
                    i.get('location_deviation_km', 0) > 1000 and
                    i.get('device_match_score', 1) == 0
                ),
                action=Action.MFA_CHALLENGE,
                requires_approval=False,
                justification="Login from new location with new device. MFA challenge required."
            ),

            # Priority 800: New device alert
            Rule(
                priority=800,
                name="new_device_login",
                description="Login from new device for existing user",
                condition=lambda i, u: (
                    i.get('device_match_score', 1) == 0 and
                    u.get('has_history', False)
                ),
                action=Action.RESTRICT_SESSION,
                requires_approval=False,
                justification="New device detected for established user. Restricting session permissions."
            ),

            # Priority 900: Multiple failed attempts
            Rule(
                priority=900,
                name="multiple_failed_attempts",
                description="Multiple failed login attempts",
                condition=lambda i, u: i.get('failed_attempts_last_minute', 0) >= 5,
                action=Action.NOTIFY_SOC,
                requires_approval=False,
                justification="Multiple failed login attempts detected. Alerting SOC."
            ),

            # Priority 950: Bot-like behavior
            Rule(
                priority=950,
                name="bot_like_behavior",
                description="Bot-like request rate detected",
                condition=lambda i, u: i.get('request_rate_band') == 'BOT_LIKE',
                action=Action.RESTRICT_SESSION,
                requires_approval=False,
                justification="Bot-like behavior detected. Session restricted."
            ),

            # Priority 1000: Regulatory compliance
            Rule(
                priority=1000,
                name="regulatory_compliance",
                description="Transaction requires compliance reporting",
                condition=lambda i, u: (
                    i.get('country_risk', 0) > 0.8 or
                    (i.get('amount', 0) > 10000 and i.get('is_new_payee', False))
                ),
                action=Action.REPORT_TO_COMPLIANCE,
                requires_approval=True,
                justification="Transaction requires compliance reporting due to high risk."
            ),

            # Priority 9999: Default rule (lowest priority)
            Rule(
                priority=9999,
                name="default_log_only",
                description="Default logging for benign events",
                condition=lambda i, u: True,
                action=Action.LOG_ONLY,
                requires_approval=False,
                justification="No suspicious patterns detected. Logging only."
            )
        ]

    # ==================================================================
    #  LEGACY decide() — backward-compatible with pipeline.py
    # ==================================================================

    def decide(self, incident: Dict, user_context: Dict) -> Dict:
        """
        Evaluate rules and return decision with full context.
        (Backward-compatible with existing pipeline.)
        """
        selected_rule = None
        rule_evaluation_log = []

        for rule in sorted(self.rules, key=lambda r: r.priority):
            try:
                if rule.condition(incident, user_context):
                    selected_rule = rule
                    rule_evaluation_log.append({
                        'rule': rule.name,
                        'priority': rule.priority,
                        'matched': True,
                        'action': rule.action.value
                    })
                    break
                else:
                    rule_evaluation_log.append({
                        'rule': rule.name,
                        'priority': rule.priority,
                        'matched': False
                    })
            except Exception as e:
                rule_evaluation_log.append({
                    'rule': rule.name,
                    'priority': rule.priority,
                    'error': str(e)
                })
                continue

        if not selected_rule:
            selected_rule = self.rules[-1]
            rule_evaluation_log.append({
                'rule': 'default_fallback',
                'matched': True,
                'action': selected_rule.action.value
            })

        # Apply user tier override
        final_action = selected_rule.action
        final_justification = selected_rule.justification
        tier = user_context.get('tier', 'basic')

        if selected_rule.user_tier_override and tier in selected_rule.user_tier_override:
            final_action = selected_rule.user_tier_override[tier]
            final_justification = f"OVERRIDE: {selected_rule.justification} (VIP protection applied)"

        # Policy: Never auto-block VIP users
        if tier == 'vip' and final_action in [Action.BLOCK_TRANSACTION, Action.FREEZE_ACCOUNT]:
            final_action = Action.MANUAL_REVIEW
            final_justification = f"POLICY: VIP user - {selected_rule.justification} converted to manual review"

        decision = {
            'action': final_action,
            'action_value': final_action.value,
            'justification': final_justification,
            'requires_approval': selected_rule.requires_approval or final_action == Action.MANUAL_REVIEW,
            'rule_name': selected_rule.name,
            'rule_priority': selected_rule.priority,
            'risk_score': incident.get('final_risk', 0),
            'incident_id': incident.get('incident_id'),
            'user_id': incident.get('user_id'),
            'timestamp': datetime.now().isoformat(),
            'rule_evaluation_log': rule_evaluation_log,
            'is_threat': incident.get('final_risk', 0) > 0.7
        }

        self.decision_history.append({
            **decision,
            'incident_summary': {
                'event_type': incident.get('event_type'),
                'final_risk': incident.get('final_risk'),
                'incident_type': incident.get('incident_type')
            }
        })

        return decision

    # ==================================================================
    #  NEW process() — full orchestrated pipeline
    # ==================================================================

    def process(self, incident: Dict, user_context: Dict,
                user_baseline: Optional[Dict] = None,
                playbook_gen=None) -> Dict:
        """
        Process incident through the **complete** response pipeline:
          1. Enrich with personalized bands
          2. Evaluate rules
          3. Apply policy overrides
          4. Generate playbook
          5. Write audit log

        Parameters
        ----------
        incident      : raw incident dict from detection pipeline
        user_context  : user tier / type / history
        user_baseline : Redis baseline (optional)
        playbook_gen  : PlaybookGenerator instance (optional, reuses pipeline's)

        Returns
        -------
        dict with status, incident (enriched), decision, playbook
        """
        # 1. Enrich
        enriched = self.band_enricher.enrich(incident, user_baseline)
        logger.info("Enriched incident %s: risk_band=%s amount_band=%s",
                     enriched.get('incident_id'), enriched.get('risk_band'),
                     enriched.get('amount_band'))

        # 2. Evaluate rules (reuse existing logic)
        selected_rule, rule_log = self._evaluate_rules(enriched, user_context)
        primary_actions = [selected_rule.action]
        if selected_rule.additional_actions:
            primary_actions.extend(selected_rule.additional_actions)

        # Apply tier override
        tier = user_context.get('tier', 'basic')
        if selected_rule.user_tier_override and tier in selected_rule.user_tier_override:
            primary_actions[0] = selected_rule.user_tier_override[tier]

        logger.info("Rule matched: %s -> %s", selected_rule.name,
                     [a.value for a in primary_actions])

        # 3. Policy overrides
        pol = self.policy_engine.apply(
            enriched, user_context, primary_actions, selected_rule.requires_approval
        )
        final_actions = pol['actions']
        logger.info("Policies applied: %s -> %s", pol['applied_policies'],
                     [a.value for a in final_actions])

        # 4. Build decision object
        risk = enriched.get('final_risk', 0)
        decision = {
            'action_value': final_actions[0].value if final_actions else 'LOG_ONLY',
            'actions': [a.value for a in final_actions],
            'justification': selected_rule.justification,
            'requires_approval': pol['requires_approval'],
            'rule_name': selected_rule.name,
            'rule_priority': selected_rule.priority,
            'policies_applied': pol['applied_policies'],
            'additional_notifications': pol['additional_notify'],
            'risk_score': risk,
            'risk_band': enriched.get('risk_band', 'UNKNOWN'),
            'incident_id': enriched.get('incident_id'),
            'user_id': enriched.get('user_id', enriched.get('entity_id')),
            'timestamp': datetime.now().isoformat(),
            'rule_evaluation_log': rule_log,
            'is_threat': risk > 0.7,
        }

        # 5. Playbook
        if playbook_gen:
            evidence = {
                'core_features': enriched.get('core_features', {}),
                'behavioral_context': enriched.get('behavioral_context', {}),
                'model_outputs': {
                    'micro_risk': enriched.get('micro_risk'),
                    'final_risk': risk,
                    'anomaly_score': enriched.get('anomaly_score'),
                },
            }
            playbook = playbook_gen.generate(enriched, decision, evidence)
        else:
            playbook = self._generate_minimal_playbook(enriched, decision)

        # 6. Audit
        try:
            self.audit_logger.log(enriched, decision, final_actions, playbook, user_context)
        except Exception as exc:
            logger.warning("Audit log failed: %s", exc)

        # Track history
        self.decision_history.append({**decision, 'incident_type': enriched.get('incident_type')})

        return {
            'status': 'processed',
            'incident': enriched,
            'decision': decision,
            'playbook': playbook,
        }

    # ------------------------------------------------------------------
    #  Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_rules(self, incident: Dict, user_context: Dict):
        """Evaluate rules, return (selected_rule, log)."""
        log = []
        for rule in sorted(self.rules, key=lambda r: r.priority):
            try:
                if rule.condition(incident, user_context):
                    log.append({'rule': rule.name, 'priority': rule.priority,
                                'matched': True, 'action': rule.action.value})
                    return rule, log
                log.append({'rule': rule.name, 'priority': rule.priority, 'matched': False})
            except Exception as e:
                log.append({'rule': rule.name, 'priority': rule.priority, 'error': str(e)})
        # fallback
        default = self.rules[-1]
        log.append({'rule': default.name, 'matched': True, 'action': default.action.value})
        return default, log

    @staticmethod
    def _generate_minimal_playbook(incident: Dict, decision: Dict) -> Dict:
        """Lightweight playbook when no PlaybookGenerator is available."""
        ts = datetime.now()
        actions_str = ', '.join(decision.get('actions', ['LOG_ONLY']))
        risk = incident.get('final_risk', 0)
        risk_band = incident.get('risk_band', 'UNKNOWN')
        inc_type = incident.get('incident_type', 'security_event').replace('_', ' ').title()

        return {
            'playbook_id': f"PB_{ts.strftime('%Y%m%d_%H%M%S')}",
            'generated_at': ts.isoformat(),
            'status': 'pending_approval' if decision.get('requires_approval') else 'auto_executed',
            'content': (
                f"1) Incident Playbook: {inc_type}\n\n"
                f"2) Incident Details\n"
                f"   - Incident ID: {incident.get('incident_id')}\n"
                f"   - Timestamp: {incident.get('timestamp')}\n"
                f"   - User: {incident.get('user_id', incident.get('entity_id'))} "
                f"({incident.get('user_tier', 'standard')})\n"
                f"   - Risk Score: {risk:.3f} ({risk_band})\n"
                f"   - Incident Type: {incident.get('incident_type')}\n\n"
                f"3) Containment Strategies\n"
                f"   - Actions: {actions_str}\n\n"
                f"4) Steps to be Done\n"
                f"   4.1 Investigation - Review user activity\n"
                f"   4.2 Remediation   - Execute {actions_str}\n"
                f"   4.3 Escalation    - If pattern continues, escalate\n\n"
                f"5) Justification\n"
                f"   {decision.get('justification', '')}\n"
                f"   Rule: {decision.get('rule_name')}\n"
                f"   Policies: {', '.join(decision.get('policies_applied', [])) or 'None'}\n\n"
                f"6) Documentation\n"
                f"   - Generated: {ts.isoformat()}\n"
                f"   - Actions: {actions_str}\n"
                f"   - Status: Pending\n"
            ),
        }

    # ------------------------------------------------------------------
    #  History / stats (unchanged)
    # ------------------------------------------------------------------

    def get_decision_history(self, limit: int = 100) -> List[Dict]:
        return self.decision_history[-limit:]

    def get_rule_statistics(self) -> Dict:
        stats: Dict[str, int] = {}
        for d in self.decision_history:
            rule = d.get('rule_name', 'unknown')
            stats[rule] = stats.get(rule, 0) + 1
        return stats
