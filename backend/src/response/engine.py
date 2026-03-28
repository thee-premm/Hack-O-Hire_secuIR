from enum import Enum
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
import json

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

@dataclass
class Rule:
    """Rule definition for response engine"""
    priority: int                    # Lower number = higher priority
    name: str                        # Unique rule identifier
    description: str                 # Human-readable description
    condition: Callable              # Function that returns boolean
    action: Action                   # Action to take
    requires_approval: bool          # Whether human approval needed
    justification: str               # Why this rule was triggered
    user_tier_override: Optional[Dict[str, Action]] = None  # Tier-specific overrides

class ResponseEngine:
    """
    Deterministic rule-based response engine with human approval workflows.
    
    Features:
    - Priority-based rule evaluation
    - VIP user protection (never auto-block)
    - Regulatory compliance flags
    - Approval workflow integration
    - Complete audit trail
    """
    
    def __init__(self):
        self.rules = self._load_rules()
        self.decision_history = []  # Audit trail
        self._validate_rules()
    
    def _validate_rules(self):
        """Validate rule priorities and conditions"""
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
                user_tier_override={
                    'vip': Action.MANUAL_REVIEW
                }
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
                user_tier_override={
                    'admin': Action.NOTIFY_SOC
                }
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
                user_tier_override={
                    'vip': Action.MANUAL_REVIEW
                }
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
            
            # Priority 800: New device alert (only for users WITH established history)
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
    
    def decide(self, incident: Dict, user_context: Dict) -> Dict:
        """
        Evaluate rules and return decision with full context.
        
        Args:
            incident: Incident object with risk scores and features
            user_context: User context (tier, type, history)
        
        Returns:
            Decision dict with action, justification, approval requirements
        """
        selected_rule = None
        rule_evaluation_log = []
        
        # Sort rules by priority and evaluate
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
        
        # Fallback to default if no rule matched
        if not selected_rule:
            selected_rule = self.rules[-1]
            rule_evaluation_log.append({
                'rule': 'default_fallback',
                'matched': True,
                'action': selected_rule.action.value
            })
        
        # Apply user tier override if applicable
        final_action = selected_rule.action
        final_justification = selected_rule.justification
        tier = user_context.get('tier', 'basic')
        
        if selected_rule.user_tier_override and tier in selected_rule.user_tier_override:
            final_action = selected_rule.user_tier_override[tier]
            final_justification = f"OVERRIDE: {selected_rule.justification} (VIP protection applied)"
        
        # Policy enforcement: Never auto-block VIP users
        if tier == 'vip' and final_action in [Action.BLOCK_TRANSACTION, Action.FREEZE_ACCOUNT]:
            final_action = Action.MANUAL_REVIEW
            final_justification = f"POLICY: VIP user - {selected_rule.justification} converted to manual review"
        
        # Build decision object
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
            'rule_evaluation_log': rule_evaluation_log
        }
        
        # Store in audit trail
        self.decision_history.append({
            **decision,
            'incident_summary': {
                'event_type': incident.get('event_type'),
                'final_risk': incident.get('final_risk'),
                'incident_type': incident.get('incident_type')
            }
        })
        
        return decision
    
    def get_decision_history(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent decisions for audit"""
        return self.decision_history[-limit:]
    
    def get_rule_statistics(self) -> Dict:
        """Get statistics on rule usage"""
        stats = {}
        for decision in self.decision_history:
            rule = decision.get('rule_name', 'unknown')
            stats[rule] = stats.get(rule, 0) + 1
        return stats
