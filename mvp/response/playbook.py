from datetime import datetime
from typing import Dict, List, Any, Optional
import json

class PlaybookGenerator:
    """
    Generate structured, evidence-backed response playbooks for human approval.
    
    Features:
    - Evidence collection and formatting
    - Investigation step generation
    - Approval workflow integration
    - Compliance-ready documentation
    """
    
    def __init__(self):
        self.playbook_history = []
    
    def generate(self, incident: Dict, decision: Dict, evidence: Dict) -> Dict:
        """
        Create a complete response playbook.
        
        Args:
            incident: Incident object with risk scores
            decision: Decision from response engine
            evidence: Collected evidence (features, state, etc.)
        
        Returns:
            Structured playbook with all required information
        """
        
        playbook = {
            'playbook_id': self._generate_playbook_id(),
            'generated_at': datetime.now().isoformat(),
            'status': 'pending_approval' if decision.get('requires_approval') else 'auto_executed',
            
            # Incident summary
            'incident_summary': {
                'incident_id': incident.get('incident_id', 'unknown'),
                'timestamp': incident.get('timestamp'),
                'user_id': incident.get('user_id'),
                'user_type': incident.get('user_type'),
                'user_tier': incident.get('user_tier', 'basic'),
                'event_type': incident.get('event_type'),
                'risk_score': incident.get('final_risk', 0),
                'micro_risk': incident.get('micro_risk', 0),
                'anomaly_score': incident.get('anomaly_score', 0),
                'incident_type': incident.get('incident_type', 'unknown'),
                'confidence': incident.get('confidence', 0)
            },
            
            # Evidence section
            'evidence': self._format_evidence(evidence, incident),
            
            # Decision and actions
            'decision': {
                'action': decision.get('action_value', 'LOG_ONLY'),
                'justification': decision.get('justification', ''),
                'rule_triggered': decision.get('rule_name', 'unknown'),
                'rule_priority': decision.get('rule_priority', 9999),
                'requires_approval': decision.get('requires_approval', False),
                'risk_score_at_decision': decision.get('risk_score', 0)
            },
            
            # Approval workflow
            'approval_workflow': self._determine_approval_workflow(incident, decision),
            
            # Investigation steps
            'investigation_steps': self._generate_investigation_steps(incident, decision),
            
            # Audit trail
            'audit_trail': self._create_audit_trail(incident, decision),
            
            # Recommendations
            'recommendations': self._generate_recommendations(incident, decision)
        }
        
        # Store for history
        self.playbook_history.append({
            'playbook_id': playbook['playbook_id'],
            'timestamp': playbook['generated_at'],
            'status': playbook['status']
        })
        
        return playbook
    
    def _generate_playbook_id(self) -> str:
        """Generate unique playbook ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"PB_{timestamp}"
    
    def _format_evidence(self, evidence: Dict, incident: Dict) -> List[Dict]:
        """Format evidence for playbook with confidence levels"""
        formatted = []
        
        # Core features evidence
        if evidence.get('core_features'):
            formatted.append({
                'type': 'behavioral_features',
                'title': 'Behavioral Features',
                'data': {k: v for k, v in evidence['core_features'].items() if isinstance(v, (int, float))},
                'confidence': 'high',
                'description': 'Features extracted from user behavior and session state'
            })
        
        # Model outputs evidence
        if evidence.get('model_outputs'):
            formatted.append({
                'type': 'model_predictions',
                'title': 'Model Predictions',
                'data': evidence['model_outputs'],
                'confidence': 'high' if incident.get('confidence', 0) > 0.7 else 'medium',
                'description': 'Risk scores from ML models'
            })
        
        # Session evidence
        if evidence.get('session_info'):
            formatted.append({
                'type': 'session_context',
                'title': 'Session Context',
                'data': evidence['session_info'],
                'confidence': 'high',
                'description': 'Current session information'
            })
        
        # Raw event evidence (sanitized)
        if evidence.get('raw_event_summary'):
            formatted.append({
                'type': 'raw_event',
                'title': 'Raw Event Summary',
                'data': evidence['raw_event_summary'],
                'confidence': 'high',
                'description': 'Original event data'
            })
        
        # Baseline deviation evidence
        if evidence.get('baseline_deviation'):
            formatted.append({
                'type': 'baseline_deviation',
                'title': 'Baseline Deviations',
                'data': evidence['baseline_deviation'],
                'confidence': 'medium',
                'description': 'How this event deviates from user baseline'
            })
        
        return formatted
    
    def _determine_approval_workflow(self, incident: Dict, decision: Dict) -> Dict:
        """Determine who needs to approve and workflow steps"""
        user_tier = incident.get('user_tier', 'basic')
        user_type = incident.get('user_type', 'customer')
        incident_type = incident.get('incident_type', 'unknown')
        action = decision.get('action_value', 'LOG_ONLY')
        
        # Determine approver based on context
        if user_type == 'employee':
            approver = 'security_team_and_hr'
            approval_steps = ['Security review', 'HR consultation', 'Manager approval']
        elif user_tier == 'vip':
            approver = 'security_manager'
            approval_steps = ['Security manager review', 'Executive notification (if approved)']
        elif action == 'FREEZE_ACCOUNT':
            approver = 'compliance_officer'
            approval_steps = ['Compliance review', 'Legal consultation']
        elif action == 'REPORT_TO_COMPLIANCE':
            approver = 'compliance_department'
            approval_steps = ['Compliance review', 'Regulatory filing']
        else:
            approver = 'security_analyst'
            approval_steps = ['Analyst review', 'Action confirmation']
        
        return {
            'requires_approval': decision.get('requires_approval', True),
            'approver': approver,
            'approval_steps': approval_steps,
            'estimated_response_time': self._estimate_response_time(incident),
            'escalation_path': self._get_escalation_path(incident)
        }
    
    def _estimate_response_time(self, incident: Dict) -> str:
        """Estimate response time based on severity"""
        risk = incident.get('final_risk', 0)
        if risk > 0.9:
            return 'Immediate (within 5 minutes)'
        elif risk > 0.7:
            return 'Urgent (within 15 minutes)'
        elif risk > 0.5:
            return 'Standard (within 1 hour)'
        else:
            return 'Low priority (next business day)'
    
    def _get_escalation_path(self, incident: Dict) -> List[str]:
        """Get escalation path for the incident"""
        path = ['Security Analyst']
        if incident.get('final_risk', 0) > 0.8:
            path.append('Security Manager')
        if incident.get('user_tier') == 'vip':
            path.append('Executive Team')
        if incident.get('user_type') == 'employee':
            path.append('HR Department')
        return path
    
    def _generate_investigation_steps(self, incident: Dict, decision: Dict) -> List[Dict]:
        """Generate step-by-step investigation steps"""
        steps = []
        
        # Step 1: Initial assessment
        steps.append({
            'step': 1,
            'title': 'Initial Incident Assessment',
            'actions': [
                f"Review incident summary for user {incident.get('user_id')}",
                f"Confirm risk score of {incident.get('final_risk', 0):.3f}",
                "Verify incident type and confidence"
            ],
            'estimated_time': '5 minutes'
        })
        
        # Step 2: Evidence review
        steps.append({
            'step': 2,
            'title': 'Evidence Review',
            'actions': [
                "Review behavioral features and deviations",
                "Check model predictions and anomaly scores",
                "Examine session context and history"
            ],
            'estimated_time': '10 minutes'
        })
        
        # Step 3: Context investigation
        steps.append({
            'step': 3,
            'title': 'Context Investigation',
            'actions': [
                f"Check user history for past incidents",
                f"Verify if {incident.get('user_id')} has reported issues before",
                "Review similar incidents in the past 30 days"
            ],
            'estimated_time': '15 minutes'
        })
        
        # Step 4: Action execution
        steps.append({
            'step': 4,
            'title': 'Execute Response',
            'actions': [
                f"Execute {decision.get('action_value', 'LOG_ONLY')} action",
                "Document all steps taken",
                "Update incident status"
            ],
            'estimated_time': '5 minutes'
        })
        
        # Step 5: Follow-up
        steps.append({
            'step': 5,
            'title': 'Follow-up and Closure',
            'actions': [
                "Verify action was successful",
                "Monitor for recurring patterns",
                "Close incident with notes"
            ],
            'estimated_time': '10 minutes'
        })
        
        return steps
    
    def _create_audit_trail(self, incident: Dict, decision: Dict) -> Dict:
        """Create audit trail entry"""
        return {
            'incident_id': incident.get('incident_id'),
            'timestamp': datetime.now().isoformat(),
            'decision_made': decision.get('action_value'),
            'rule_used': decision.get('rule_name'),
            'requires_approval': decision.get('requires_approval', False),
            'risk_score_at_decision': incident.get('final_risk', 0),
            'system_version': '2.0.0'
        }
    
    def _generate_recommendations(self, incident: Dict, decision: Dict) -> List[str]:
        """Generate recommendations based on incident"""
        recommendations = []
        
        risk = incident.get('final_risk', 0)
        incident_type = incident.get('incident_type', '')
        
        if risk > 0.8:
            recommendations.append("Consider implementing additional MFA for this user")
            recommendations.append("Review user's recent activity for patterns")
        
        if incident_type == 'account_takeover':
            recommendations.append("Reset user's credentials and require new MFA enrollment")
            recommendations.append("Notify user of suspicious activity")
        
        if incident.get('is_new_payee', False):
            recommendations.append("Verify new payee details before processing future transactions")
        
        if incident.get('device_match_score', 1) == 0:
            recommendations.append("Add new device to approved devices list if verified")
        
        if not recommendations:
            recommendations.append("No additional recommendations at this time")
        
        return recommendations
