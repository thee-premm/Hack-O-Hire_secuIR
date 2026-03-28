from fastapi import FastAPI
import uvicorn
import uuid
from datetime import datetime

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello World"}

@app.post("/api/ingest")
def ingest(event: dict):
    raw_log = event.get("raw_log", {})
    
    # Extract fields
    user_id = raw_log.get("user_id", "unknown")
    amount = raw_log.get("amount", 0)
    is_new_payee = raw_log.get("is_new_payee", False)
    payee_country = raw_log.get("payee_country", "")
    event_type = raw_log.get("event_type", "api_call")
    device_id = raw_log.get("device_id", "unknown")
    ip_address = raw_log.get("ip_address", "0.0.0.0")
    location_country = raw_log.get("location_country", "US")
    timestamp = raw_log.get("timestamp", datetime.now().isoformat())
    
    # Calculate risk score
    if amount > 10000 and is_new_payee:
        risk_score = 0.85
        action = "BLOCK_TRANSACTION"
        action_value = "BLOCK_TRANSACTION"
        is_threat = True
        justification = "Critical risk detected. Large transaction to new payee."
        incident_type = "account_takeover"
    elif amount > 5000:
        risk_score = 0.65
        action = "MFA_CHALLENGE"
        action_value = "MFA_CHALLENGE"
        is_threat = False
        justification = "Medium risk detected. Large transaction amount."
        incident_type = "suspicious"
    elif is_new_payee or payee_country in ["NG", "RU", "CN"]:
        risk_score = 0.55
        action = "MFA_CHALLENGE"
        action_value = "MFA_CHALLENGE"
        is_threat = False
        justification = "Suspicious activity detected. New payee or high-risk country."
        incident_type = "suspicious"
    else:
        risk_score = 0.12
        action = "LOG_ONLY"
        action_value = "LOG_ONLY"
        is_threat = False
        justification = "No suspicious patterns detected. Logging only."
        incident_type = "benign"
    
    # Build full response
    response = {
        "status": "processed",
        "incident": {
            "incident_id": str(uuid.uuid4())[:8],
            "timestamp": timestamp,
            "user_id": user_id,
            "user_type": raw_log.get("user_type", "customer"),
            "event_type": event_type,
            "final_risk": risk_score,
            "micro_risk": risk_score * 0.95,
            "anomaly_score": risk_score * 1.05,
            "incident_type": incident_type,
            "device_id": device_id,
            "ip_address": ip_address,
            "location_country": location_country,
            "amount": amount,
            "is_new_payee": is_new_payee,
            "payee_country": payee_country
        },
        "decision": {
            "action": action,
            "action_value": action_value,
            "justification": justification,
            "requires_approval": action == "MANUAL_REVIEW",
            "rule_name": "risk_based_rule",
            "rule_priority": 500,
            "risk_score": risk_score,
            "incident_id": str(uuid.uuid4())[:8],
            "user_id": user_id,
            "timestamp": datetime.now().isoformat(),
            "is_threat": is_threat
        },
        "playbook": {
            "playbook_id": f"PB_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "status": "auto_executed" if not is_threat else "pending_review",
            "incident_summary": {
                "incident_id": str(uuid.uuid4())[:8],
                "user_id": user_id,
                "risk_score": risk_score,
                "incident_type": incident_type
            },
            "decision": {
                "action": action,
                "justification": justification,
                "requires_approval": action == "MANUAL_REVIEW"
            },
            "investigation_steps": [
                f"Review user activity for {user_id}",
                f"Verify transaction of ${amount}",
                f"Confirm {action} action was executed",
                "Document findings"
            ]
        }
    }
    
    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
