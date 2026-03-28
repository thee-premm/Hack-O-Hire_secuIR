import pandas as pd
import pickle
import numpy as np
from state.session_manager import SessionManager
from state.baseline_manager import BaselineManager
from state.risk_memory import RiskMemory
from features.core_builder import CoreFeatureBuilder

df = pd.read_csv('synthetic_logs.csv', parse_dates=['timestamp'])
event = df.iloc[0].to_dict()
event['timestamp'] = pd.to_datetime(event['timestamp'])

session_mgr = SessionManager()
baseline_mgr = BaselineManager()
risk_mem = RiskMemory()
core_builder = CoreFeatureBuilder(session_mgr, baseline_mgr, risk_mem)

session = session_mgr.get_or_create_session(event['user_id'], event['session_id'], event['timestamp'])
session_mgr.update_session(event['session_id'], event)
baseline_mgr.update(event['user_id'], event)
feat = core_builder.build(event, session)

print("Core features:")
for k, v in feat.items():
    print(f"  {k}: {v}")

# Show the vector
vector = np.array([feat['hour_of_day'], feat['day_of_week'], feat['session_event_count'],
                   feat['session_entropy'], feat['session_avg_rate'], feat['login_hour_deviation'],
                   feat['device_match_score'], feat['location_deviation_km'], feat['cumulative_risk'],
                   feat['last_window_risk'], feat['transaction_amount_zscore']])
print("Vector:", vector)