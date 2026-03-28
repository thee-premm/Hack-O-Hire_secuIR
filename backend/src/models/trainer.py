import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle

def prepare_training_data(df):
    # Simulate labeling: we'll mark events that are from attacks (we know from generation)
    # In synthetic data, we have no explicit label. For demonstration, we'll manually label
    # based on some heuristics. For a real hackathon, you'd have a labeled dataset.
    # Here, we'll just create a mock label: treat any transaction > 5000 as malicious.
    df['label'] = ((df['event_type'] == 'transaction') & (df['amount'] > 5000)).astype(int)
    # Compute core features (simplified) for all events
    features = []
    for _, row in df.iterrows():
        f = []
        f.append(row['timestamp'].hour)
        f.append(row['timestamp'].weekday())
        f.append(0)  # session_event_count placeholder
        f.append(0)  # entropy placeholder
        f.append(0)  # rate placeholder
        f.append(0)  # login_hour_dev placeholder
        f.append(1 if row.get('is_new_payee') else 0)  # device_match
        f.append(0)  # location deviation
        f.append(0)  # cumulative risk
        f.append(0)  # last window risk
        f.append(row.get('amount', 0) / 10000)  # transaction amount scaled
        features.append(f)
    X = np.array(features)
    y = df['label'].values
    return X, y

def train_models():
    # Load synthetic data
    df = pd.read_csv('synthetic_logs.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed')
    df['amount'] = df['amount'].fillna(0)
    X, y = prepare_training_data(df)
    
    # Logistic Regression
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    lr = LogisticRegression(class_weight='balanced')
    lr.fit(X_scaled, y)
    with open('models/lr_model.pkl', 'wb') as f:
        pickle.dump((lr, scaler), f)
    
    # Isolation Forest (unsupervised, use X)
    iso = IsolationForest(contamination=0.05, random_state=42)
    iso.fit(X_scaled)
    with open('models/iso_model.pkl', 'wb') as f:
        pickle.dump((iso, scaler), f)
    
    # XGBoost (we'll skip for MVP to avoid extra dependency, but can be added)
    print("Models trained and saved.")

if __name__ == '__main__':
    train_models()
