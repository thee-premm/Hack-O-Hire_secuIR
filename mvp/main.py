import pandas as pd
from pipeline import DetectionPipeline

def main():
    # Load synthetic logs
    df = pd.read_csv('synthetic_logs.csv', parse_dates=['timestamp'])
    # Sort by timestamp
    df = df.sort_values('timestamp')
    
    pipeline = DetectionPipeline()
    
    # Process first 100 events
    for idx, row in df.head(100).iterrows():
        event = row.to_dict()
        # Convert timestamp back to datetime if needed
        event['timestamp'] = pd.to_datetime(event['timestamp'])
        # Ensure all required fields exist (fill NaN)
        for k, v in event.items():
            if pd.isna(v):
                event[k] = None
        print(f"Processing event {idx}: {event['event_type']} by {event['user_id']}")
        pipeline.process_event(event)

if __name__ == '__main__':
    main()
