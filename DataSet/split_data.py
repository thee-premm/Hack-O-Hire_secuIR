import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from datetime import datetime
import os

print("="*70)
print("DATASET SPLITTER - 50K Training | 12K Testing | 8K Calibration")
print("="*70)

# Load the generated dataset
print("\n📂 Loading dataset...")
input_file = 'synthetic_bank_logs_70000_robust.csv'
df = pd.read_csv(input_file)
print(f"✅ Loaded {len(df):,} rows from {input_file}")

# Set split sizes
TARGET_TRAIN = 50000
TARGET_TEST = 12000
TARGET_CALIB = 8000

print(f"\n📊 Target Split:")
print(f"  - Training: {TARGET_TRAIN:,} rows")
print(f"  - Testing: {TARGET_TEST:,} rows")
print(f"  - Calibration: {TARGET_CALIB:,} rows")

# Create output directory
output_dir = 'bank_security_dataset_70k'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
    print(f"\n📁 Created output directory: {output_dir}")

# Prepare data for stratification
print("\n🔧 Preparing data for splitting...")
df['stratify_col'] = df['severity'].map({
    'CRITICAL': 'high', 'HIGH': 'high', 
    'MEDIUM': 'medium', 'LOW': 'low', 'UNKNOWN': 'low'
}).fillna('low')

print(f"✅ Data prepared")

# First split: Training vs Rest
print("\n📊 Performing first split (Training vs Rest)...")
train_df, rest_df = train_test_split(
    df,
    train_size=TARGET_TRAIN,
    random_state=42,
    stratify=df['stratify_col']
)
print(f"✅ Training set: {len(train_df):,} rows")

# Second split: Test vs Calibration
print("\n📊 Performing second split (Test vs Calibration)...")
test_df, calib_df = train_test_split(
    rest_df,
    test_size=TARGET_CALIB,
    random_state=42,
    stratify=rest_df['stratify_col']
)
print(f"✅ Test set: {len(test_df):,} rows")
print(f"✅ Calibration set: {len(calib_df):,} rows")

# Validate no overlap
print("\n🔍 Validating split integrity...")
train_indices = set(train_df.index)
test_indices = set(test_df.index)
calib_indices = set(calib_df.index)

assert train_indices.isdisjoint(test_indices), "ERROR: Training and Test overlap!"
assert train_indices.isdisjoint(calib_indices), "ERROR: Training and Calibration overlap!"
assert test_indices.isdisjoint(calib_indices), "ERROR: Test and Calibration overlap!"
print("✅ No overlapping data detected!")

# Check distribution
print("\n📈 High-risk distribution check:")
print(f"  - Training: {train_df['is_high_risk'].mean()*100:.1f}% high-risk")
print(f"  - Test: {test_df['is_high_risk'].mean()*100:.1f}% high-risk")
print(f"  - Calibration: {calib_df['is_high_risk'].mean()*100:.1f}% high-risk")

# Remove temporary column
train_df.drop('stratify_col', axis=1, inplace=True)
test_df.drop('stratify_col', axis=1, inplace=True)
calib_df.drop('stratify_col', axis=1, inplace=True)

# Save raw files
print("\n💾 Saving raw datasets...")
train_df.to_csv(f'{output_dir}/training_50k.csv', index=False)
test_df.to_csv(f'{output_dir}/test_12k.csv', index=False)
calib_df.to_csv(f'{output_dir}/calibration_8k.csv', index=False)
print(f"✅ Saved to {output_dir}/")

# Create feature-rich versions
print("\n🔧 Creating feature-rich versions...")

def add_features(df):
    df_copy = df.copy()
    df_copy['message_length'] = df_copy['message'].str.len().fillna(0)
    df_copy['has_ip'] = df_copy['message'].str.contains(r'\d+\.\d+\.\d+\.\d+', na=False).astype(int)
    df_copy['has_error'] = df_copy['message'].str.contains('error|fail|denied', case=False, na=False).astype(int)
    df_copy['attempts'].fillna(0, inplace=True)
    return df_copy

train_features = add_features(train_df)
test_features = add_features(test_df)
calib_features = add_features(calib_df)

train_features.to_csv(f'{output_dir}/training_50k_features.csv', index=False)
test_features.to_csv(f'{output_dir}/test_12k_features.csv', index=False)
calib_features.to_csv(f'{output_dir}/calibration_8k_features.csv', index=False)
print("✅ Feature-rich versions saved")

# Create classification-ready files
print("\n📊 Creating classification-ready files...")
class_cols = ['ts', 'host', 'user', 'event', 'attempts', 'severity', 
              'ip', 'message', 'source', 'is_high_risk', 'message_length', 
              'has_ip', 'has_error']

train_df[class_cols].to_csv(f'{output_dir}/training_50k_classification.csv', index=False)
test_df[class_cols].to_csv(f'{output_dir}/test_12k_classification.csv', index=False)
calib_df[class_cols].to_csv(f'{output_dir}/calibration_8k_classification.csv', index=False)
print("✅ Classification-ready files saved")

# Create anomaly detection files
print("\n🔍 Creating anomaly detection files...")
anomaly_cols = ['ts', 'host', 'user', 'event', 'severity', 
                'ip', 'message', 'source']

train_df[anomaly_cols].to_csv(f'{output_dir}/training_50k_anomaly.csv', index=False)
test_df[anomaly_cols].to_csv(f'{output_dir}/test_12k_anomaly.csv', index=False)
calib_df[anomaly_cols].to_csv(f'{output_dir}/calibration_8k_anomaly.csv', index=False)
print("✅ Anomaly detection files saved")

# Generate summary
print("\n📝 Generating summary...")
summary = pd.DataFrame({
    'Split': ['Training', 'Testing', 'Calibration', 'Total'],
    'Rows': [len(train_df), len(test_df), len(calib_df), len(df)],
    'High_Risk_%': [
        f"{train_df['is_high_risk'].mean()*100:.1f}%",
        f"{test_df['is_high_risk'].mean()*100:.1f}%",
        f"{calib_df['is_high_risk'].mean()*100:.1f}%",
        f"{df['is_high_risk'].mean()*100:.1f}%"
    ]
})
summary.to_csv(f'{output_dir}/split_summary.csv', index=False)
print(summary.to_string(index=False))

# Final output
print("\n" + "="*70)
print("✅ SPLIT COMPLETE!")
print("="*70)
print(f"\n📁 Output folder: {output_dir}/")
print("\n📊 Files created:")
print(f"  1. training_50k.csv - Raw training data")
print(f"  2. test_12k.csv - Raw test data")
print(f"  3. calibration_8k.csv - Raw calibration data")
print(f"  4. training_50k_features.csv - With engineered features")
print(f"  5. test_12k_features.csv - With engineered features")
print(f"  6. calibration_8k_features.csv - With engineered features")
print(f"  7. training_50k_classification.csv - ML-ready classification")
print(f"  8. test_12k_classification.csv - ML-ready classification")
print(f"  9. calibration_8k_classification.csv - ML-ready classification")
print(f" 10. training_50k_anomaly.csv - For anomaly detection")
print(f" 11. test_12k_anomaly.csv - For anomaly detection")
print(f" 12. calibration_8k_anomaly.csv - For anomaly detection")
print(f" 13. split_summary.csv - Statistics summary")

print("\n✅ All splits are legitimate:")
print("  ✓ No data overlap between splits")
print("  ✓ Stratified split maintained distribution")
print("  ✓ Random seed 42 ensures reproducibility")
print("\n🚀 Ready for machine learning training!")
print("="*70)