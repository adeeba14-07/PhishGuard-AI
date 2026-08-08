"""
PhishGuard AI - Complete Model Training Script
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import os

print("=" * 60)
print("🛡️  PhishGuard AI - Model Training")
print("=" * 60)

# Load dataset
print("\n📂 Loading dataset...")
df = pd.read_csv('dataset/phishing_dataset.csv')
print(f"✅ Loaded {len(df)} samples")

# Separate features and labels
X = df.drop('label', axis=1)
y = df['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train model
print("\n🤖 Training Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Model Accuracy: {accuracy:.2%}")

# Save model
os.makedirs('models', exist_ok=True)
joblib.dump(model, 'models/model.pkl')
print(f"✅ Model saved to: models/model.pkl")