#!/usr/bin/env python
"""Test model with actual training data samples."""
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load model
with (PROJECT_ROOT / 'Phishing_model.pkl').open('rb') as f:
    model = pickle.load(f)

# Load training data
df = pd.read_csv(PROJECT_ROOT / "phishing.csv")
if 'Index' in df.columns:
    df = df.drop(['Index'], axis=1)
df.drop_duplicates(inplace=True)

# Drop low-correlation columns
cols_to_drop = ['LongURL','Symbol@','ShortURL','Redirecting//','DomainRegLen', 
                'Favicon', 'UsingPopupWindow', 'IframeRedirection', 'LinksPointingToPage']
df.drop(columns=[c for c in cols_to_drop if c in df.columns], inplace=True)

# Get a legitimate (safe) example - class = 1
legit = df[df['class'] == 1].iloc[0]
legit_features = legit.drop('class').values.reshape(1, -1)
legit_class = legit['class']

# Get a phishing example - class = -1
phishing = df[df['class'] == -1].iloc[0]
phishing_features = phishing.drop('class').values.reshape(1, -1)
phishing_class = phishing['class']

print("=" * 70)
print("TESTING MODEL WITH ACTUAL TRAINING DATA")
print("=" * 70)

print(f"\n1. Legitimate (Safe) Example from Data:")
print(f"   Actual class: {legit_class}")
legit_pred = model.predict(legit_features)[0]
print(f"   Model prediction: {legit_pred}")
print(f"   Match: {'✓' if legit_pred == legit_class else '✗'}")

print(f"\n2. Phishing (Not Safe) Example from Data:")
print(f"   Actual class: {phishing_class}")
phishing_pred = model.predict(phishing_features)[0]
print(f"   Model prediction: {phishing_pred}")
print(f"   Match: {'✓' if phishing_pred == phishing_class else '✗'}")

# Get accuracy on validation set
print(f"\n3. Full Validation:")
X = df.drop(['class'], axis=1)
y = df['class']


# Scale
from sklearn.preprocessing import StandardScaler
X = np.log1p(X + 0.0001)  
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

score = model.score(X_scaled, y)
print(f"   Model accuracy on full dataset: {score:.4f}")

print("\n" + "=" * 70)
