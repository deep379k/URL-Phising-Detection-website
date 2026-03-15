#!/usr/bin/env python
"""
Retrain and save Phishing_model.pkl with current sklearn version.
This eliminates InconsistentVersionWarning from version mismatches.
"""
import numpy as np
import pandas as pd
import pickle
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from imblearn.over_sampling import SMOTE

print("Loading phishing.csv...")
df = pd.read_csv("phishing.csv")
print(f"Loaded: {df.shape}")

# Drop Index column
if 'Index' in df.columns:
    df = df.drop(['Index'], axis=1)

# Remove duplicates
df.drop_duplicates(inplace=True)
print(f"After removing duplicates: {df.shape}")

# Drop columns with low correlation (from notebook analysis)
cols_to_drop = ['LongURL','Symbol@','ShortURL','Redirecting//','DomainRegLen', 
                'Favicon', 'UsingPopupWindow', 'IframeRedirection', 'LinksPointingToPage']
df.drop(columns=[c for c in cols_to_drop if c in df.columns], inplace=True)
print(f"After dropping low-correlation columns: {df.shape}")

# Split features and target BEFORE transformation
X = df.drop(["class"], axis=1)
y = df["class"]

# Handle outliers with log transformation (features only)
X = np.log1p(X + 0.0001)

# Scale
print("Scaling features...")
scaler = StandardScaler()
clmn_names = X.columns
scaled = scaler.fit_transform(X)
features = pd.DataFrame(scaled, columns=clmn_names)

# Train-test split
print("Splitting into train/test sets...")
X_train, X_test, y_train, y_test = train_test_split(
    features, y, test_size=0.2, random_state=42
)

# Balance with SMOTE
print("Applying SMOTE to balance classes...")
try:
    smote = SMOTE(sampling_strategy=1)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print(f"After SMOTE: {X_train.shape}")
except Exception as e:
    print(f"SMOTE warning (non-fatal): {e}")

# Train Gradient Boosting Classifier
print("Training GradientBoostingClassifier...")
gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
gbc.fit(X_train, y_train)

# Evaluate
score = gbc.score(X_test, y_test)
print(f"Model accuracy on test set: {score:.4f}")

# Save model
print("Saving Phishing_model.pkl...")
pickle.dump(gbc, open('Phishing_model.pkl', 'wb'))
print("✓ Model saved successfully!")
print("Done. You can now run 'python app.py' without sklearn version warnings.")
