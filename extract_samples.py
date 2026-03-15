#!/usr/bin/env python
"""Extract real sample features from phishing.csv."""
import pandas as pd

df = pd.read_csv("phishing.csv")
if 'Index' in df.columns:
    df = df.drop(['Index'], axis=1)
df.drop_duplicates(inplace=True)

# Drop low-correlation columns
cols_to_drop = ['LongURL','Symbol@','ShortURL','Redirecting//','DomainRegLen', 
                'Favicon', 'UsingPopupWindow', 'IframeRedirection', 'LinksPointingToPage']
df.drop(columns=[c for c in cols_to_drop if c in df.columns], inplace=True)

# Print column names (feature names)
print("Feature names:")
feature_names = list(df.columns)
feature_names.remove('class')
for i, name in enumerate(feature_names, 1):
    print(f"  {i}. {name}")

# Get a legitimate example
legit = df[df['class'] == 1].iloc[5]  # Pick a random legitimate one
print(f"\nLegitimate (Safe) Example - Class:{legit['class']}")
for feat in feature_names:
    print(f"  '{feat}': {int(legit[feat])},")

# Get a phishing example
phishing = df[df['class'] == -1].iloc[5]
print(f"\nPhishing (Not Safe) Example - Class: {phishing['class']}")
for feat in feature_names:
    print(f"  '{feat}': {int(phishing[feat])},")
