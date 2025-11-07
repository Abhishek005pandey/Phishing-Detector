import argparse
import csv
import os
from joblib import dump
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import precision_score, recall_score, f1_score
from ml_features import extract_features

# Define paths
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, 'rf_model.joblib')

def load_dataset(csv_path: str):
    """Load CSV file and return URLs + labels"""
    urls = []
    labels = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get('url') or row.get('URL') or row.get('link')
            label = row.get('label')
            if not url or label not in ('phishing', 'benign'):
                continue
            urls.append(url.strip())
            labels.append(1 if label == 'phishing' else 0)
    return urls, np.array(labels)

def build_features(urls, no_whois=False):
    """Convert URLs into numeric features using extract_features()"""
    X = []
    for u in urls:
        vec, names = extract_features(u, no_whois=no_whois)
        X.append(vec)
    return np.array(X), names

def main():
    parser = argparse.ArgumentParser(description="Train phishing URL detection model")
    parser.add_argument('csv', help='Path to labeled CSV (columns: url,label)')
    parser.add_argument('--no-whois', action='store_true', help='Skip WHOIS lookups (faster)')
    args = parser.parse_args()

    # Load dataset
    urls, y = load_dataset(args.csv)
    if len(urls) == 0:
        print('❌ No valid rows found in', args.csv)
        return

    print(f'📂 Loaded {len(urls)} URLs, extracting features (no_whois={args.no_whois}) ...')
    X, feature_names = build_features(urls, no_whois=args.no_whois)
    print('🧩 Feature names:', feature_names)
    print('📊 X shape:', X.shape)

    # Initialize classifier
    clf = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1
    )

    # Adjust CV folds based on dataset size
    cv_folds = 2 if len(y) < 10 else 5
    print(f'🔁 Running {cv_folds}-fold cross-validation (accuracy)...')

    scores = cross_val_score(clf, X, y, cv=cv_folds, scoring='accuracy', n_jobs=-1)
    print('✅ CV accuracy scores:', scores, 'mean:', round(scores.mean(), 3))

    # Train on full dataset
    clf.fit(X, y)

    # Save model
    dump({'model': clf, 'feature_names': feature_names}, MODEL_PATH)
    print(f'💾 Model trained and saved to: {MODEL_PATH}')

    # Evaluate on training data
    preds = clf.predict(X)
    p = precision_score(y, preds)
    r = recall_score(y, preds)
    f1 = f1_score(y, preds)
    print(f'📈 Training precision={p:.3f} recall={r:.3f} f1={f1:.3f}')

if __name__ == '__main__':
    main()

