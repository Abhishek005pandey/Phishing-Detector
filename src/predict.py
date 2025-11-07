import sys, os
from joblib import load
from ml_features import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')

def main():
    if len(sys.argv) < 2:
        print('Usage: python src/predict.py <url>')
        return
    url = sys.argv[1]
    if not os.path.exists(MODEL_PATH):
        print('Model not found. Train first with: python src/train.py data/labeled_urls.csv')
        return
    obj = load(MODEL_PATH)
    model = obj['model']
    feature_names = obj['feature_names']
    vec, _ = extract_features(url, no_whois=True)  # skip whois for predict speed
    prob = model.predict_proba([vec])[0][1] if hasattr(model, 'predict_proba') else None
    pred = model.predict([vec])[0]
    label = 'phishing' if pred == 1 else 'benign'
    print('URL:', url)
    print('Predicted:', label)
    if prob is not None:
        print('Phishing probability:', round(prob, 3))
    print('Feature vector (name:value):')
    print(dict(zip(feature_names, vec)))

if __name__ == '__main__':
    main()
import sys, os
from joblib import load
from ml_features import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')

def main():
    if len(sys.argv) < 2:
        print('Usage: python src/predict.py <url>')
        return
    url = sys.argv[1]
    if not os.path.exists(MODEL_PATH):
        print('Model not found. Train first with: python src/train.py data/labeled_urls.csv')
        return
    obj = load(MODEL_PATH)
    model = obj['model']
    feature_names = obj['feature_names']
    vec, _ = extract_features(url, no_whois=True)  # skip whois for predict speed
    prob = model.predict_proba([vec])[0][1] if hasattr(model, 'predict_proba') else None
    pred = model.predict([vec])[0]
    label = 'phishing' if pred == 1 else 'benign'
    print('URL:', url)
    print('Predicted:', label)
    if prob is not None:
        print('Phishing probability:', round(prob, 3))
    print('Feature vector (name:value):')
    print(dict(zip(feature_names, vec)))

if __name__ == '__main__':
    main()
