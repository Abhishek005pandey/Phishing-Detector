from flask import Flask, render_template, request, redirect, url_for
import os
from joblib import load

# Import your existing analyzer function
# Note: analyze() is located in src/main.py and returns a heuristics result dict
from src.main import analyze as heuristic_analyze
from src.ml_features import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'rf_model.joblib')

app = Flask(__name__)
model_bundle = None

def load_model():
    global model_bundle
    if model_bundle is None and os.path.exists(MODEL_PATH):
        model_bundle = load(MODEL_PATH)
    return model_bundle

def get_ml_prediction(url, no_whois=True):
    bundle = load_model()
    if not bundle:
        return None, None
    model = bundle['model']
    feature_names = bundle['feature_names']
    vec, _ = extract_features(url, no_whois=no_whois)
    prob = model.predict_proba([vec])[0][1] if hasattr(model, 'predict_proba') else None
    pred = model.predict([vec])[0]
    label = 'phishing' if pred == 1 else 'benign'
    return label, float(prob) if prob is not None else None

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = "Please enter a URL."
        else:
            # Run heuristic analysis (this does WHOIS + active checks inside analyze())
            try:
                heur = heuristic_analyze(url)
            except Exception as e:
                heur = {'error': str(e)}
            # Run ML prediction (skip slow WHOIS for prediction by default)
            ml_label, ml_prob = get_ml_prediction(url, no_whois=True)
            # Combine results into a simple final decision
            final = {}
            heuristic_score = heur.get('score', 0) if isinstance(heur, dict) else 0
            ml_prob_val = ml_prob if ml_prob is not None else 0.0

            # Fusion rule (simple): final_score = heuristic_score + (ml_prob * 30)
            final_score = heuristic_score + (ml_prob_val * 30)
            if final_score >= 30:
                final_label = 'phishing'
            elif final_score >= 10:
                final_label = 'suspicious'
            else:
                final_label = 'benign'

            result = {
                'url': url,
                'heuristics': heur,
                'ml_label': ml_label,
                'ml_prob': ml_prob_val,
                'final_label': final_label,
                'final_score': round(final_score, 3)
            }
    return render_template('index.html', result=result, error=error)

if __name__ == '__main__':
    # Use 127.0.0.1 so it's only available locally by default
    app.run(host='127.0.0.1', port=5000, debug=True)
