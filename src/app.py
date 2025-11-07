# src/app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from joblib import load
import os
import logging

# local analyzer/model imports (must exist in src/)
from ml_features import extract_features

# Initialize app
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# Path to model (models/rf_model.joblib relative to project root)
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')

# Load model
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        "Model not found. Train it first with: python src/train.py data/labeled_urls.csv"
    )

_model_bundle = load(MODEL_PATH)
model = _model_bundle.get('model')
feature_names = _model_bundle.get('feature_names', [])

# ---------------------
# /predict  (ML only)
# ---------------------
@app.route('/predict', methods=['POST'])
def predict():
    """
    POST JSON: { "url": "<url>" }
    Returns: { "url": "<url>", "label": "phishing|benign", "probability": 0.123 }
    """
    data = request.get_json(force=True, silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL'}), 400

    url = data['url']
    try:
        vec, _ = extract_features(url, no_whois=True)
    except Exception as e:
        return jsonify({'error': f'feature extraction failed: {e}'}), 500

    try:
        pred = model.predict([vec])[0]
        prob = model.predict_proba([vec])[0][1] if hasattr(model, 'predict_proba') else None
    except Exception as e:
        return jsonify({'error': f'model prediction failed: {e}'}), 500

    label = 'phishing' if int(pred) == 1 else 'benign'
    return jsonify({
        'url': url,
        'label': label,
        'probability': round(float(prob), 3) if prob is not None else None
    })

# ---------------------
# /analyze  (full CLI analyze)
# ---------------------
@app.route('/analyze', methods=['POST'])
def analyze_full():
    """
    Returns the full heuristic analysis used by your CLI analyze() function.
    POST JSON: { "url": "<url>" }
    """
    payload = request.get_json(force=True, silent=True)
    if not payload or 'url' not in payload:
        return jsonify({'error': 'missing url'}), 400

    url = payload['url']
    try:
        # try both import paths so it works when running from project root
        try:
            from src.main import analyze as cli_analyze
        except Exception:
            from main import analyze as cli_analyze
        result = cli_analyze(url)
        return jsonify(result)
    except Exception as e:
        logging.exception("analyze() failed")
        return jsonify({'error': str(e)}), 500

# ---------------------
# Serve web UI from src/web (index.html + static files)
# ---------------------
WEB_DIR = os.path.join(os.path.dirname(__file__), 'web')

@app.route('/', methods=['GET'])
def serve_index():
    index_path = os.path.join(WEB_DIR, 'index.html')
    if not os.path.exists(index_path):
        return jsonify({'error': 'web UI not found. Put index.html in src/web/'}), 404
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/<path:filename>', methods=['GET'])
def serve_static(filename):
    file_path = os.path.join(WEB_DIR, filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'file not found'}), 404
    return send_from_directory(WEB_DIR, filename)

# ---------------------
# Simple health route
# ---------------------
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

# ---------------------
# Run server
# ---------------------
if __name__ == '__main__':
    # host 0.0.0.0 so reachable from LAN (use 127.0.0.1 if you prefer local only)
    app.run(host='0.0.0.0', port=5000, debug=True)

