# app.py — PhishGuard Python ML Backend
# Run: python app.py
# Requires: pip install flask flask-cors scikit-learn pandas numpy requests

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import math
import urllib.parse

app = Flask(__name__)
CORS(app)  # Allow Chrome extension to call this

# ─── Feature Extraction ────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.link', '.work', '.party', '.review', '.trade', '.date', '.racing'
}

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'wikipedia.org', 'reddit.com', 'stackoverflow.com',
    'cloudflare.com', 'mozilla.org', 'openai.com', 'anthropic.com'
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'paypal', 'password', 'credential', 'wallet', 'suspended',
    'alert', 'notification', 'helpdesk', 'support', 'unusual', 'activity'
]

def extract_features(url: str) -> dict:
    """Extract numerical features from a URL for ML prediction."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
        full_path = path + query
    except Exception:
        return {k: 0 for k in get_feature_names()}

    # Root domain
    parts = hostname.split('.')
    root_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    features = {
        # Length features
        'url_length':           len(url),
        'hostname_length':      len(hostname),
        'path_length':          len(path),
        'query_length':         len(query),

        # Protocol
        'has_https':            1 if parsed.scheme == 'https' else 0,

        # Domain features
        'num_subdomains':       max(0, len(parts) - 2),
        'num_hyphens_domain':   hostname.count('-'),
        'num_dots':             hostname.count('.'),
        'num_digits_domain':    sum(c.isdigit() for c in hostname),
        'is_ip_address':        1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0,
        'has_suspicious_tld':   1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
        'is_trusted_domain':    1 if root_domain in TRUSTED_DOMAINS else 0,
        'starts_with_xn':       1 if hostname.startswith('xn--') else 0,

        # Path features
        'num_slashes_path':     path.count('/'),
        'has_double_slash':     1 if '//' in path else 0,
        'has_at_symbol':        1 if '@' in url else 0,
        'has_hex_in_path':      1 if re.search(r'%[0-9a-fA-F]{2}', full_path) else 0,
        'num_params':           len(query.split('&')) if query else 0,

        # Keyword features
        'num_phishing_keywords': sum(1 for kw in PHISHING_KEYWORDS if kw in url.lower()),
        'has_brand_impersonation': 1 if re.search(
            r'paypa[l1]|g[o0]{2}gle|arnazon|amaz[o0]n|micr[o0]s[o0]ft|netfl[i1]x',
            hostname, re.I
        ) else 0,

        # Entropy (randomness in domain)
        'domain_entropy':       _entropy(hostname),

        # Non-standard port
        'has_nonstandard_port': 1 if parsed.port and parsed.port not in (80, 443) else 0,
    }

    return features

def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((f/total) * math.log2(f/total) for f in freq.values())

def get_feature_names():
    return list(extract_features('https://example.com').keys())


# ─── Simple Rule-based Scorer (works without training data) ───────────────────

def rule_based_score(features: dict, url: str) -> tuple[int, list]:
    """
    Score 0–100 based on extracted features.
    Returns (score, flags_list)
    """
    score = 0
    flags = []

    if not features.get('has_https'):
        score += 20
        flags.append({'type': 'bad', 'msg': 'No HTTPS — connection is unencrypted'})

    if features.get('is_trusted_domain'):
        score = max(0, score - 30)
        flags.append({'type': 'good', 'msg': 'Verified trusted domain'})

    if features.get('has_suspicious_tld'):
        score += 25
        flags.append({'type': 'bad', 'msg': 'Suspicious free TLD (common in phishing)'})

    if features.get('is_ip_address'):
        score += 30
        flags.append({'type': 'bad', 'msg': 'IP address used instead of domain'})

    if features.get('has_brand_impersonation'):
        score += 35
        flags.append({'type': 'bad', 'msg': 'Brand name impersonation detected'})

    if features.get('url_length', 0) > 100:
        score += 10
        flags.append({'type': 'warn', 'msg': f"Long URL ({features['url_length']} chars)"})

    if features.get('num_subdomains', 0) >= 3:
        score += 15
        flags.append({'type': 'bad', 'msg': f"Too many subdomains ({features['num_subdomains']})"})

    if features.get('num_hyphens_domain', 0) >= 3:
        score += 15
        flags.append({'type': 'bad', 'msg': 'Excessive hyphens in domain'})

    if features.get('has_at_symbol'):
        score += 25
        flags.append({'type': 'bad', 'msg': '@ symbol in URL — redirect trick'})

    if features.get('has_double_slash'):
        score += 20
        flags.append({'type': 'bad', 'msg': 'Double slash in path — redirect manipulation'})

    if features.get('starts_with_xn'):
        score += 20
        flags.append({'type': 'bad', 'msg': 'Internationalized domain (homograph attack risk)'})

    if features.get('num_phishing_keywords', 0) >= 2:
        score += 12
        flags.append({'type': 'warn', 'msg': f"Multiple phishing keywords in URL ({features['num_phishing_keywords']})"})

    if features.get('domain_entropy', 0) > 4.0:
        score += 10
        flags.append({'type': 'warn', 'msg': 'High randomness in domain name'})

    if features.get('has_nonstandard_port'):
        score += 15
        flags.append({'type': 'warn', 'msg': 'Non-standard port number'})

    if not flags:
        flags.append({'type': 'good', 'msg': 'No suspicious patterns detected'})

    return min(100, max(0, score)), flags


# ─── Optional: Train ML model on PhishTank dataset ────────────────────────────
# Uncomment and run train_model() once to create model.pkl
#
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report
# import pickle, csv
#
# def train_model():
#     """
#     Download dataset from: https://data.phishtank.com/data/online-valid.csv
#     Also get legit URLs from: https://moz.com/top500  or  Alexa top 1M
#     """
#     X, y = [], []
#
#     # Load phishing URLs
#     with open('phishing_urls.csv') as f:
#         for row in csv.DictReader(f):
#             feats = extract_features(row['url'])
#             X.append(list(feats.values()))
#             y.append(1)
#
#     # Load legitimate URLs
#     with open('legitimate_urls.txt') as f:
#         for line in f:
#             feats = extract_features(line.strip())
#             X.append(list(feats.values()))
#             y.append(0)
#
#     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
#     clf = RandomForestClassifier(n_estimators=100, random_state=42)
#     clf.fit(X_train, y_train)
#
#     print(classification_report(y_test, clf.predict(X_test)))
#     with open('model.pkl', 'wb') as f:
#         pickle.dump(clf, f)
#     print("Model saved to model.pkl")
#
# ─── Load ML model if available ───────────────────────────────────────────────
#
# ml_model = None
# try:
#     import pickle
#     with open('model.pkl', 'rb') as f:
#         ml_model = pickle.load(f)
#     print("[PhishGuard] ML model loaded successfully")
# except FileNotFoundError:
#     print("[PhishGuard] No ML model found — using rule-based scoring only")


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Extract features
    features = extract_features(url)

    # Rule-based score
    score, flags = rule_based_score(features, url)

    # Optional: use ML model if loaded
    ml_score = None
    # if ml_model:
    #     feat_vector = [list(features.values())]
    #     proba = ml_model.predict_proba(feat_vector)[0]
    #     ml_score = int(proba[1] * 100)
    #     # Blend ML + rule-based
    #     score = int(0.6 * ml_score + 0.4 * score)

    result = {
        'url':      url,
        'score':    score,
        'level':    'safe' if score <= 30 else 'suspicious' if score <= 65 else 'dangerous',
        'flags':    flags,
        'features': features,
        'ml_score': ml_score,
        'info': {
            'Analysis': 'Python backend (rule-based)',
            'Features extracted': len(features),
        }
    }

    return jsonify(result)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'PhishGuard Backend'})


@app.route('/batch', methods=['POST'])
def batch_analyze():
    """Analyze multiple URLs at once."""
    data = request.get_json()
    urls = data.get('urls', [])
    results = []
    for url in urls[:50]:  # Max 50
        features = extract_features(url)
        score, flags = rule_based_score(features, url)
        results.append({'url': url, 'score': score, 'level': 'safe' if score <= 30 else 'suspicious' if score <= 65 else 'dangerous'})
    return jsonify({'results': results})


if __name__ == '__main__':
    print("PhishGuard backend running on http://localhost:5000")
    print("Extension will auto-connect to this backend.")
    app.run(debug=True, port=5000)
