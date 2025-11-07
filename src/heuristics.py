import re
from typing import Tuple, List

SUSPICIOUS_KEYWORDS = ['login','secure','account','update','verify','bank','confirm','signin','paypal','ebay']
HEX_RE = re.compile(r'[0-9a-fA-F]{20,}')
AT_SIGN_RE = re.compile(r'@')

def score_tokens(features: dict) -> Tuple[int, List[str]]:
    url = features.get('original_url', '').lower()
    score = 0
    reasons = []

    if AT_SIGN_RE.search(url):
        score += 30
        reasons.append('contains_at_sign')

    if features.get('is_ip'):
        score += 25
        reasons.append('ip_in_host')

    if HEX_RE.search(url):
        score += 10
        reasons.append('long_hex')

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url:
            score += 5
            reasons.append(f'keyword_{kw}')

    if features.get('url_len', 0) > 200:
        score += 8
        reasons.append('long_url')

    subdomain = features.get('subdomain', '')
    if subdomain and len(subdomain.split('.')) >= 3:
        score += 5
        reasons.append('many_subdomains')

    return score, reasons
