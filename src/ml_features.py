import math
from typing import Dict, List, Tuple
from parser import parse_url
from heuristics import score_tokens
from active_checks import check_redirects
from whois_helper import get_domain_age_days

def safe_int(val, default=0):
    try:
        return int(val)
    except Exception:
        return default

def extract_features(url: str, no_whois: bool = False) -> Tuple[List[float], List[str]]:
    """
    Returns (feature_vector, feature_names)
    """
    feats = parse_url(url)
    score, reasons = score_tokens(feats)

    # basic numeric features
    url_len = feats.get('url_len', 0)
    path_len = feats.get('path_len', 0)
    path_segments = feats.get('path_segments', 0)
    query_len = feats.get('query_len', 0)
    num_query_params = feats.get('num_query_params', 0)
    is_ip = 1 if feats.get('is_ip') else 0

    # derived counts
    keyword_count = sum(1 for r in reasons if r.startswith('keyword_'))
    hex_present = 1 if any(r == 'long_hex' for r in reasons) else 0
    at_sign = 1 if any(r == 'contains_at_sign' for r in reasons) else 0
    many_subdomains = 1 if any(r == 'many_subdomains' for r in reasons) else 0

    # WHOIS (optional)
    whois_age = None
    if not no_whois:
        try:
            age = get_domain_age_days(feats.get('domain', ''))
            whois_age = age if age is not None else -1
        except Exception:
            whois_age = -1
    else:
        whois_age = -1

    # active checks (best-effort, may timeout or return error)
    redirects = 0
    contains_form = 0
    try:
        act = check_redirects(feats['original_url'])
        if act and not act.get('error'):
            redirects = len(act.get('redirect_chain', [])) - 1
            contains_form = 1 if act.get('contains_form') else 0
        else:
            redirects = -1
            contains_form = -1
    except Exception:
        redirects = -1
        contains_form = -1

    feature_names = [
        'url_len', 'path_len', 'path_segments', 'query_len', 'num_query_params',
        'is_ip', 'keyword_count', 'hex_present', 'at_sign', 'many_subdomains',
        'whois_age_days', 'redirects', 'contains_form'
    ]
    feature_vector = [
        float(url_len),
        float(path_len),
        float(path_segments),
        float(query_len),
        float(num_query_params),
        float(is_ip),
        float(keyword_count),
        float(hex_present),
        float(at_sign),
        float(many_subdomains),
        float(whois_age if whois_age is not None else -1),
        float(redirects),
        float(contains_form)
    ]
    # fix NaN/infinite
    feature_vector = [0.0 if (isinstance(x, float) and (math.isnan(x) or math.isinf(x))) else x for x in feature_vector]
    return feature_vector, feature_names
