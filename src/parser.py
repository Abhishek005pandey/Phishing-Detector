import re
import tldextract
from urllib.parse import urlparse, parse_qs

IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def parse_url(url: str) -> dict:
    url = normalize_url(url)
    p = urlparse(url)
    ext = tldextract.extract(p.netloc)
    domain = ext.domain + ('.' + ext.suffix if ext.suffix else '')
    subdomain = ext.subdomain or ''
    hostname = p.hostname or ''
    is_ip = bool(IP_RE.match(hostname))

    features = {
        'original_url': url,
        'scheme': p.scheme,
        'hostname': hostname,
        'domain': domain,
        'subdomain': subdomain,
        'path': p.path,
        'path_len': len(p.path) if p.path else 0,
        'path_segments': len([seg for seg in p.path.split('/') if seg]) if p.path else 0,
        'query': p.query,
        'query_len': len(p.query) if p.query else 0,
        'num_query_params': len(parse_qs(p.query)) if p.query else 0,
        'is_ip': is_ip,
        'url_len': len(url)
    }
    return features
