import requests
from requests.exceptions import RequestException

DEFAULT_HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; PhishCheck/1.0)'}

def check_redirects(url: str, timeout: int = 6) -> dict:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers=DEFAULT_HEADERS)
        chain = [resp.url for resp in r.history] + [r.url]
        final = r.url
        contains_form = '<form' in (r.text or '').lower()
        return {
            'final_url': final,
            'status_code': r.status_code,
            'redirect_chain': chain,
            'contains_form': contains_form,
            'error': None
        }
    except RequestException as e:
        return {'error': str(e)}
