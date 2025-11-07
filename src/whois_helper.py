import whois
import sqlite3
from datetime import datetime
from typing import Optional

DB = 'whois_cache.db'

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS whois_cache
                    (domain TEXT PRIMARY KEY, created_date TEXT, fetched_at TEXT)''')
    conn.commit()
    conn.close()

def cache_get(domain: str) -> Optional[str]:
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT created_date FROM whois_cache WHERE domain=?', (domain,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def cache_set(domain: str, created_date: str):
    conn = sqlite3.connect(DB)
    conn.execute('REPLACE INTO whois_cache(domain, created_date, fetched_at) VALUES(?,?,?)',
                 (domain, str(created_date), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_domain_age_days(domain: str) -> Optional[int]:
    init_db()
    cached = cache_get(domain)
    if cached:
        try:
            created = datetime.fromisoformat(cached)
            return (datetime.utcnow() - created).days
        except Exception:
            pass
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list) and created:
            created = created[0]
        if created:
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created)
                except Exception:
                    return None
            cache_set(domain, created.isoformat())
            return (datetime.utcnow() - created).days
    except Exception:
        return None
