#!/usr/bin/env python3
"""
Interactive CLI for Phishing Detector.

Run:
  python src/main.py

Then paste a URL at the prompt and press Enter.
Type 'exit' or 'quit' or Ctrl+C to stop.
You can also start with a URL argument:
  python src/main.py "http://example.com"
Or pass a file of URLs (one per line):
  python src/main.py --file urls.txt
"""

import sys
import json
import argparse
from datetime import datetime, timezone

# import your analyzer components (these are your local modules in src/)
from parser import parse_url
from heuristics import score_tokens
from whois_helper import get_domain_age_days
from active_checks import check_redirects

# thresholds (tune as desired)
PHISHING_THRESHOLD = 20
SUSPICIOUS_THRESHOLD = 5

def analyze(url: str) -> dict:
    """Return a full analysis dict for the URL (heuristics + whois + active)."""
    feats = parse_url(url)
    score, reasons = score_tokens(feats)

    # WHOIS age check (best-effort)
    try:
        age = get_domain_age_days(feats.get('domain', ''))
    except Exception:
        age = None
    if age is not None and isinstance(age, int) and age < 90:
        score += 12
        reasons.append('young_domain')

    # Active checks (network; allow failures to be handled gracefully)
    try:
        act = check_redirects(feats.get('original_url', url))
        if not isinstance(act, dict):
            act = {'error': 'active_check_no_data'}
    except Exception as e:
        act = {'error': str(e)}

    if act.get('error'):
        # Treat unreachable domains as strongly suspicious
        score += 20
        reasons.append('unreachable_domain')
    else:
        if len(act.get('redirect_chain', [])) > 3:
            score += 5
            reasons.append('many_redirects')
        if act.get('contains_form'):
            score += 5
            reasons.append('contains_form')
        final = act.get('final_url', '')
        if feats.get('domain') and feats['domain'].lower() not in final.lower():
            score += 8
            reasons.append('final_domain_differs')

    if score >= PHISHING_THRESHOLD:
        label = 'phishing'
    elif score >= SUSPICIOUS_THRESHOLD:
        label = 'suspicious'
    else:
        label = 'benign'

    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'url': feats.get('original_url', url),
        'score': score,
        'label': label,
        'reasons': reasons,
        'features': feats,
        'whois_age_days': age,
        'active': act
    }


def pretty_print(result: dict):
    """Compact human-friendly print in the terminal."""
    print("\n=== Analysis Result ===")
    print("URL:      ", result.get('url'))
    print("Label:    ", result.get('label').upper(), f"(score={result.get('score')})")
    reasons = result.get('reasons') or []
    print("Reasons:  ", ", ".join(reasons) if reasons else "none")
    whois_age = result.get('whois_age_days')
    print("Domain age (days):", whois_age if whois_age is not None else "n/a")
    act = result.get('active') or {}
    final = act.get('final_url')
    if final:
        print("Final URL after redirects:", final)
    status = act.get('status_code')
    if status:
        print("HTTP status:", status)
    # show error message if present
    if act.get('error'):
        print("Active check error:", act.get('error'))
    print("========================\n")


def repl():
    print("Interactive Phishing Detector CLI")
    print("Paste a URL and press Enter. Type 'exit' or 'quit' to stop.")
    try:
        while True:
            url = input("URL> ").strip()
            if not url:
                continue
            if url.lower() in ('exit', 'quit'):
                print("Bye.")
                break
            try:
                res = analyze(url)
                pretty_print(res)
            except KeyboardInterrupt:
                print("\nInterrupted by user. Exiting.")
                break
            except Exception as e:
                print("Error analyzing URL:", str(e))
    except (EOFError, KeyboardInterrupt):
        print("\nGoodbye.")


def process_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                print(f"\nProcessing: {line}")
                try:
                    res = analyze(line)
                    pretty_print(res)
                except Exception as e:
                    print("Error for", line, ":", e)
    except FileNotFoundError:
        print("File not found:", path)


def main():
    parser = argparse.ArgumentParser(description="Interactive phishing URL analyzer")
    parser.add_argument('url', nargs='?', help='Optional URL to analyze once and exit')
    parser.add_argument('--file', '-f', help='Path to a file with URLs (one per line) to process and exit')
    args = parser.parse_args()

    # If user supplied a URL as argument -> analyze once and exit
    if args.url:
        res = analyze(args.url)
        print(json.dumps(res, default=str, indent=2))
        return

    # If user supplied a file -> process each line then exit
    if args.file:
        process_file(args.file)
        return

    # Otherwise go interactive REPL
    repl()


if __name__ == '__main__':
    main()

