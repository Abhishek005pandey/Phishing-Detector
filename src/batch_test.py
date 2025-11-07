import json
from main import analyze

with open('tests/test_urls.txt') as f:
    urls = [line.strip() for line in f if line.strip()]

results = []
for url in urls:
    print(f"\n--- Analyzing: {url} ---")
    res = analyze(url)
    print(json.dumps(res, indent=2))
    results.append(res)

with open('tests/results.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\n✅ All results saved to tests/results.json")
