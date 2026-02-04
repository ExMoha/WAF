from flask import Flask, request, Response
import requests
import re
import gzip
import io
from datetime import datetime
import os

app = Flask(__name__)
BACKEND_URL = "http://192.168.8.139"


BLOCK_PATTERNS = [
    r"<script\b:8",
    r"union\s+select:10",
    r"\.?\./:6",
    r"(;|&&|\|\|):3",
    r"(['\"]?\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1):8",
    r"onerror=:8",
    r"%2e%2e%2f:6"
]

PATTERN_SCORES = {}

def parse_pattern_score(pattern_line):
    pattern_line = pattern_line.strip()
    if ':' in pattern_line:
        parts = pattern_line.split(':', 1)
        pattern = parts[0].strip()
        try:
            score = int(parts[1].strip())
            return pattern, score
        except (ValueError, IndexError):
            return pattern, 5
    else:
        return pattern_line, 5

for pattern_line in BLOCK_PATTERNS:
    pattern, score = parse_pattern_score(pattern_line)
    PATTERN_SCORES[pattern] = score


def load_block_patterns_from_file(filename="rules.txt"):
    patterns = {}
    filepath = os.path.join(os.path.dirname(__file__), filename)
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    pattern, score = parse_pattern_score(line)
                    patterns[pattern] = score

    except FileNotFoundError:
        print(f"rules.txt not found")
    except Exception as e:
        print(f"Error: {str(e)}")
    
    return patterns


file_patterns = load_block_patterns_from_file("rules.txt")
PATTERN_SCORES.update(file_patterns)

ALL_PATTERNS = list(PATTERN_SCORES.keys())

def calculate_threat_score(payload):
    total_score = 0
    matched_patterns = []
    
    for pattern in ALL_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            score = PATTERN_SCORES.get(pattern, 5) 
            total_score += score
            matched_patterns.append((pattern, score))
    
    return total_score, matched_patterns


BLOCK_THRESHOLD = 6


@app.route('/', defaults={'path': ''}, methods=["GET", "POST"])
@app.route('/<path:path>', methods=["GET", "POST"])

def proxy(path):
    data = request.get_data(as_text=True)

    data_score, _ = calculate_threat_score(data)
    args_score = [calculate_threat_score(arg_value)[0] for arg_value in request.args.values()]
    form_scores = [calculate_threat_score(str(form_value))[0] for form_value in request.form.values()] if request.form else []
    total_score = min(10, data_score + sum(args_score) + sum(form_scores))

    if total_score >= BLOCK_THRESHOLD:
        with open('waf.log', 'a') as f:
            f.write(f"{datetime.now().isoformat()} | BLOCKED | IP: {request.remote_addr} | Method: {request.method} | Path: {path} | Score: {total_score}\n")
        return Response("Request blocked by WAF", status=403)
    
    target = f"{BACKEND_URL}/{path}"
    resp = requests.request(
        method=request.method,
        url=target,
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=data,
        allow_redirects=False
    )

    excluded_headers = ['content-encoding', 'transfer-encoding', 'content-length', 'connection']
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]

    content = resp.content

    if resp.headers.get('Content-Encoding') == 'gzip':
        try:
            buf = io.BytesIO(resp.content)
            content = gzip.GzipFile(fileobj=buf).read()
        except Exception as e:
            print(f"Error: couldn't decompress gzip: {e}")

    response = Response(content, resp.status_code, headers)
    return response
    

if __name__ == "__main__":
    app.run(port=8080)

