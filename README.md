# Web Application Firewall (WAF)

A lightweight, rule-based WAF built with Python that inspects HTTP traffic, detects malicious patterns, and provides real-time monitoring through an interactive dashboard.

![WAF Dashboard](https://img.shields.io/badge/Security-WAF-red) ![Python](https://img.shields.io/badge/Python-3.8+-blue) ![Flask](https://img.shields.io/badge/Flask-2.0+-green)

## Features

- **Pattern-Based Detection**: 30+ rules covering OWASP Top 10 vulnerabilities
- **Threat Scoring System**: Cumulative scoring (0-10) with severity classification (Medium, High, Critical)
- **Dashboard**: web interface displaying blocked requests
- **Comprehensive Logging**: Detailed logs with timestamp, IP, method, path, and threat score
- **Customizable Rules**: Easy-to-modify rule file for adding new attack patterns
- **JSON Export**: Export blocked requests data for further analysis

## Project Structure

```
waf-dashboard/
├── waf.py              # Main WAF application with proxy logic
├── rules.txt           # Attack pattern rules with severity scores
├── waf.log             # Log file for blocked requests
├── index.html          # Dashboard HTML structure
├── styles.css          # Dashboard styling
├── script.js           # Dashboard JavaScript logic
└── README.md           # Project documentation
```

**Severity Levels:**

- **Medium**: Score 6-7
- **High**: Score 8-9
- **Critical**: Score 10+

## Dashboard Features

The web dashboard displays:

- **Request ID**: Unique identifier for each blocked request
- **Timestamp**: When the request was blocked
- **Source IP**: Origin of the malicious request
- **HTTP Method**: GET, POST, etc.
- **Path**: Targeted endpoint
- **Threat Score**: Cumulative severity score
- **Severity**: Classification (Medium/High/Critical)
- **Export**: Download blocked requests as JSON

## How It Works

1. **Request Interception**: All HTTP traffic passes through the WAF proxy
2. **Pattern Matching**: Request components (path, query params, body) are checked against regex rules
3. **Threat Scoring**: Matches accumulate scores based on pattern severity
4. **Decision Making**: If total score >= threshold, request is blocked
5. **Logging**: Blocked requests are logged with full details
6. **Visualization**: Dashboard reads logs and displays blocked attempts in real-time

## Log Format

Blocked requests are logged in the following format:

```
YYYY-MM-DDTHH:MM:SS.microseconds | BLOCKED | IP: x.x.x.x | Method: GET/POST | Path: /path | Score: X
```

**Example:**

```
2025-11-02T08:16:08.277649 | BLOCKED | IP: 192.168.1.100 | Method: GET | Path: login.php?user=admin' OR '1'='1 | Score: 10
```

## Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript
