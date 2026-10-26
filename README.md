# PhishGuard — Computer Networks Project

PhishGuard is a local academic prototype for phishing-risk URL analysis. It combines transparent URL heuristics, DNS resolution, optional Google Safe Browsing threat-intelligence lookup, and a dashboard.

> **Important:** This is a risk estimator, not a guarantee of safety. It never opens the submitted website. DNS resolution is not proof of legitimacy. A low score does not mean a URL is safe.

## 1. Requirements

- Python 3.10 or newer
- pip
- Internet connectivity for DNS checks and optional reputation lookup
- Optional: a valid Google Safe Browsing API key, subject to current Google terms and eligibility

## 2. Run locally

### macOS / Linux

```bash
cd PhishGuard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

### Windows PowerShell

```powershell
cd PhishGuard
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## 3. Optional threat-intelligence lookup

The application works without an API key. To enable the Google Safe Browsing lookup, first check Google's current API documentation, usage terms, eligibility and privacy implications. When enabled, the submitted URL is sent to the provider.

macOS / Linux:
```bash
export GOOGLE_SAFE_BROWSING_API_KEY="your-key-here"
python app.py
```

PowerShell:
```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="your-key-here"
python app.py
```

Do not commit API keys to Git. A provider timeout or error is shown as unavailable, not as safe.

## 4. What is implemented?

- URL parsing and basic validation; only HTTP and HTTPS schemes accepted.
- Transparent heuristic scoring from URL/hostname features.
- DNS resolution with a short timeout and A/AAAA-capable system resolver behavior.
- Optional Google Safe Browsing threat-intelligence check.
- Score from 0–100, risk band, evidence list, DNS status, component timing and recent in-memory history.
- Responsive dashboard and `/api/scan`, `/api/history`, `/api/health` endpoints.

The first version intentionally does not include an ML model. The optional threat-intelligence check makes it a hybrid rules + reputation design when configured. If no API key is set, it runs in rules-only fallback mode and labels the missing signal clearly.

## 5. Suggested demonstration

Use benign examples and URLs from an approved, labelled dataset. Do not visit suspected phishing URLs. You can test input validation with a malformed value and observe DNS errors using a reserved/nonexistent test domain chosen by your instructor. A URL with an IP literal is a useful feature-extraction demonstration, but it is not automatically malicious.

## 6. Computer Networks syllabus mapping

| Module | Visible syllabus topics | PhishGuard connection |
|---|---|---|
| 1 — Networking Principles and Layered Architecture | Communications model, protocols, OSI, TCP/IP | Browser ↔ Flask request/response; explain application, transport and network roles |
| 2 — Circuit and Packet Switching | Packet switching, network software, performance | End-to-end scan latency, timeouts and network-dependent delays |
| 3 — Data Link Layer | Ethernet, WLAN, error detection and access protocols | Context only; not directly implemented by this application |
| 4 — Network Layer | IPv4/IPv6, addressing, NAT | IP-literal detection and hostname address resolution |
| 5 — Routing Protocols | Link-state, distance-vector, performance, Packet Tracer | Routing is supporting context for reachability and latency; no routing protocol is implemented |
| 6 — Transport Layer | TCP/UDP, congestion, QoS | Network timeouts and HTTP/API transport behavior; DNS commonly uses UDP and may use TCP |
| 7 — Application Layer | DNS, HTTP, FTP, SMTP, SNMP | Core mapping: URL parsing, DNS resolution, HTTP interface and optional HTTPS threat-intelligence API; SMTP is phishing-delivery context |

## 7. How risk scoring works

Starter weights are in `detector/rule_engine.py`. They are illustrative and not scientifically calibrated. The score is capped at 100. A positive reputation match forces a high-risk warning. HTTPS adds no trust points because phishing sites can use HTTPS. DNS errors do not automatically increase risk because legitimate domains can fail to resolve due to transient or local resolver issues.

Before reporting effectiveness, evaluate on a labelled dataset and compute precision, recall, F1-score, false-positive rate, and latency. Do not claim accuracy without test evidence.

## 8. Limitations and safety

- Lexical rules can produce false positives and miss sophisticated phishing.
- DNS records alone cannot prove a site is safe or malicious.
- Reputation coverage can be incomplete, and provider access can be rate-limited or unavailable.
- This prototype performs DNS lookups but does not fetch the submitted website. If future versions fetch URLs, they require strict SSRF defenses, redirect controls, and outbound network restrictions.
- Scan history is in memory and disappears when the server restarts.
- The development server is intended for local demonstrations, not production deployment.

## 9. References

- RFC 1034 — Domain Names: Concepts and Facilities: https://www.rfc-editor.org/rfc/rfc1034
- Python URL parsing: https://docs.python.org/3/library/urllib.parse.html
- Flask documentation: https://flask.palletsprojects.com/
- Google Safe Browsing documentation: https://developers.google.com/safe-browsing
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
