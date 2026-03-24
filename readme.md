# Scam Detector CLI
### *Terminal-based OSINT & phishing intelligence tool for cybersecurity research*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OSINT](https://img.shields.io/badge/Focus-OSINT%20%26%20Pentest-red.svg)](#)
[![Contribution Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](https://github.com/sendaljpt/scam-detector/issues)

**Scam Detector CLI** is a terminal-based investigation tool to quickly analyze scam/phishing indicators for a URL/domain. It’s useful for SOC analysts, malware researchers, and cybersecurity practitioners/creators who need an initial triage before deeper investigation.

> **⚠️ Disclaimer:** This tool is intended for education and security research. Do not use it for illegal activity. Any misuse is entirely the user’s responsibility.

---

## ✨ Key Features

This tool combines **OSINT** and **network analysis** techniques to produce a risk score (Low/Medium/High) along with detailed findings.

### 🌐 Domain & DNS Intelligence
* **WHOIS Insight:** Check domain age & expiration date (a common indicator of newly created scam sites).
* **DNS Recon:** IP resolution, nameserver checks, and MX record validation.
* **Typosquatting Engine:** Detects brand-impersonating domains.
* **Fake Gov Detection:** Automatic validation for government domains (e.g., `go.id`).

### 🔒 SSL & Security Audit
* **SSL/TLS Validator:** Analyze certificate validity and issuer information.
* **Redirect Tracker:** Track suspicious redirect chains.
* **Port Scanner:** Check for unusual open ports on the web server.

### 📊 Advanced Analysis
* **Keyword Heuristics:** Detect brand abuse and suspicious keywords in the URL.
* **URL Obfuscation:** Unpack common URL hiding techniques.
* **Risk Scoring System:** Automatic risk scoring (Low, Medium, High).
* **UI/UX:** Clean output with colored indicators and a progress bar (`tqdm`).

---

## 🚀 Installation

Make sure you have **Python 3.8+** installed (Linux/Kali Linux recommended).

### 1) Clone the repo & create a virtualenv
```bash
# Clone repository
git clone https://github.com/sendaljpt/scam-detector.git
cd scam-detector

# Setup Virtual Environment (Recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🧪 Usage

The tool is executed via `main.py` and takes **1 required argument**: `url`.

```bash
python3 main.py example.com
```

Examples:

```bash
python3 main.py https://example.com
python3 main.py http://bit.ly/some-shortlink
python3 main.py https://login-google-security.example
```

---

## 📁 Project Structure (brief)

- **`main.py`**
  - CLI entry point (takes `url`, then runs the scan).
- **`detector.py`**
  - `ScamDetector` implementation (WHOIS/DNS/SSL/redirect/heuristic scoring, and detailed output).
- **`suspicious_keywords.txt`**, **`gov_keywords.txt`**
  - Keyword lists for heuristics.

---

## 📝 Notes

- **Accuracy**
  - The score is heuristic/OSINT-based, not a definitive verdict. Use it as an initial triage.
- **Network dependency**
  - Some checks require internet access and may fail due to timeouts, rate limits, or blocking.
- **Run safely**
  - Avoid running this against suspicious links on your main machine (use a VM/sandbox if needed).

---

## 🤝 Contributing

Contributions are welcome.

- Open an issue for bugs/feature requests.
- Send a PR with a short explanation of what changed and why.

---

## 📄 License

This project is licensed under the **MIT** License. See the license badge above for reference.

---

## ❤️ Donate

If this project helps you, consider supporting the author.

<img src="assets/qris.jpg" alt="QRIS" width="220"/>