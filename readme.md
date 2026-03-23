# 🕵️‍♂️ Scam Detector CLI
### *Advanced OSINT & Phishing Intelligence Tool for Cyber Security Research*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OSINT](https://img.shields.io/badge/Focus-OSINT%20%26%20Pentest-red.svg)](#)
[![Contribution Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](https://github.com/sendaljpt/scam-detector/issues)

**Scam Detector CLI** adalah instrumen investigasi berbasis terminal yang dirancang untuk melakukan analisa mendalam terhadap indikator kecurangan (*Scam/Phishing*) pada sebuah domain secara real-time. Tool ini sangat berguna bagi analis SOC, peneliti malware, maupun content creator di bidang cyber security.

> **⚠️ Disclaimer:** Tool ini dibuat khusus untuk tujuan edukasi *cyber security* dan *penetration testing*. Segala bentuk penyalahgunaan adalah tanggung jawab pengguna sepenuhnya.

---

## ✨ Key Modules & Capabilities

Tool ini menggabungkan berbagai teknik **OSINT** dan **Network Analysis** untuk memberikan klasifikasi risiko yang akurat:

### 🌐 Domain & DNS Intelligence
* **WHOIS Insight:** Cek umur domain & tanggal kadaluarsa (indikator utama web scam baru).
* **DNS Recon:** Resolusi IP, *Nameserver check*, dan validasi *MX Records*.
* **Typosquatting Engine:** Mendeteksi domain yang meniru brand ternama.
* **Fake Gov Detection:** Verifikasi otomatis terhadap domain instansi pemerintah (misal: `go.id`).

### 🔒 SSL & Security Audit
* **SSL/TLS Validator:** Analisa validitas sertifikat dan informasi *Issuer*.
* **Redirect Tracker:** Melacak rantai pengalihan URL yang mencurigakan.
* **Port Scanner:** Memeriksa port terbuka yang tidak biasa pada web server.

### 📊 Advanced Analysis
* **Keyword Heuristics:** Mendeteksi *brand abuse* dan kata kunci mencurigakan di URL.
* **URL Obfuscation:** Membongkar teknik penyembunyian link asli.
* **Risk Scoring System:** Kalkulasi skor risiko otomatis (Low, Medium, High).
* **UI/UX:** Output tabel yang rapi (Tabulate) dengan indikator warna dan progress bar (`tqdm`).

---

## 🚀 Installation & Setup

Pastikan kamu sudah menginstal Python 3.8+ di lingkungan Linux atau Kali Linux kamu.

### 1. Clone & Environment
```bash
# Clone repository
git clone [https://github.com/sendaljpt/scam-detector.git](https://github.com/sendaljpt/scam-detector.git)
cd scam-detector

# Setup Virtual Environment (Recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```