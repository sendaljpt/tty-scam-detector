import re
import whois
import tldextract
import socket
import requests
import ssl
import dns.resolver
import urllib.parse
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from colorama import Fore, Style, init
from urllib.parse import urljoin
from tqdm import tqdm


init(autoreset=True)

def banner():
    print(Fore.CYAN + r"""
  ___  ___   _   __  __   ___  ___ _____ ___ ___ _____ ___  ___ 
 / __|/ __| /_\ |  \/  | |   \| __|_   _| __/ __|_   _/ _ \| _ \
 \__ \ (__ / _ \| |\/| | | |) | _|  | | | _| (__  | || (_) |   /
 |___/\___/_/ \_\_|  |_| |___/|___| |_| |___\___| |_| \___/|_|_\
                         by TypingTypo 🔍
    """)


class ScamDetector:
    def __init__(self, url):
        self.original_url = url
        self.url = self.normalize_url(url)
        self.domain = self.extract_domain(self.url)
        self.total_score = 0
        self.findings = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
        }

        # load data
        self.keywords = self.load_list("suspicious_keywords.txt")
        self.gov_keywords = self.load_list("gov_keywords.txt")
        self.whois_data = self.get_whois()

    def log(self, message, score=0):
        if "[!!!]" in message or "[!]" in message:
            tqdm.write(Fore.RED + "❌ " + message)
        elif "[+]" in message:
            tqdm.write(Fore.GREEN + "✅ " + message)
        else:
            tqdm.write(Fore.YELLOW + "⚠️ " + message)

        self.total_score += score
        self.findings.append((message, score))

    # ======================
    # BASIC UTIL
    # ======================
    def get_response(self):
        if hasattr(self, "_response"):
            return self._response

        try:
            self._response = requests.get(self.url, headers=self.headers, timeout=5, allow_redirects=True)
            return self._response
        except:
            self._response = None
            return None
        
    def get_whois(self):
        try:
            return whois.whois(self.domain)
        except:
            return None
        
    def load_list(self, filepath):
        try:
            with open(filepath, "r") as f:
                return [line.strip().lower() for line in f if line.strip()]
        except:
            return []

    def normalize_url(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        return url

    def extract_domain(self, url):
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    def is_ip_address(self):
        parsed = urlparse(self.url)
        return re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc)

    # ======================
    # CHECK FUNCTIONS
    # ======================

    def check_domain_age(self):
        try:
            w = self.whois_data
            if not w:
                self.log("[!] Whois tidak tersedia")
                return
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                self.log("[!] Tidak bisa mendapatkan tanggal domain", 1)
                return

            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days

            if age_days < 30:
                self.log(f"[!] Domain baru ({age_days} hari)", 2)
            else:
                self.log(f"[+] Domain lama ({age_days} hari)")

        except:
            self.log("[!] Whois tidak tersedia")
    
    def check_expiration(self):
        try:
            w = self.whois_data
            if not w:
                self.log("[!] Whois tidak tersedia")
                return
            
            expire_date = w.expiration_date

            if isinstance(expire_date, list):
                expire_date = expire_date[0]

            if expire_date:
                days_left = (expire_date - datetime.now(expire_date.tzinfo)).days

                if days_left < 30:
                    self.log(f"[!] Domain akan expired ({days_left} hari)", 2)
                else:
                    self.log(f"[+] Domain Expired dalam {days_left} hari")
            else:
                self.log("[!] Tidak ada info expired", 1)

        except:
            self.log("[!] Gagal cek expired")

    def check_url_pattern(self):
        score = 0

        if len(self.url) > 75:
            score += 1

        if "@" in self.url:
            score += 2

        if re.search(r"\d{4,}", self.url):
            score += 1

        if score >= 2:
            self.log("[!] Pola URL mencurigakan", score)
        else:
            self.log("[+] Pola URL normal")
        
    def check_suspicious_keywords(self):
        for key in self.keywords:
            if key in self.domain:
                self.log(f"[!] Mengandung brand sensitif: {key}", 2)
                return

        self.log("[+] Tidak ada keyword sensitif")

    def check_fake_tld(self):
        for gov in self.gov_keywords:
            if gov in self.domain:
                if self.domain.endswith("go.id"):
                    self.log(f"[+] Domain pemerintah valid ({gov})")
                else:
                    self.log(f"[!] Kemungkinan domain palsu pemerintah ({gov})", 3)
                return

        self.log("[+] Bukan domain pemerintah")

    def check_dns(self):
        try:
            socket.gethostbyname(self.domain)
            self.log("[+] Domain resolve")
        except:
            self.log("[!] DNS gagal resolve", 1)

    def check_https(self):
        try:
            r = self.get_response()
            if not r:
                self.log("[!] Gagal request")
                return

            if r.url.startswith("https"):
                self.log("[+] HTTPS aktif")
            else:
                self.log("[!] Tidak menggunakan HTTPS", 1)

        except:
            self.log("[!] HTTPS check gagal")

    def check_ssl(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(3)
                s.connect((self.domain, 443))
                cert = s.getpeercert()

            expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

            if expire_date < datetime.utcnow():
                self.log("[!] SSL expired", 2)
            else:
                self.log("[+] SSL valid")

        except:
            self.log("[!] SSL tidak tersedia", 1)

    def check_ssl_issuer(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(3)
                s.connect((self.domain, 443))
                cert = s.getpeercert()

            issuer = dict(x[0] for x in cert['issuer'])
            self.log(f"[+] SSL Issuer: {issuer.get('organizationName', 'Unknown')}")

        except:
            self.log("[!] Gagal cek SSL issuer")

    def check_redirect(self):
        try:
            r = self.get_response()
            if not r:
                self.log("[!] Gagal request")
                return

            if len(r.history) > 2:
                self.log("[!] Terlalu banyak redirect", 2)
            elif len(r.history) > 0:
                self.log("[!] Ada redirect", 1)
            else:
                self.log("[+] Tidak ada redirect")

        except:
            self.log("[!] Gagal cek redirect")

    def check_subdomain(self):
        ext = tldextract.extract(self.url)
        subdomain = ext.subdomain

        if subdomain.count(".") >= 2:
            self.log("[!] Subdomain terlalu banyak", 2)
        elif subdomain:
            self.log("[!] Menggunakan subdomain", 1)
        else:
            self.log("[+] Tidak ada subdomain")
    

    def check_mx_record(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            if answers:
                self.log("[+] Memiliki MX record (email server)")
            else:
                self.log("[!] Tidak memiliki MX record", 1)
        except:
            self.log("[!] MX record tidak ditemukan", 1)

    
    def check_ip_info(self):
        try:
            ip = socket.gethostbyname(self.domain)
            self.log(f"[+] IP Address: {ip}")
        except:
            self.log("[!] Tidak bisa mendapatkan IP", 1)

    def check_external_links(self):
        try:
            r = self.get_response()
            if not r:
                self.log("[!] Gagal request")
                return
            
            content = r.text

            external_count = content.count("http")
            
            if external_count > 20:
                self.log("[!] Banyak external link", 1)
            else:
                self.log("[+] External link normal")

        except:
            self.log("[!] Tidak bisa cek external link")

    def check_port(self):
        parsed = urlparse(self.url)

        if parsed.port and parsed.port not in [80, 443]:
            self.log(f"[!] Menggunakan port tidak umum: {parsed.port}", 2)
        else:
            self.log("[+] Port normal")
    

    def check_url_encoding(self):
        decoded = urllib.parse.unquote(self.url)

        if decoded != self.url:
            self.log("[!] URL menggunakan encoding (obfuscation)", 2)
        else:
            self.log("[+] URL tidak di-encode")

    def check_nameserver(self):
        try:
            w = self.whois_data
            if not w:
                self.log("[!] Whois tidak tersedia")
                return
            ns = w.name_servers

            if ns:
                self.log(f"[+] Nameserver ditemukan ({len(ns)})")
            else:
                self.log("[!] Tidak ada nameserver", 1)

        except:
            self.log("[!] Gagal cek nameserver")

    def check_typosquatting(self):
        suspicious_patterns = ["0", "1", "-", "co-", "id-"]

        for p in suspicious_patterns:
            if p in self.domain:
                self.log("[!] Kemungkinan typosquatting / domain tiruan", 2)
                return

        self.log("[+] Tidak terdeteksi typosquatting")

    # ======================
    # MAIN SCAN
    # ======================
    def print_summary(self):
        risk = "LOW"
        color = Fore.GREEN

        if self.total_score >= 7:
            risk = "HIGH"
            color = Fore.RED
        elif self.total_score >= 4:
            risk = "MEDIUM"
            color = Fore.YELLOW

        print(Fore.CYAN + "\n=== SUMMARY ===")
        print(f"Target     : {self.domain}")
        print(f"Score      : {self.total_score}")
        print(f"Risk Level : {color}{risk}")
    
    def print_table(self):
        print(Fore.CYAN + "\n=== DETAIL SCORE (TABLE) ===")

        # Header
        print(f"{'No':<4} {'Finding':<55} {'Score':<5}")
        print("-" * 70)

        # Rows
        for i, (msg, score) in enumerate(self.findings, 1):
            short_msg = msg.replace("[+]", "").replace("[!]", "").strip()

            if score > 0:
                color = Fore.RED
            else:
                color = Fore.GREEN

            print(color + f"{i:<4} {short_msg:<55} {score:<5}")

        print("-" * 70)
        print(f"{'TOTAL':<60} {self.total_score}")

    def run_scan(self):
        print(f"\nScanning: {self.original_url}")

        if self.is_ip_address():
            self.log("[!] Menggunakan IP Address", 3)

        
        checks = [
            self.check_domain_age,
            self.check_expiration,
            self.check_url_pattern,
            self.check_suspicious_keywords,
            self.check_fake_tld,
            self.check_dns,
            self.check_https,
            self.check_ssl,
            self.check_ssl_issuer,
            self.check_redirect,
            self.check_subdomain,
            self.check_mx_record,
            self.check_ip_info,
            self.check_external_links,
            self.check_port,
            self.check_url_encoding,
            self.check_nameserver,
            self.check_typosquatting
        ]

        for check in tqdm(checks, desc="Scanning", ncols=70, leave=True):
            check()

        self.print_summary()

        self.print_table()