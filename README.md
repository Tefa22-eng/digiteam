# README.md

<div align="center">

# 🔍 DIGI TEAM

### Elite Reconnaissance Framework

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-2.0.0-purple.svg)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen.svg)

*A professional-grade, modular reconnaissance toolkit for bug bounty hunters and penetration testers.*

---

</div>

## ⚡ Features

### 🔍 Passive Reconnaissance
| Module | Description |
|--------|-------------|
| WHOIS Lookup | Domain registration & registrar details |
| DNS Enumeration | Comprehensive DNS record discovery (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, DMARC) |
| Subdomain Enumeration | Multi-source subdomain discovery (subfinder, crt.sh, HackerTarget, ThreatCrowd, BufferOver) |
| Certificate Transparency | SSL certificate analysis & CT log querying |
| Shodan Intelligence | Host & service intelligence via Shodan API |
| Censys Intelligence | Certificate & host data via Censys API |
| VirusTotal | Domain reputation & intelligence |
| Wayback URLs | Historical URL discovery (waybackurls, gau, CDX API) |
| ASN Intelligence | IP intelligence, geolocation & ASN data |

### ⚔️ Active Reconnaissance
| Module | Description |
|--------|-------------|
| Live Host Detection | HTTP probing via httpx with technology detection |
| Port Scanning | Open port discovery via naabu/nmap with service detection |
| Directory Fuzzing | Hidden directory & file discovery via ffuf |
| HTTP Headers Analysis | Security header audit with vulnerability flagging |
| Technology Detection | CMS, framework & server technology fingerprinting |
| Screenshot Capture | Visual reconnaissance via gowitness |

### 🛡️ Security Analysis
- Missing security headers detection
- SPF/DMARC/DNSSEC validation
- Cookie security audit
- Information disclosure detection
- Zone transfer testing
- CVE correlation (via Shodan)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/digiteam.git
cd digiteam

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install external tools for full capability
# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/sensepost/gowitness@latest

# System tools
sudo apt install nmap  # Debian/Ubuntu
```

