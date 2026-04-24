<div align="center">

<img src="./assets/banner.png" alt="Dark Devil Logo" width="200"/>

# ☠️ DARK DEVIL SCANNER ☠️
### Version 9.0.0 — Codename: PHANTOM STRIKE

*Where Systems Confess Their Sins.*
*Not just a tool. A weapon for the authorized.*

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Zero-FP](https://img.shields.io/badge/False_Positives-<5%25-red.svg)]()
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Web%20%26%20API%20Top%2010-purple.svg)]()

**Built by:** Dark-Devil  
**Contact:** mr.ghost010245@gmail.com  

</div>

---

## ⚠️ CAUTION & LEGAL DISCLAIMER

**FOR AUTHORIZED SECURITY TESTING ONLY.**  
This tool is designed explicitly for professional penetration testers, security researchers, and system administrators to identify and mitigate vulnerabilities within their own networks or networks they have explicit, written permission to test.

**ANY UNAUTHORIZED USE WILL RESULT IN IMMEDIATE AND SEVERE LEGAL ACTION.**  
The author (`Dark-Devil`) assumes no liability and is not responsible for any misuse or damage caused by this program. By running this scanner, you agree that you are fully responsible for your actions. **Hack the planet. Responsibly.**

---

## 📖 What is Dark Devil Scanner?

Dark Devil is an advanced, automated Web & API Security Framework designed to simulate real-world cyberattacks and uncover critical vulnerabilities before threat actors do. 

With **Version 9.0 (Phantom Strike)**, the engine has been completely overhauled to introduce a **Zero-FP (<5% False Positives) Architecture**. Unlike traditional scanners that rely on simple string matching, Dark Devil uses baseline comparisons, mathematical evaluations, and complex multi-gate logic to ensure that every finding is a mathematically and structurally confirmed vulnerability.

### Core Capabilities:
- **Comprehensive Coverage:** Scans for OWASP Web Top 10 (2021) and OWASP API Top 10 (2023).
- **MITRE ATT&CK Tagging:** Automatically maps findings to the MITRE ATT&CK framework (e.g., T1059, T1190).
- **CVSS v3.1 Scoring:** Fully automated dynamic severity scoring based on attack vectors.
- **100+ Internal Modules:** Custom-built detection engines for XSS, SQLi, SSRF, LFI, SSTI, XXE, Deserialization, HTTP Smuggling, JWT flaws, and more.
- **Arsenal Integration:** Wraps and orchestrates over 40+ industry-standard security tools in parallel.

---

## ⚙️ How It Works (The Workflow)

Dark Devil operates in a phased, stealthy, and highly parallelized methodology:

1. **Phase 1: Passive Fingerprinting & Reconnaissance**
   - Warms up the baseline cache for Zero-FP comparisons.
   - Detects WAFs, weak crypto, outdated components, and deeply fingerprints the tech stack.
   - Extracts historical secrets via Git leaks and WayBack URLs.
2. **Phase 2: Policy & Logic Evaluation**
   - Validates CORS, CSRF, Clickjacking, Cache Poisoning, and HTTP Smuggling vectors.
3. **Phase 3: Exposure & Disclosure**
   - Hunts for exposed sensitive files, cloud metadata (AWS, GCP, Azure), API versions, GraphQL endpoints, and WebSockets.
4. **Phase 4: Authentication & Session Attacks**
   - Tests for default credentials, session fixation, JWT confusion, SAML bypasses, and performs timing attacks.
5. **Phase 5: External Recon (Subdomains & Infrastructure)**
   - Orchestrates Subfinder, Amass, Sublist3r, DNSx, HTTPx, and Nmap for deep infrastructure mapping and subdomain takeover testing.
6. **Phase 6: Crawling & URL Discovery**
   - Deploys Katana, GoSpider, GAU, and ParamSpider to extract every possible endpoint, hidden API, and parameter.
7. **Phase 7: Web Server Scanners & Tool Arsenal**
   - Automatically runs Nuclei, Nikto, SSLScan, DalFox, SQLMap, FFUF, and other heavy artillery in the background.
8. **Phase 8: Active Injection & API Testing (The Killchain)**
   - Targets discovered endpoints with strict, Zero-FP injection modules (SQLi, XSS, SSRF, LFI, SSTI, XXE, Command Injection).
9. **Phase 9: AI Analysis (Optional)**
   - Connects to an AI Advisor to provide a PTES-compliant executive summary of the findings.

---

## 🛠️ Installation & Virtual Environment

To prevent dependency conflicts with your system packages, **it is highly recommended to run Dark Devil in an isolated Python Virtual Environment.**

### 1. Create and Activate the Virtual Environment
```bash
# Windows
python -m venv dd_env
dd_env\Scripts\activate

# Linux/macOS
python3 -m venv dd_env
source dd_env/bin/activate
```

### 2. Install Requirements
*Note: Dark Devil attempts to auto-install missing tools via apt, go, pip, and git, but you need the base Python packages first.*
```bash
pip install requests urllib3
# Run the scanner (it will bootstrap other dependencies)
python CODE.py
```

### 3. Usage
```bash
# Interactive UI
python CODE.py

# Direct CLI usage
python CODE.py -u https://target.com --threads 10 --html
```

---

## ⚔️ Integrated Arsenal & Credits

Dark Devil stands on the shoulders of giants. It automatically installs, configures, and orchestrates the following open-source tools. Full credit goes to their respective authors and communities:

### ProjectDiscovery Tools (Go)
- **[Nuclei](https://github.com/projectdiscovery/nuclei)** & **[Nuclei-Templates](https://github.com/projectdiscovery/nuclei-templates)**
- **[SubFinder](https://github.com/projectdiscovery/subfinder)**, **[HTTPX](https://github.com/projectdiscovery/httpx)**, **[DNSX](https://github.com/projectdiscovery/dnsx)**
- **[Naabu](https://github.com/projectdiscovery/naabu)**, **[Katana](https://github.com/projectdiscovery/katana)**, **[Interactsh](https://github.com/projectdiscovery/interactsh)**

### Recon & Discovery
- **[Amass](https://github.com/owasp-amass/amass)** (OWASP)
- **[Sublist3r](https://github.com/aboul3la/Sublist3r)** (aboul3la)
- **[Assetfinder](https://github.com/tomnomnom/assetfinder)**, **[WaybackURLs](https://github.com/tomnomnom/waybackurls)**, **[Unfurl](https://github.com/tomnomnom/unfurl)**, **[Anew](https://github.com/tomnomnom/anew)** (tomnomnom)
- **[GAU](https://github.com/lc/gau)**, **[SubJS](https://github.com/lc/subjs)** (lc)
- **[Hakrawler](https://github.com/hakluke/hakrawler)** (hakluke)
- **[GoSpider](https://github.com/jaeles-project/gospider)** (jaeles-project)
- **[theHarvester](https://github.com/laramies/theHarvester)** (laramies)
- **[DirSearch](https://github.com/maurosoria/dirsearch)** (maurosoria)
- **[FFUF](https://github.com/ffuf/ffuf)** (ffuf)
- **[GoBuster](https://github.com/OJ/gobuster)** (OJ)
- **[FeroxBuster](https://github.com/epi052/feroxbuster)** (epi052)
- **[ParamSpider](https://github.com/devanshbatham/ParamSpider)** (devanshbatham)
- **[Arjun](https://github.com/s0md3v/Arjun)** (s0md3v)

### Scanners & Exploitation
- **[SQLMap](https://github.com/sqlmapproject/sqlmap)** (sqlmapproject)
- **[DalFox](https://github.com/hahwul/dalfox)** (hahwul)
- **[XSStrike](https://github.com/s0md3v/XSStrike)**, **[Corsy](https://github.com/s0md3v/Corsy)**, **[Photon](https://github.com/s0md3v/Photon)** (s0md3v)
- **[TplMap](https://github.com/epinna/tplmap)** (epinna)
- **[SSTImap](https://github.com/vladko312/SSTImap)** (vladko312)
- **[SSRFmap](https://github.com/swisskyrepo/SSRFmap)**, **[GraphQLmap](https://github.com/swisskyrepo/GraphQLmap)** (swisskyrepo)
- **[NoSQLMap](https://github.com/codingo/NoSQLMap)** (codingo)
- **[JWT Tool](https://github.com/ticarpi/jwt_tool)** (ticarpi)
- **[Commix](https://github.com/commixproject/commix)** (commixproject)
- **[WPScan](https://github.com/wpscanteam/wpscan)** (wpscanteam)
- **[JoomScan](https://github.com/OWASP/joomscan)** (OWASP)
- **[CMSeek](https://github.com/Tuhinshubhra/CMSeek)** (Tuhinshubhra)
- **[Ghauri](https://github.com/r0oth3x49/ghauri)** (r0oth3x49)
- **[LFISuite](https://github.com/D35m0nd142/LFISuite)** (D35m0nd142)
- **[XSRFProbe](https://github.com/0xInfection/XSRFProbe)** (0xInfection)

### Security, Secrets, and Misconfigurations
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** (trufflesecurity)
- **[GitLeaks](https://github.com/gitleaks/gitleaks)** (gitleaks)
- **[Nikto](https://github.com/sullo/nikto)** (sullo)
- **[WAFW00F](https://github.com/EnableSecurity/wafw00f)** (EnableSecurity)
- **[SSLScan](https://github.com/rbsec/sslscan)** (rbsec)
- **[SSLyze](https://github.com/nabla-c0d3/sslyze)** (nabla-c0d3)
- **[Checkov](https://github.com/bridgecrewio/checkov)** (bridgecrewio)
- **[Cloud Enum](https://github.com/initstring/cloud_enum)** (initstring)
- **[S3Scanner](https://github.com/sa7mon/S3Scanner)** (sa7mon)

### Wordlists & Payloads
- **[SecLists](https://github.com/danielmiessler/SecLists)** (danielmiessler)
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** (swisskyrepo)
- **[FuzzDB](https://github.com/fuzzdb-project/fuzzdb)** (fuzzdb-project)

---

<div align="center">
<i>"Precision is power. A false positive is a wasted exploit."</i><br>
<b>— Dark Devil Framework</b>
</div>
#   W E B - B A S E D - S C A N N E R  
 