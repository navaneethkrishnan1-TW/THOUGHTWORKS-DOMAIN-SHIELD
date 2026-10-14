# 🛡️ Thoughtworks Domain Shield (GitHub Pages Edition)
> **Author:** `navaneethkrishnan1-TW`  
> **Deployment:** GitHub Pages (Client-Side Serverless Cyber Threat Intelligence Dashboard)  
> **Target:** Triage & investigate suspicious domains impersonating Thoughtworks with 1-click launch of all 13 SOC tools.

---

## 🚀 Live Demo & How to Deploy to GitHub Pages

To host this on your personal GitHub Pages URL (`https://navaneethkrishnan1-TW.github.io/thoughtworks-domain-shield/`):

### 1. Initialize & Push to your GitHub account:
Run the following commands in your terminal:

```bash
cd /Users/navaneeth/antigravity/thoughtworks-domain-shield

# Initialize Git
git init
git add .
git commit -m "feat: initial commit of Thoughtworks Domain Shield GitHub Pages app"

# Link to your GitHub repository (create an empty repo named 'thoughtworks-domain-shield' first on github.com)
git branch -M main
git remote add origin https://github.com/navaneethkrishnan1-TW/thoughtworks-domain-shield.git
git push -u origin main
```

### 2. Enable GitHub Pages:
1. Open your repository on GitHub: `https://github.com/navaneethkrishnan1-TW/thoughtworks-domain-shield`
2. Go to **Settings** → **Pages** (in the left sidebar).
3. Under **Branch**, select **`main`** and **`/ (root)`**, then click **Save**.
4. In ~60 seconds, your page will be live at:  
   👉 **`https://navaneethkrishnan1-TW.github.io/thoughtworks-domain-shield/`**

*(Alternatively, if you create a repo named `navaneethkrishnan1-TW.github.io`, it will be live directly at your root domain!)*

---

## ⚡ How It Works (100% Client-Side, Zero Backend Needed)

Traditional web tools require complex Python backends. This web application runs **100% inside the user's browser** using modern CORS-enabled public threat intelligence APIs:

1. **DNS-over-HTTPS (DoH)**: Queries Google Public DNS (`https://dns.google/resolve`) over HTTPS to fetch:
   - `A` records (IPv4 addresses)
   - `AAAA` records (IPv6 addresses)
   - `MX` records (mail exchangers)
   - `TXT` records (SPF validation)
   - `_dmarc.<domain>` records (DMARC policy status)
   - `NS` records (authoritative nameservers)
2. **ICANN RDAP Protocol**: Queries `https://rdap.org/domain/<domain>` over HTTPS with CORS to extract registrar identity, registration date, expiration, and exact domain age in days.
3. **BGP & ASN Intelligence**: Queries the **RIPE NCC** REST API (`https://stat.ripe.net/data/network-info/` & `as-overview/`) to map resolved IP addresses to their Autonomous System Number (ASN), AS Name, and BGP CIDR prefix.
4. **urlscan.io API (Search & Live Submissions)**:
   - **Search API (`/api/v1/search/`)**: Fetches historical DOM captures, landing page titles, server banners, malicious verdicts/scores, and live screenshots.
   - **Submission API (`/api/v1/scan/`)**: Allows 1-click submission of live scans directly from the browser using your `urlscan.io API Key`.
   - **API Key Persistence**: API keys are saved locally in browser `localStorage` (zero backend/server storage).
5. **Memory System (NT Storage)**: Persists previous domain investigations in browser `localStorage` (`TW_NT_INVESTIGATIONS_MEMORY`). Analysts can inspect past targets, re-load them with 1 click, or export the full memory dossier to JSON.
6. **One-Click Launchpad for All 13 Tools**: Pre-fills target domains and IPs and opens all 13 tools simultaneously in separate browser tabs!

---

## 🛠️ The 13 Tools Integrated (From Screenshot)

| # | Tool | Function in Web App |
|---|---|---|
| **01** | **ANYRun** | Launches interactive sandbox analysis session |
| **02** | **IP Void** | Deep-links to IP blacklist & reputation check with resolved IP |
| **03** | **Abuse IP DB** | Deep-links to AbuseIPDB IP reputation report |
| **04** | **URL Void** | Deep-links to URLVoid reputation & safety scan |
| **05** | **ICANN Lookup** | Deep-links to official ICANN registration search |
| **06** | **URL Scan.io** | Deep-links to urlscan.io domain search + API query |
| **07** | **IP Quality** | Deep-links to IPQualityScore fraud and proxy checker |
| **08** | **Browser.lol** | Launches disposable isolated cloud browser |
| **09** | **Email Scanner Sensei** | Deep-links to MXToolbox / Sensei email health checker |
| **10** | **EasyDMARC** | Deep-links to EasyDMARC anti-spoofing policy analyzer |
| **11** | **WHOis** | Deep-links to Who.is registration & nameserver dossier |
| **12** | **cymru** | Direct link to Team Cymru IP-to-ASN mapping services |
| **13** | **CyberChef** | Pre-loaded CyberChef recipe with URL defanging |
| *+* | *VirusTotal, Shodan, Crt.sh* | Supplementary multi-engine scans and SSL logs |

---

## 📋 Features & Workflow

- **Auto-Defanging & Normalization**: Strips `http(s)://`, `hxxp(s)://`, trailing paths, and converts `[.]` to standard dots for analysis, while displaying the defanged version safely.
- **Thoughtworks Heuristic Gauge**: Visual gauge (0-100) combining brand inclusion, homoglyph typosquatting, keywords (`careers`, `jobs`, `login`, `hr`, `offer`, etc.), disposable TLDs (`.xyz`, `.online`, etc.), and domain age.
- **Automated Takedown Generator**: Generates formal abuse complaints ready to send to registrars and hosting providers, with 1-click clipboard copy.
- **Export Options**: Download complete Markdown reports (`.md`) or raw JSON dossiers (`.json`).
