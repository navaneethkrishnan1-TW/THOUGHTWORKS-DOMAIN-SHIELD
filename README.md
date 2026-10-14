# 🛡️ Thoughtworks Domain Shield (Dual-Engine Edition)
> **Author:** `navaneethkrishnan1-TW`  
> **Deployment:** GitHub Pages (Client-Side Serverless Cyber Threat Intelligence Dashboard)  
> **Engines:** Dedicated VirusTotal v3 REST API & urlscan.io Visual DOM Sandbox  
> **Target:** Triage & investigate suspicious domains impersonating Thoughtworks with live visual landing page captures and multi-engine threat scores.

---

## 🌐 Live Application
The tool is hosted live on GitHub Pages:  
👉 **`https://navaneethkrishnan1-tw.github.io/THOUGHTWORKS-DOMAIN-SHIELD/`**

---

## ⚡ Architecture: Dedicated Dual Threat Intelligence Engines

The application has been refactored to focus exclusively on two top-tier threat intelligence engines:

### 1. 🦠 VirusTotal Threat Intelligence Engine (v3 API)
- **Multi-Engine Detection Ratio**: Aggregates verdicts from 70+ AV and threat intelligence scanners (Google Safe Browsing, Kaspersky, Sophos, Fortinet, BitDefender, ESET, etc.).
- **Detection Meter Bar**: Color-coded breakdown of Malicious (Red), Suspicious (Yellow), Harmless (Green), and Undetected engines.
- **Reputation & Community Score**: Captures threat community feedback and score metrics.
- **Threat Categories & Tags**: Identifies malware families, phishing tags, and malicious campaigns.
- **Security Vendor Breakdown**: Lists all individual engines that flagged the domain along with their detection verdict.
- **Direct Link**: 1-click access to the full VirusTotal GUI dossier.

### 2. 🔍 urlscan.io Sandbox & Visual Landing Page Engine
- **📸 Visual Landing Page Screenshot**: Prominent high-resolution preview of the target domain's live website.
- **DOM Title & Content Inspection**: Extracts page `<title>` to detect fake "Thoughtworks Careers", "Candidate Portals", or "Employee Login" scams.
- **Effective Destination URL**: Follows HTTP redirect chains to identify the final landing destination.
- **Network & Host Telemetry**: Resolves host IP, Geolocation (Country/City), Autonomous System Number (ASN), and Web Server banner.
- **⚡ Live Scan Dispatch (`/api/v1/scan/`)**: Allows instant triggering of fresh public scans via the urlscan.io API directly from the browser.

---

## 🔑 Secure API Keys Management (100% Client-Side)

- **Zero Exposure**: API keys are saved **strictly in your browser's private `localStorage`** (`tw_urlscan_api_key` and `tw_vt_api_key`).
- **No Git Leaks**: Keys are never pushed to GitHub, never sent to external servers, and never visible to the public.
- **1-Click Team Onboarding Link**: Click **"🔗 Copy Team Link"** in the API Keys modal to generate a private `#config=` URL fragment that loads the keys into your teammates' browsers in a single click (the URL fragment is never logged or sent to GitHub servers).

---

## 📋 Forensic Workflow & Features

1. **Target Normalization & Defanging**: Auto-converts `hxxps://`, `[.]`, and deep URLs to canonical domain names while safely displaying the defanged target format (`thoughtworks-careers[.]online`).
2. **Thoughtworks Impersonation Risk Score**: Algorithmic scoring gauge (0-100) combining brand match, homoglyph typosquatting, recruitment/credential phishing keywords, disposable TLDs, VirusTotal detection counts, and urlscan page title spoofing.
3. **Automated Abuse Takedown Generator**: Drafts a formal abuse complaint citing VirusTotal multi-vendor detections and urlscan.io landing page evidence with 1-click clipboard copy.
4. **NT Local Memory Drawer**: Stores your recent triage investigations locally for rapid recall and allows exporting full dossiers to JSON.
5. **Report Exports**: Download formatted Markdown (`.md`) reports or complete JSON telemetry in one click.
