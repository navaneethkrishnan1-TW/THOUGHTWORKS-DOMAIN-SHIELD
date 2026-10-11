/**
 * Thoughtworks Domain Shield - Client-Side Threat Intelligence App
 * Author: navaneethkrishnan1-TW
 * Powered by Google DoH, ICANN RDAP, RIPE NCC, and LocalStorage NT Memory
 */

// ==============================================================================
// CONFIGURATION & CONSTANTS
// ==============================================================================
const LEGITIMATE_DOMAINS = new Set([
  "thoughtworks.com",
  "www.thoughtworks.com",
  "thoughtworks.cn",
  "martinfowler.com",
  "technologyradar.com"
]);

const HIGH_RISK_TLDS = new Set([
  "xyz", "top", "online", "site", "live", "store", "buzz", "cfd", "shop",
  "icu", "work", "click", "vip", "link", "monster", "rest", "cam", "gdn",
  "space", "app", "tech", "club", "uno", "fit", "fun", "pw", "cc"
]);

const IMPERSONATION_KEYWORDS = [
  "career", "careers", "job", "jobs", "hire", "hiring", "interview",
  "hr", "recruitment", "recruit", "talent", "offer", "intern", "apply",
  "resume", "assessment", "placement", "salary", "payroll",
  "login", "portal", "sso", "auth", "okta", "verify", "employee",
  "mail", "webmail", "support", "helpdesk", "vpn", "service", "secure",
  "it", "confluence", "jira", "github", "token", "password",
  "global", "corp", "group", "work", "tech", "cloud", "consulting",
  "solutions", "lab", "digital", "official", "network", "dev"
];

// Exact tools from /Users/navaneeth/Desktop/Screenshot 2026-10-12 at 1.47.50 AM.heic
const TOOLS_MAP = [
  {
    id: 1,
    name: "ANYRun",
    category: "Interactive Malware & Phishing Sandbox",
    icon: "▶️",
    getUrl: (d, ip) => `https://app.any.run/`
  },
  {
    id: 2,
    name: "IP Void",
    category: "IP & Domain Reputation Check",
    icon: "🌐",
    getUrl: (d, ip) => ip ? `https://www.ipvoid.com/ip-blacklist-check/?ip=${ip}` : `https://www.ipvoid.com/domain-reputation-check/`
  },
  {
    id: 3,
    name: "Abuse IP DB",
    category: "IP Threat Reputation & Abuse Confidence",
    icon: "🚫",
    getUrl: (d, ip) => ip ? `https://www.abuseipdb.com/check/${ip}` : `https://www.abuseipdb.com/`
  },
  {
    id: 4,
    name: "URL Void",
    category: "Domain Safety & Web Blacklist Engine",
    icon: "🔍",
    getUrl: (d, ip) => `https://www.urlvoid.com/scan/${d}/`
  },
  {
    id: 5,
    name: "ICANN Lookup",
    category: "Official ICANN RDAP / WHOIS Records",
    icon: "🌐",
    getUrl: (d, ip) => `https://lookup.icann.org/en/lookup?q=${encodeURIComponent(d)}`
  },
  {
    id: 6,
    name: "URL Scan.io",
    category: "DOM, Network Requests & Page Screenshot",
    icon: "🔎",
    getUrl: (d, ip) => `https://urlscan.io/search/#domain%3A${encodeURIComponent(d)}`
  },
  {
    id: 7,
    name: "IP Quality",
    category: "IPQualityScore Fraud & Malicious URL Scanner",
    icon: "🔥",
    getUrl: (d, ip) => ip ? `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${ip}` : `https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner`
  },
  {
    id: 8,
    name: "Browser.lol",
    category: "Safe Disposable Cloud Browser Sandbox",
    icon: "🧪",
    getUrl: (d, ip) => `https://browser.lol/`
  },
  {
    id: 9,
    name: "Email Scanner Sensei",
    category: "Email Security & Mail Health Assessment",
    icon: "✉️",
    getUrl: (d, ip) => `https://mxtoolbox.com/emailhealth/${encodeURIComponent(d)}`
  },
  {
    id: 10,
    name: "EasyDMARC",
    category: "DMARC & SPF Anti-Spoofing Analyzer",
    icon: "🛡️",
    getUrl: (d, ip) => `https://easydmarc.com/tools/dmarc-lookup?domain=${encodeURIComponent(d)}`
  },
  {
    id: 11,
    name: "WHOis",
    category: "Domain Registration & Ownership Dossier",
    icon: "📜",
    getUrl: (d, ip) => `https://who.is/whois/${encodeURIComponent(d)}`
  },
  {
    id: 12,
    name: "cymru",
    category: "Team Cymru IP to ASN & BGP Reputation",
    icon: "🐉",
    getUrl: (d, ip) => `https://team-cymru.com/community-services/ip-asn-mapping/`
  },
  {
    id: 13,
    name: "CyberChef",
    category: "Cyber Swiss Army Knife (Defang & Recipe Analysis)",
    icon: "👨‍🍳",
    getUrl: (d, ip) => `https://gchq.github.io/CyberChef/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')&input=${encodeURIComponent(d)}`
  },
  // Supplementary analyst tools
  {
    id: 14,
    name: "VirusTotal",
    category: "Multi-Engine Threat & Community Graph",
    icon: "🦠",
    getUrl: (d, ip) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(d)}`
  },
  {
    id: 15,
    name: "Shodan",
    category: "Internet-Connected Device & Open Ports",
    icon: "👁️",
    getUrl: (d, ip) => `https://www.shodan.io/search?query=hostname%3A${encodeURIComponent(d)}`
  },
  {
    id: 16,
    name: "Crt.sh",
    category: "Certificate Transparency Logs",
    icon: "🔐",
    getUrl: (d, ip) => `https://crt.sh/?q=%25${encodeURIComponent(d)}`
  }
];

// Current State
let currentIntel = null;

// ==============================================================================
// DOM ELEMENTS
// ==============================================================================
const investigateForm = document.getElementById("investigateForm");
const targetInput = document.getElementById("targetInput");
const pasteBtn = document.getElementById("pasteBtn");
const submitBtn = document.getElementById("submitBtn");
const searchSpinner = document.getElementById("searchSpinner");
const btnText = document.getElementById("btnText");
const quickDemoBtn = document.getElementById("quickDemoBtn");
const resetBtn = document.getElementById("resetBtn");
const loadingIndicator = document.getElementById("loadingIndicator");
const loadingStep = document.getElementById("loadingStep");
const resultsWrapper = document.getElementById("resultsWrapper");

// Results Elements
const scoreValue = document.getElementById("scoreValue");
const gaugeArc = document.getElementById("gaugeArc");
const verdictBadge = document.getElementById("verdictBadge");
const displayDomain = document.getElementById("displayDomain");
const displayDefanged = document.getElementById("displayDefanged");
const displayTimestamp = document.getElementById("displayTimestamp");
const impersonationFlagsList = document.getElementById("impersonationFlagsList");

const dnsARecords = document.getElementById("dnsARecords");
const dnsAAAARecords = document.getElementById("dnsAAAARecords");
const bgpAsn = document.getElementById("bgpAsn");
const bgpPrefix = document.getElementById("bgpPrefix");
const dnsNSRecords = document.getElementById("dnsNSRecords");

const emailMXRecords = document.getElementById("emailMXRecords");
const emailThreatStatus = document.getElementById("emailThreatStatus");
const emailSPFRecord = document.getElementById("emailSPFRecord");
const emailDMARCStatus = document.getElementById("emailDMARCStatus");

const rdapRegistrar = document.getElementById("rdapRegistrar");
const rdapCreated = document.getElementById("rdapCreated");
const rdapAge = document.getElementById("rdapAge");
const rdapExpires = document.getElementById("rdapExpires");

const urlscanCount = document.getElementById("urlscanCount");
const urlscanLink = document.getElementById("urlscanLink");
const urlscanScreenshot = document.getElementById("urlscanScreenshot");
const crtshLink = document.getElementById("crtshLink");

const toolsGrid = document.getElementById("toolsGrid");
const openAllToolsBtn = document.getElementById("openAllToolsBtn");
const takedownTextarea = document.getElementById("takedownTextarea");
const copyTakedownBtn = document.getElementById("copyTakedownBtn");
const downloadReportBtn = document.getElementById("downloadReportBtn");
const downloadJsonBtn = document.getElementById("downloadJsonBtn");

// History Drawer
const historyToggleBtn = document.getElementById("historyToggleBtn");
const historyDrawer = document.getElementById("historyDrawer");
const drawerOverlay = document.getElementById("drawerOverlay");
const closeDrawerBtn = document.getElementById("closeDrawerBtn");
const historyListContainer = document.getElementById("historyListContainer");
const historyCount = document.getElementById("historyCount");
const exportMemoryBtn = document.getElementById("exportMemoryBtn");
const clearMemoryBtn = document.getElementById("clearMemoryBtn");
const toast = document.getElementById("toast");

// ==============================================================================
// INITIALIZATION
// ==============================================================================
document.addEventListener("DOMContentLoaded", () => {
  renderToolsLaunchpad("thoughtworks.com", null);
  updateHistoryBadge();
  setupEventListeners();
});

function setupEventListeners() {
  investigateForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const raw = targetInput.value.trim();
    if (raw) runInvestigation(raw);
  });

  pasteBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      targetInput.value = text.trim();
      targetInput.focus();
    } catch {
      showToast("Clipboard read blocked. Paste manually (Cmd+V).");
    }
  });

  quickDemoBtn.addEventListener("click", () => {
    targetInput.value = "thoughtworks-careers.online";
    runInvestigation("thoughtworks-careers.online");
  });

  resetBtn.addEventListener("click", () => {
    targetInput.value = "";
    resultsWrapper.style.display = "none";
    currentIntel = null;
  });

  openAllToolsBtn.addEventListener("click", () => {
    if (!currentIntel) return;
    const d = currentIntel.domain;
    const ip = currentIntel.dns.a[0] || null;
    TOOLS_MAP.slice(0, 13).forEach(tool => {
      window.open(tool.getUrl(d, ip), "_blank");
    });
    showToast("Opened all 13 tools in browser tabs!");
  });

  copyTakedownBtn.addEventListener("click", () => {
    if (!takedownTextarea.value) return;
    navigator.clipboard.writeText(takedownTextarea.value);
    showToast("Takedown notice copied to clipboard!");
  });

  downloadReportBtn.addEventListener("click", () => {
    if (!currentIntel) return;
    downloadFile(`TW-Report-${currentIntel.domain}.md`, generateMarkdownReport(currentIntel), "text/markdown");
  });

  downloadJsonBtn.addEventListener("click", () => {
    if (!currentIntel) return;
    downloadFile(`TW-Intel-${currentIntel.domain}.json`, JSON.stringify(currentIntel, null, 2), "application/json");
  });

  historyToggleBtn.addEventListener("click", openHistoryDrawer);
  closeDrawerBtn.addEventListener("click", closeHistoryDrawer);
  drawerOverlay.addEventListener("click", closeHistoryDrawer);
  exportMemoryBtn.addEventListener("click", exportAllMemory);
  clearMemoryBtn.addEventListener("click", clearMemory);
}

// ==============================================================================
// NORMALIZATION & LEVENSHTEIN DISTANCE
// ==============================================================================
function normalizeTarget(raw) {
  let clean = raw.trim();
  clean = clean.replace(/hxxps:\/\//i, "https://").replace(/hxxp:\/\//i, "http://");
  clean = clean.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
  clean = clean.replace(/\[:\/\/\]/g, "://").replace(/\(:\/\/\)/g, "://");

  let domain = clean;
  if (clean.includes("://")) {
    try {
      const u = new URL(clean);
      domain = u.hostname.toLowerCase();
    } catch {
      domain = clean.split("/")[2] || clean;
    }
  } else {
    domain = clean.split("/")[0].split(":")[0].toLowerCase();
  }
  domain = domain.replace(/^\.+|\.+$/g, "");

  const defangedDomain = domain.replace(/\./g, "[.]");
  return { domain, defangedDomain };
}

function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;
  let prevRow = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    let currRow = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      let ins = prevRow[j + 1] + 1;
      let del = currRow[j] + 1;
      let sub = prevRow[j] + (s1[i] !== s2[j] ? 1 : 0);
      currRow.push(Math.min(ins, del, sub));
    }
    prevRow = currRow;
  }
  return prevRow[prevRow.length - 1];
}

// ==============================================================================
// PARALLEL RECONNAISSANCE ENGINE (CLIENT-SIDE DOH & APIS)
// ==============================================================================
async function runInvestigation(rawInput) {
  const { domain, defangedDomain } = normalizeTarget(rawInput);
  if (!domain || !domain.includes(".")) {
    showToast("Invalid domain format! Please enter a valid domain.");
    return;
  }

  setLoading(true, `Querying DNS, RDAP, and Threat Feeds for ${defangedDomain}...`);

  const intel = {
    timestamp: new Date().toISOString(),
    domain,
    defangedDomain,
    dns: { a: [], aaaa: [], mx: [], txt: [], spf: null, dmarc: null, ns: [] },
    rdap: { registrar: "Unknown", created: null, expires: null, ageDays: null },
    bgp: { asn: null, asName: null, prefix: null },
    urlscan: { scansFound: 0, latestUrl: null, screenshotUrl: null },
    indicators: [],
    riskScore: 0,
    verdict: "ANALYZING"
  };

  try {
    // 1. Parallel DNS-over-HTTPS queries via Google Public DNS (CORS enabled)
    const [aRes, aaaaRes, mxRes, txtRes, dmarcRes, nsRes] = await Promise.all([
      queryDoH(domain, "A"),
      queryDoH(domain, "AAAA"),
      queryDoH(domain, "MX"),
      queryDoH(domain, "TXT"),
      queryDoH(`_dmarc.${domain}`, "TXT"),
      queryDoH(domain, "NS")
    ]);

    intel.dns.a = aRes;
    intel.dns.aaaa = aaaaRes;
    intel.dns.mx = mxRes;
    intel.dns.txt = txtRes;
    intel.dns.ns = nsRes;

    // Parse SPF
    const spfMatch = txtRes.find(t => t.toLowerCase().includes("v=spf1"));
    if (spfMatch) intel.dns.spf = spfMatch;

    // Parse DMARC
    if (dmarcRes.length > 0) intel.dns.dmarc = dmarcRes[0];

    // 2. Query ICANN RDAP for registration data
    const rdapData = await queryRDAP(domain);
    intel.rdap = rdapData;

    // 3. Query BGP / ASN via RIPE NCC for the primary resolved IP
    const primaryIp = intel.dns.a[0] || null;
    if (primaryIp) {
      const bgpData = await queryRIPE(primaryIp);
      intel.bgp = bgpData;
    }

    // 4. Query public urlscan.io search
    const urlscanData = await queryUrlscan(domain);
    intel.urlscan = urlscanData;

    // 5. Calculate Impersonation Risk Score
    const { score, indicators, verdict } = calculateRisk(intel);
    intel.riskScore = score;
    intel.indicators = indicators;
    intel.verdict = verdict;

    // Save to NT LocalStorage Memory
    saveToMemory(intel);

    currentIntel = intel;
    renderResults(intel);
  } catch (err) {
    console.error("Investigation error:", err);
    showToast("Reconnaissance encountered an error. Check console.");
  } finally {
    setLoading(false);
  }
}

// Google DNS-over-HTTPS Query
async function queryDoH(name, type) {
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    if (!res.ok) return [];
    const data = await res.json();
    if (data.Answer && Array.isArray(data.Answer)) {
      return data.Answer.map(ans => ans.data.replace(/^"|"$/g, ""));
    }
    return [];
  } catch {
    return [];
  }
}

// RDAP Registration Query
async function queryRDAP(domain) {
  const result = { registrar: "Unknown", created: null, expires: null, ageDays: null };
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return result;
    const data = await res.json();
    
    // Find events
    if (data.events) {
      const eventsMap = {};
      data.events.forEach(e => { eventsMap[e.eventAction] = e.eventDate; });
      result.created = eventsMap["registration"] || null;
      result.expires = eventsMap["expiration"] || null;
      if (result.created) {
        const createDate = new Date(result.created);
        const diffTime = Math.abs(Date.now() - createDate.getTime());
        result.ageDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
      }
    }

    // Find registrar
    if (data.entities) {
      for (const ent of data.entities) {
        if (ent.roles && ent.roles.includes("registrar")) {
          if (ent.vcardArray && ent.vcardArray[1]) {
            const fn = ent.vcardArray[1].find(p => p[0] === "fn");
            if (fn) result.registrar = fn[3];
          }
          if (result.registrar === "Unknown" && ent.handle) {
            result.registrar = ent.handle;
          }
        }
      }
    }
  } catch {
    // RDAP rate limit or ccTLD without public endpoint
  }
  return result;
}

// RIPE NCC Network & ASN Query
async function queryRIPE(ip) {
  const bgp = { asn: null, asName: null, prefix: null };
  try {
    const netRes = await fetch(`https://stat.ripe.net/data/network-info/data.json?resource=${ip}`);
    if (netRes.ok) {
      const netData = await netRes.json();
      if (netData.data && netData.data.asns && netData.data.asns.length > 0) {
        bgp.asn = netData.data.asns[0];
        bgp.prefix = netData.data.prefix;
        
        // Lookup AS Name
        const asRes = await fetch(`https://stat.ripe.net/data/as-overview/data.json?resource=${bgp.asn}`);
        if (asRes.ok) {
          const asData = await asRes.json();
          bgp.asName = asData.data?.holder || null;
        }
      }
    }
  } catch {}
  return bgp;
}

// urlscan.io Public Search Query
async function queryUrlscan(domain) {
  const result = { scansFound: 0, latestUrl: null, screenshotUrl: null };
  try {
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=1`);
    if (res.ok) {
      const data = await res.json();
      result.scansFound = data.total || 0;
      if (data.results && data.results.length > 0) {
        result.latestUrl = data.results[0].result;
        result.screenshotUrl = data.results[0].screenshot;
      }
    }
  } catch {}
  return result;
}

// ==============================================================================
// HEURISTIC IMPERSONATION RISK CALCULATION
// ==============================================================================
function calculateRisk(intel) {
  const domain = intel.domain.toLowerCase();
  const tld = domain.split(".").pop();

  if (LEGITIMATE_DOMAINS.has(domain) || domain.endsWith(".thoughtworks.com")) {
    return {
      score: 0,
      indicators: ["Legitimate Official Thoughtworks Infrastructure"],
      verdict: "LEGITIMATE / AUTHORIZED"
    };
  }

  let score = 0;
  const indicators = [];

  // 1. Direct or Typosquatted Brand Inclusion
  const isExactThoughtworks = domain.includes("thoughtworks");
  const normDomain = domain.replace(/0/g, "o").replace(/1/g, "l").replace(/vv/g, "w");
  const isHomoglyph = (normDomain.includes("thoughtworks") && !isExactThoughtworks) || 
                      (levenshteinDistance("thoughtworks", domain.split(".")[0]) <= 2);

  if (isExactThoughtworks) {
    score += 35;
    indicators.push("Target Brand Match: Explicitly contains 'thoughtworks'");
  } else if (isHomoglyph) {
    score += 40;
    indicators.push("Typosquatting / Homoglyph Attack: Visually mimics 'thoughtworks'");
  }

  // 2. High-Risk Phishing / Impersonation Keywords
  const matchedKeywords = IMPERSONATION_KEYWORDS.filter(kw => domain.includes(kw));
  if (matchedKeywords.length > 0) {
    const kwScore = Math.min(30, matchedKeywords.length * 12);
    score += kwScore;
    indicators.push(`Impersonation Attack Vectors: Keywords detected [${matchedKeywords.join(", ")}]`);
  }

  // 3. High-Abuse / Disposable TLD
  if (HIGH_RISK_TLDS.has(tld)) {
    score += 15;
    indicators.push(`High-Abuse TLD: Domain uses .${tld} (frequent in disposable phishing campaigns)`);
  }

  // 4. Domain Age Analysis
  if (intel.rdap.ageDays !== null) {
    if (intel.rdap.ageDays < 14) {
      score += 30;
      indicators.push(`Critical Age Flag: Domain registered only ${intel.rdap.ageDays} days ago`);
    } else if (intel.rdap.ageDays < 60) {
      score += 20;
      indicators.push(`Newly Registered Domain: Registered ${intel.rdap.ageDays} days ago`);
    } else if (intel.rdap.ageDays < 180) {
      score += 10;
      indicators.push(`Recent Domain Registration: Registered ${intel.rdap.ageDays} days ago`);
    }
  }

  // 5. MX Records (Active Email Weaponization)
  if (intel.dns.mx.length > 0) {
    score += 15;
    indicators.push(`Active Email Infrastructure: ${intel.dns.mx.length} MX record(s) active (capable of email phishing)`);
  } else {
    indicators.push("No MX Records: Domain currently not accepting inbound email");
  }

  // 6. DMARC / Spoofing Posture
  if (!intel.dns.dmarc) {
    score += 10;
    indicators.push("Missing DMARC Protection: Domain can be forged in spoofed email headers");
  } else if (intel.dns.dmarc.toLowerCase().includes("p=none")) {
    score += 5;
    indicators.push("Weak DMARC Policy: Configured with 'p=none' (monitoring mode, no spoofing rejection)");
  }

  const finalScore = Math.min(100, Math.max(0, score));
  let verdict = "BENIGN / LOW RISK";
  if (finalScore >= 80) verdict = "CRITICAL RISK (ACTIVE THOUGHTWORKS IMPERSONATION)";
  else if (finalScore >= 60) verdict = "HIGH RISK (SUSPICIOUS BRAND SPOOFING)";
  else if (finalScore >= 40) verdict = "MEDIUM RISK (REQUIRES ACTIVE MONITORING)";
  else if (finalScore >= 20) verdict = "LOW RISK (UNCONFIRMED / MINIMAL)";

  return { score: finalScore, indicators, verdict };
}

// ==============================================================================
// RENDER INVESTIGATION RESULTS
// ==============================================================================
function renderResults(intel) {
  resultsWrapper.style.display = "block";
  resultsWrapper.scrollIntoView({ behavior: "smooth" });

  // 1. Gauge & Score
  scoreValue.innerText = intel.riskScore;
  const circumference = 314;
  const offset = circumference - (intel.riskScore / 100) * circumference;
  gaugeArc.style.strokeDashoffset = offset;

  if (intel.riskScore >= 80) {
    gaugeArc.style.stroke = "var(--accent-red)";
    verdictBadge.style.background = "var(--critical-bg)";
    verdictBadge.style.color = "#fff";
  } else if (intel.riskScore >= 60) {
    gaugeArc.style.stroke = "var(--accent-yellow)";
    verdictBadge.style.background = "var(--accent-yellow)";
    verdictBadge.style.color = "#000";
  } else if (intel.riskScore >= 40) {
    gaugeArc.style.stroke = "var(--accent-cyan)";
    verdictBadge.style.background = "var(--accent-cyan)";
    verdictBadge.style.color = "#000";
  } else {
    gaugeArc.style.stroke = "var(--accent-green)";
    verdictBadge.style.background = "var(--accent-green)";
    verdictBadge.style.color = "#000";
  }
  verdictBadge.innerText = intel.verdict;

  // 2. Targets & Flags
  displayDomain.innerText = intel.domain;
  displayDefanged.innerText = intel.defangedDomain;
  displayTimestamp.innerText = new Date(intel.timestamp).toLocaleTimeString();

  impersonationFlagsList.innerHTML = intel.indicators.map(ind => `<li>${ind}</li>`).join("");

  // 3. DNS & Routing
  dnsARecords.innerText = intel.dns.a.length > 0 ? intel.dns.a.join(", ") : "No A records resolved";
  dnsAAAARecords.innerText = intel.dns.aaaa.length > 0 ? intel.dns.aaaa.join(", ") : "None";
  bgpAsn.innerText = intel.bgp.asn ? `AS${intel.bgp.asn} (${intel.bgp.asName || 'Unknown'})` : "N/A";
  bgpPrefix.innerText = intel.bgp.prefix || "N/A";
  dnsNSRecords.innerText = intel.dns.ns.length > 0 ? intel.dns.ns.join(", ") : "None";

  // 4. Email Weaponization
  emailMXRecords.innerText = intel.dns.mx.length > 0 ? intel.dns.mx.join(" | ") : "None";
  if (intel.dns.mx.length > 0) {
    emailThreatStatus.innerHTML = intel.riskScore > 30 
      ? `<span class="text-red">ACTIVE PHISHING CAPABILITY</span>` 
      : `<span class="text-green">Corporate Mail Exchangers</span>`;
  } else {
    emailThreatStatus.innerHTML = `<span class="text-muted">No Inbound Email</span>`;
  }
  emailSPFRecord.innerText = intel.dns.spf || "No SPF record found";
  emailDMARCStatus.innerHTML = intel.dns.dmarc 
    ? `<span class="text-cyan">${intel.dns.dmarc}</span>` 
    : `<span class="text-red">MISSING (Vulnerable to spoofing)</span>`;

  // 5. RDAP & Registration
  rdapRegistrar.innerText = intel.rdap.registrar;
  rdapCreated.innerText = intel.rdap.created ? intel.rdap.created.slice(0, 10) : "Unknown";
  rdapAge.innerText = intel.rdap.ageDays !== null ? `${intel.rdap.ageDays} days` : "Unknown";
  rdapExpires.innerText = intel.rdap.expires ? intel.rdap.expires.slice(0, 10) : "Unknown";

  // 6. Sandbox & SSL
  urlscanCount.innerText = `${intel.urlscan.scansFound} scan(s)`;
  urlscanLink.innerHTML = intel.urlscan.latestUrl 
    ? `<a href="${intel.urlscan.latestUrl}" target="_blank" class="text-cyan">View Scan</a>` 
    : `<a href="https://urlscan.io/search/#domain%3A${intel.domain}" target="_blank" class="text-cyan">Search urlscan.io</a>`;
  urlscanScreenshot.innerHTML = intel.urlscan.screenshotUrl 
    ? `<a href="${intel.urlscan.screenshotUrl}" target="_blank" class="text-yellow">View Snapshot</a>` 
    : `None available`;
  crtshLink.innerHTML = `<a href="https://crt.sh/?q=%25${intel.domain}" target="_blank" class="text-cyan">View crt.sh Certs</a>`;

  // 7. Render 13 Investigation Tools
  const primaryIp = intel.dns.a[0] || null;
  renderToolsLaunchpad(intel.domain, primaryIp);

  // 8. Takedown Template
  takedownTextarea.value = generateTakedownNotice(intel);
}

// Render Tools Grid (All 13 from Screenshot + extras)
function renderToolsLaunchpad(domain, primaryIp) {
  toolsGrid.innerHTML = TOOLS_MAP.map(tool => {
    const url = tool.getUrl(domain, primaryIp);
    return `
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="tool-tile">
        <div class="tool-tile-top">
          <span class="tool-tile-id">[${String(tool.id).padStart(2, "0")}]</span>
          <span style="font-size: 1.1rem;">${tool.icon}</span>
        </div>
        <div>
          <div class="tool-tile-name">${tool.name}</div>
          <div class="tool-tile-category">${tool.category}</div>
        </div>
        <div class="tool-tile-action">
          Open In Tool ↗
        </div>
      </a>
    `;
  }).join("");
}

// ==============================================================================
// DOSSIER & TAKEDOWN NOTICE GENERATORS
// ==============================================================================
function generateTakedownNotice(intel) {
  const d = intel.domain;
  const def = intel.defangedDomain;
  const ip = intel.dns.a[0] || "N/A";
  const reg = intel.rdap.registrar || "Domain Registrar";
  const asName = intel.bgp.asName || "Hosting Provider";

  let letter = `SUBJECT: URGENT: Thoughtworks Brand Impersonation & Phishing Notice - ${def}\n\n`;
  letter += `To Abuse Team at ${reg} / ${asName},\n\n`;
  letter += `I am writing on behalf of Thoughtworks Security & Brand Protection to report active malicious brand impersonation and fraudulent activity hosted on your infrastructure.\n\n`;
  letter += `Target Domain: ${def} (Resolving to IP: ${ip})\n`;
  letter += `Registrar: ${reg}\n`;
  letter += `Hosting Network: ${asName}\n\n`;
  letter += `EVIDENCE OF MALICIOUS ACTIVITY:\n`;
  letter += `1. Unauthorized use of the Thoughtworks brand name and deceptive likeness.\n`;
  letter += `2. Registration details indicate a newly created domain with no authorization from Thoughtworks Inc.\n`;
  if (intel.dns.mx.length > 0) {
    letter += `3. Domain is weaponized with active MX mail exchangers (${intel.dns.mx.join(", ")}), enabling fraudulent communications to job applicants or employees.\n`;
  }
  letter += `\nWe request the immediate suspension of this domain name in accordance with your Acceptable Use Policy (AUP) and ICANN anti-abuse provisions.\n\n`;
  letter += `Regards,\nThoughtworks Information Security & Incident Response\nEmail: abuse-report@thoughtworks.com\n`;
  return letter;
}

function generateMarkdownReport(intel) {
  let md = `# 🛡️ Threat Intelligence Report: Thoughtworks Impersonation Investigation\n\n`;
  md += `- **Target Domain:** \`${intel.defangedDomain}\`\n`;
  md += `- **Investigation Date:** \`${intel.timestamp}\`\n`;
  md += `- **Risk Score:** **${intel.riskScore}/100**\n`;
  md += `- **Verdict:** **${intel.verdict}**\n\n`;
  md += `## 🚨 Impersonation Signals\n`;
  intel.indicators.forEach(i => { md += `- ⚠️ ${i}\n`; });
  md += `\n## 🌐 DNS & Infrastructure\n`;
  md += `- **Resolved IPs:** \`${intel.dns.a.join(", ") || "None"}\`\n`;
  md += `- **BGP ASN:** \`AS${intel.bgp.asn || "N/A"}\` (${intel.bgp.asName || "N/A"})\n`;
  md += `- **Registrar:** \`${intel.rdap.registrar}\`\n`;
  md += `- **Domain Age:** \`${intel.rdap.ageDays || "Unknown"} days\`\n\n`;
  md += `## ✉️ Email Posture\n`;
  md += `- **MX:** \`${intel.dns.mx.join(", ") || "None"}\`\n`;
  md += `- **SPF:** \`${intel.dns.spf || "None"}\`\n`;
  md += `- **DMARC:** \`${intel.dns.dmarc || "Missing"}\`\n`;
  return md;
}

function downloadFile(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Downloaded ${filename}`);
}

// ==============================================================================
// NT MEMORY REPOSITORY (LOCALSTORAGE)
// ==============================================================================
const MEMORY_STORAGE_KEY = "TW_NT_INVESTIGATIONS_MEMORY";

function getMemory() {
  try {
    return JSON.parse(localStorage.getItem(MEMORY_STORAGE_KEY)) || [];
  } catch {
    return [];
  }
}

function saveToMemory(intel) {
  let history = getMemory();
  // Filter out duplicate domain
  history = history.filter(h => h.domain !== intel.domain);
  history.unshift({
    domain: intel.domain,
    defangedDomain: intel.defangedDomain,
    riskScore: intel.riskScore,
    verdict: intel.verdict,
    timestamp: intel.timestamp,
    registrar: intel.rdap.registrar,
    ageDays: intel.rdap.ageDays
  });
  // Keep last 30
  history = history.slice(0, 30);
  localStorage.setItem(MEMORY_STORAGE_KEY, JSON.stringify(history));
  updateHistoryBadge();
}

function updateHistoryBadge() {
  const count = getMemory().length;
  historyCount.innerText = count;
}

function openHistoryDrawer() {
  const history = getMemory();
  if (history.length === 0) {
    historyListContainer.innerHTML = `<p class="dim-text" style="padding: 1rem;">No investigations in memory yet.</p>`;
  } else {
    historyListContainer.innerHTML = history.map(item => {
      let badgeColor = "var(--accent-green)";
      if (item.riskScore >= 80) badgeColor = "var(--accent-red)";
      else if (item.riskScore >= 60) badgeColor = "var(--accent-yellow)";
      else if (item.riskScore >= 40) badgeColor = "var(--accent-cyan)";

      return `
        <div class="history-item" onclick="loadFromHistory('${item.domain}')">
          <div class="history-item-top">
            <span class="history-domain">${item.defangedDomain}</span>
            <span class="history-score-badge" style="background: ${badgeColor}; color: #000;">${item.riskScore}</span>
          </div>
          <div class="history-date">${new Date(item.timestamp).toLocaleString()} • ${item.registrar || 'Unknown'}</div>
        </div>
      `;
    }).join("");
  }
  historyDrawer.classList.add("open");
  drawerOverlay.classList.add("open");
}

function closeHistoryDrawer() {
  historyDrawer.classList.remove("open");
  drawerOverlay.classList.remove("open");
}

window.loadFromHistory = function(domain) {
  closeHistoryDrawer();
  targetInput.value = domain;
  runInvestigation(domain);
};

function exportAllMemory() {
  const history = getMemory();
  downloadFile("TW-NT-Memory-Dossiers.json", JSON.stringify(history, null, 2), "application/json");
}

function clearMemory() {
  if (confirm("Are you sure you want to clear all NT investigation memory?")) {
    localStorage.removeItem(MEMORY_STORAGE_KEY);
    updateHistoryBadge();
    openHistoryDrawer();
    showToast("Memory cleared.");
  }
}

// UI Helpers
function setLoading(isLoading, stepText = "") {
  if (isLoading) {
    loadingIndicator.style.display = "block";
    loadingStep.innerText = stepText;
    searchSpinner.style.display = "inline-block";
    btnText.innerText = "Analyzing...";
    submitBtn.disabled = true;
  } else {
    loadingIndicator.style.display = "none";
    searchSpinner.style.display = "none";
    btnText.innerText = "🔍 Investigate Domain";
    submitBtn.disabled = false;
  }
}

function showToast(msg) {
  toast.innerText = msg;
  toast.classList.add("show");
  setTimeout(() => { toast.classList.remove("show"); }, 3000);
}
