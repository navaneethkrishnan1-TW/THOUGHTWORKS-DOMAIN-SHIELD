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

// Curated Domain OSINT & Infrastructure Threat Intelligence Tools
const TOOLS_MAP = [
  {
    id: 1,
    name: "WHOis",
    category: "Domain Registration & Nameserver Dossier",
    icon: "📜",
    getUrl: (d, ip) => `https://who.is/whois/${d}`
  },
  {
    id: 2,
    name: "ICANN Lookup",
    category: "Official ICANN RDAP Registrar Records",
    icon: "🌐",
    getUrl: (d, ip) => `https://lookup.icann.org/en/lookup?q=${encodeURIComponent(d)}`
  },
  {
    id: 3,
    name: "URL Void",
    category: "Domain Safety & Web Blacklist Engine (30+ Engines)",
    icon: "🔍",
    getUrl: (d, ip) => `https://www.urlvoid.com/scan/${d}/`
  },
  {
    id: 4,
    name: "URL Scan.io",
    category: "DOM, Redirects & Page Screenshot Sandbox",
    icon: "🔎",
    getUrl: (d, ip) => `https://urlscan.io/search/#domain%3A${encodeURIComponent(d)}`
  },
  {
    id: 5,
    name: "VirusTotal",
    category: "Multi-Vendor Domain Threat Intel & Passive DNS",
    icon: "🦠",
    getUrl: (d, ip) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(d)}`
  },
  {
    id: 6,
    name: "Crt.sh",
    category: "Certificate Transparency Logs & Subdomain Discovery",
    icon: "🔐",
    getUrl: (d, ip) => `https://crt.sh/?q=%25${encodeURIComponent(d)}`
  },
  {
    id: 7,
    name: "EasyDMARC",
    category: "DMARC, SPF & Anti-Spoofing Posture Validator",
    icon: "🛡️",
    getUrl: (d, ip) => `https://easydmarc.com/tools/dmarc-lookup?domain=${encodeURIComponent(d)}`
  },
  {
    id: 8,
    name: "Email Scanner Sensei",
    category: "MX Records & Mail Delivery Health Assessment",
    icon: "✉️",
    getUrl: (d, ip) => `https://mxtoolbox.com/emailhealth/${encodeURIComponent(d)}`
  },
  {
    id: 9,
    name: "Abuse IP DB",
    category: "IP Abuse Confidence & Threat Incident Reports",
    icon: "🚫",
    getUrl: (d, ip) => ip ? `https://www.abuseipdb.com/check/${ip}` : `https://www.abuseipdb.com/`
  },
  {
    id: 10,
    name: "IP Void",
    category: "IP Blacklist & Hosting Infrastructure Check",
    icon: "🌐",
    getUrl: (d, ip) => ip ? `https://www.ipvoid.com/ip-blacklist-check/?ip=${ip}` : `https://www.ipvoid.com/domain-reputation-check/`
  },
  {
    id: 11,
    name: "cymru",
    category: "Team Cymru IP to ASN & BGP Reputation",
    icon: "🐉",
    getUrl: (d, ip) => `https://team-cymru.com/community-services/ip-asn-mapping/`
  },
  {
    id: 12,
    name: "Shodan",
    category: "Open Ports, Host Services & SSL Banners",
    icon: "👁️",
    getUrl: (d, ip) => `https://www.shodan.io/search?query=hostname%3A${encodeURIComponent(d)}`
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
const urlscanVerdictRow = document.getElementById("urlscanVerdictRow");
const urlscanVerdict = document.getElementById("urlscanVerdict");
const urlscanTitleRow = document.getElementById("urlscanTitleRow");
const urlscanTitle = document.getElementById("urlscanTitle");
const urlscanLink = document.getElementById("urlscanLink");
const urlscanScreenshot = document.getElementById("urlscanScreenshot");
const urlscanThumbWrapper = document.getElementById("urlscanThumbWrapper");
const urlscanThumbImg = document.getElementById("urlscanThumbImg");
const urlscanThumbLink = document.getElementById("urlscanThumbLink");
const urlscanSubmitBtn = document.getElementById("urlscanSubmitBtn");
const urlscanSubmitMsg = document.getElementById("urlscanSubmitMsg");
const urlscanKeyToggleBtn = document.getElementById("urlscanKeyToggleBtn");
const urlscanKeyQuickBtn = document.getElementById("urlscanKeyQuickBtn");
const urlscanModal = document.getElementById("urlscanModal");
const closeUrlscanModalBtn = document.getElementById("closeUrlscanModalBtn");
const urlscanApiKeyInput = document.getElementById("urlscanApiKeyInput");
const vtApiKeyInput = document.getElementById("vtApiKeyInput");
const saveUrlscanKeyBtn = document.getElementById("saveUrlscanKeyBtn");
const clearUrlscanKeyBtn = document.getElementById("clearUrlscanKeyBtn");
const urlscanKeyStatusText = document.getElementById("urlscanKeyStatusText");
const vtKeyStatusText = document.getElementById("vtKeyStatusText");
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
  updateUrlscanKeyUI();
  setupEventListeners();
});

function openUrlscanModal() {
  if (urlscanModal) {
    if (urlscanApiKeyInput) urlscanApiKeyInput.value = getUrlscanApiKey();
    if (vtApiKeyInput) vtApiKeyInput.value = getVTApiKey();
    updateUrlscanKeyUI();
    urlscanModal.style.display = "flex";
  }
}

function closeUrlscanModal() {
  if (urlscanModal) {
    urlscanModal.style.display = "none";
  }
}

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
    TOOLS_MAP.forEach(tool => {
      window.open(tool.getUrl(d, ip), "_blank");
    });
    showToast(`Opened all ${TOOLS_MAP.length} Domain OSINT tools in browser tabs!`);
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

  // urlscan.io Key & Scan Event Listeners
  if (urlscanKeyToggleBtn) urlscanKeyToggleBtn.addEventListener("click", openUrlscanModal);
  if (urlscanKeyQuickBtn) urlscanKeyQuickBtn.addEventListener("click", openUrlscanModal);
  if (closeUrlscanModalBtn) closeUrlscanModalBtn.addEventListener("click", closeUrlscanModal);
  if (urlscanModal) {
    urlscanModal.addEventListener("click", (e) => {
      if (e.target === urlscanModal) closeUrlscanModal();
    });
  }
  if (saveUrlscanKeyBtn) {
    saveUrlscanKeyBtn.addEventListener("click", () => {
      const uKey = urlscanApiKeyInput ? urlscanApiKeyInput.value : "";
      const vKey = vtApiKeyInput ? vtApiKeyInput.value : "";
      saveApiKeys(uKey, vKey);
      closeUrlscanModal();
    });
  }
  if (clearUrlscanKeyBtn) {
    clearUrlscanKeyBtn.addEventListener("click", () => {
      clearApiKeys();
      closeUrlscanModal();
    });
  }
  if (urlscanSubmitBtn) {
    urlscanSubmitBtn.addEventListener("click", () => {
      if (currentIntel && currentIntel.domain) {
        submitUrlscanScan(currentIntel.domain);
      } else {
        showToast("Please investigate a domain first.");
      }
    });
  }
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
    urlscan: {
      scansFound: 0,
      latestUrl: null,
      screenshotUrl: null,
      malicious: false,
      score: 0,
      title: null,
      server: null,
      ip: null,
      date: null,
      categories: []
    },
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

// Multi-Source RDAP & WHOIS Query Engine (Fast, CORS-Safe, Multi-Tiered)
async function queryRDAP(domain) {
  const result = {
    registrar: "Unavailable (Check WHOIS link)",
    created: null,
    expires: null,
    ageDays: null,
    abuseEmail: null
  };

  const tld = domain.split(".").pop().toLowerCase();

  // Helper with 4.5s timeout so queries never hang
  const fetchWithTimeout = async (url, options = {}, timeoutMs = 4500) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timer);
      return res;
    } catch (e) {
      clearTimeout(timer);
      throw e;
    }
  };

  // Source 1: Direct Verisign Registry RDAP for .com and .net (Authoritative, Zero Redirects, CORS enabled)
  if (tld === "com" || tld === "net") {
    try {
      const res = await fetchWithTimeout(`https://rdap.verisign.com/${tld}/v1/domain/${domain}`);
      if (res.ok) {
        const data = await res.json();
        
        // Find registration date
        if (data.events && Array.isArray(data.events)) {
          const regEvent = data.events.find(e => e.eventAction === "registration");
          const expEvent = data.events.find(e => e.eventAction === "expiration");
          if (regEvent && regEvent.eventDate) {
            result.created = regEvent.eventDate;
            const dt = new Date(regEvent.eventDate);
            if (!isNaN(dt.getTime())) {
              result.ageDays = Math.floor(Math.abs(Date.now() - dt.getTime()) / (1000 * 60 * 60 * 24));
            }
          }
          if (expEvent && expEvent.eventDate) {
            result.expires = expEvent.eventDate;
          }
        }

        // Find registrar
        if (data.entities && Array.isArray(data.entities)) {
          const regEntity = data.entities.find(e => e.roles && e.roles.includes("registrar"));
          if (regEntity) {
            const fnProp = regEntity.vcardArray?.[1]?.find(p => p[0] === "fn");
            if (fnProp && fnProp[3]) {
              result.registrar = fnProp[3];
            } else if (regEntity.handle) {
              result.registrar = `Registrar IANA ID: ${regEntity.handle}`;
            }
          }
        }
        
        if (result.created && result.registrar !== "Unavailable (Check WHOIS link)") {
          return result;
        }
      }
    } catch (e) {
      console.warn("Direct Verisign RDAP error, trying next source:", e);
    }
  }

  // Source 2: NetworkCalc Public WHOIS API (CORS enabled, supports .com, .org, .xyz, .net, etc.)
  try {
    const res = await fetchWithTimeout(`https://networkcalc.com/api/dns/whois/${domain}`);
    if (res.ok) {
      const data = await res.json();
      if (data.status === "OK" && data.whois) {
        const w = data.whois;
        if (w.registrar) result.registrar = w.registrar;
        if (w.registry_created_date) {
          result.created = w.registry_created_date;
          const dt = new Date(w.registry_created_date);
          if (!isNaN(dt.getTime())) {
            result.ageDays = Math.floor(Math.abs(Date.now() - dt.getTime()) / (1000 * 60 * 60 * 24));
          }
        }
        if (w.registry_expiration_date) result.expires = w.registry_expiration_date;
        if (w.abuse_email) result.abuseEmail = w.abuse_email;
        if (result.created) return result;
      }
    }
  } catch (e) {
    console.warn("NetworkCalc WHOIS error, trying generic RDAP relay:", e);
  }

  // Source 3: rdap.org generic relay fallback
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${domain}`);
    if (res.ok) {
      const data = await res.json();
      if (data.events && Array.isArray(data.events)) {
        const regEvent = data.events.find(e => e.eventAction === "registration");
        const expEvent = data.events.find(e => e.eventAction === "expiration");
        if (regEvent && regEvent.eventDate) {
          result.created = regEvent.eventDate;
          const dt = new Date(regEvent.eventDate);
          if (!isNaN(dt.getTime())) {
            result.ageDays = Math.floor(Math.abs(Date.now() - dt.getTime()) / (1000 * 60 * 60 * 24));
          }
        }
        if (expEvent && expEvent.eventDate) result.expires = expEvent.eventDate;
      }
      if (data.entities && Array.isArray(data.entities)) {
        const regEntity = data.entities.find(e => e.roles && e.roles.includes("registrar"));
        if (regEntity) {
          const fnProp = regEntity.vcardArray?.[1]?.find(p => p[0] === "fn");
          if (fnProp && fnProp[3]) result.registrar = fnProp[3];
          else if (regEntity.handle) result.registrar = regEntity.handle;
        }
      }
    }
  } catch (e) {
    console.warn("rdap.org relay error:", e);
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

// ==============================================================================
// URLSCAN.IO API INTEGRATION
// ==============================================================================
function getUrlscanApiKey() {
  return (localStorage.getItem("tw_urlscan_api_key") || "").trim();
}

function getVTApiKey() {
  return (localStorage.getItem("tw_vt_api_key") || "").trim();
}

function saveApiKeys(urlscanKey, vtKey) {
  const cleanUrlscan = (urlscanKey || "").trim();
  const cleanVt = (vtKey || "").trim();

  if (cleanUrlscan) {
    localStorage.setItem("tw_urlscan_api_key", cleanUrlscan);
  } else {
    localStorage.removeItem("tw_urlscan_api_key");
  }

  if (cleanVt) {
    localStorage.setItem("tw_vt_api_key", cleanVt);
  } else {
    localStorage.removeItem("tw_vt_api_key");
  }

  updateUrlscanKeyUI();
  showToast("API keys saved safely in browser localStorage!");
}

function clearApiKeys() {
  localStorage.removeItem("tw_urlscan_api_key");
  localStorage.removeItem("tw_vt_api_key");
  updateUrlscanKeyUI();
  showToast("API keys cleared from browser.");
}

function updateUrlscanKeyUI() {
  const urlscanKey = getUrlscanApiKey();
  const vtKey = getVTApiKey();

  // 1. urlscan.io field
  if (urlscanKey) {
    const masked = urlscanKey.length > 8 ? `${urlscanKey.slice(0, 4)}••••${urlscanKey.slice(-4)}` : "••••••••";
    if (urlscanKeyStatusText) {
      urlscanKeyStatusText.innerHTML = `<span style="color:#10b981;">Active</span> (<code>${masked}</code>)`;
    }
    if (urlscanApiKeyInput) {
      urlscanApiKeyInput.value = urlscanKey;
    }
  } else {
    if (urlscanKeyStatusText) {
      urlscanKeyStatusText.innerHTML = `<span class="text-muted">No API Key configured (Public Quotas)</span>`;
    }
    if (urlscanApiKeyInput) {
      urlscanApiKeyInput.value = "";
    }
  }

  // 2. VirusTotal field
  if (vtKey) {
    const masked = vtKey.length > 8 ? `${vtKey.slice(0, 4)}••••${vtKey.slice(-4)}` : "••••••••";
    if (vtKeyStatusText) {
      vtKeyStatusText.innerHTML = `<span style="color:#10b981;">Active</span> (<code>${masked}</code>)`;
    }
    if (vtApiKeyInput) {
      vtApiKeyInput.value = vtKey;
    }
  } else {
    if (vtKeyStatusText) {
      vtKeyStatusText.innerHTML = `<span class="text-muted">No API Key configured (Standard Lookups)</span>`;
    }
    if (vtApiKeyInput) {
      vtApiKeyInput.value = "";
    }
  }

  // 3. Header button badge
  const activeCount = (urlscanKey ? 1 : 0) + (vtKey ? 1 : 0);
  if (urlscanKeyToggleBtn) {
    if (activeCount > 0) {
      urlscanKeyToggleBtn.innerHTML = `🔑 Keys (${activeCount}) <span style="color:#10b981;">●</span>`;
      urlscanKeyToggleBtn.classList.add("btn-key-active");
    } else {
      urlscanKeyToggleBtn.innerHTML = `🔑 API Keys`;
      urlscanKeyToggleBtn.classList.remove("btn-key-active");
    }
  }
}

// urlscan.io Search API Query
async function queryUrlscan(domain) {
  const result = {
    scansFound: 0,
    latestUrl: null,
    screenshotUrl: null,
    malicious: false,
    score: 0,
    title: null,
    server: null,
    ip: null,
    date: null,
    categories: []
  };

  const apiKey = getUrlscanApiKey();
  const headers = { "Accept": "application/json" };
  if (apiKey) {
    headers["API-Key"] = apiKey;
  }

  try {
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`, {
      headers,
      mode: "cors"
    });

    if (res.ok) {
      const data = await res.json();
      result.scansFound = data.total || 0;
      if (data.results && data.results.length > 0) {
        const first = data.results[0];
        result.latestUrl = first.result;
        result.screenshotUrl = first.screenshot;
        result.date = (first.task?.time || "").slice(0, 10);
        result.title = first.page?.title || null;
        result.server = first.page?.server || null;
        result.ip = first.page?.ip || null;

        const verdicts = first.verdicts?.overall || {};
        result.malicious = !!verdicts.malicious;
        result.score = verdicts.score || 0;
        result.categories = verdicts.categories || [];
      }
    }
  } catch (err) {
    console.warn("urlscan.io API search query failed or blocked by CORS:", err);
  }

  return result;
}

// urlscan.io Submission API (Live Scan)
async function submitUrlscanScan(domain) {
  if (!domain) return;
  const apiKey = getUrlscanApiKey();

  if (!apiKey) {
    openUrlscanModal();
    showToast("Please save your urlscan.io API Key to submit scans.");
    return;
  }

  if (!urlscanSubmitBtn || !urlscanSubmitMsg) return;

  const targetUrl = domain.startsWith("http") ? domain : `https://${domain}`;
  urlscanSubmitBtn.disabled = true;
  urlscanSubmitBtn.innerText = "⏳ Submitting...";
  urlscanSubmitMsg.style.display = "block";
  urlscanSubmitMsg.innerHTML = `<span class="spinner" style="display:inline-block; vertical-align:middle; width:12px; height:12px; margin-right:4px;"></span> Dispatching scan request to urlscan.io API...`;

  try {
    const res = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key": apiKey
      },
      body: JSON.stringify({
        url: targetUrl,
        visibility: "public",
        tags: ["thoughtworks-domain-shield"]
      })
    });

    const data = await res.json();
    if (res.ok && data.result) {
      urlscanSubmitMsg.innerHTML = `✅ Scan queued! <a href="${data.result}" target="_blank" class="text-cyan font-bold">Open Live Scan Report ↗</a> (UUID: ${data.uuid ? data.uuid.slice(0, 8) : 'done'}...)`;
      showToast("Scan queued on urlscan.io!");
    } else {
      const errMsg = data.message || data.description || "Scan submission rejected";
      urlscanSubmitMsg.innerHTML = `⚠️ Error: ${escapeHtml(errMsg)}`;
    }
  } catch (err) {
    urlscanSubmitMsg.innerHTML = `⚠️ Submission error (${escapeHtml(err.message)}). <a href="https://urlscan.io/search/#domain%3A${encodeURIComponent(domain)}" target="_blank" class="text-cyan">Open urlscan.io directly ↗</a>`;
  } finally {
    urlscanSubmitBtn.disabled = false;
    urlscanSubmitBtn.innerText = "⚡ Submit Scan (API)";
  }
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

  // 7. urlscan.io Sandbox Threat Verdicts
  if (intel.urlscan) {
    if (intel.urlscan.malicious || intel.urlscan.score >= 50) {
      score += 35;
      indicators.push(`urlscan.io Threat Verdict: Domain carries MALICIOUS verdict (Score: ${intel.urlscan.score})`);
    }
    if (intel.urlscan.title && intel.urlscan.title.toLowerCase().includes("thoughtworks")) {
      score += 25;
      indicators.push(`Brand Hijacking in Page Content: urlscan.io landing title mentions 'Thoughtworks' ("${intel.urlscan.title}")`);
    }
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
  if (intel.rdap.registrar && intel.rdap.registrar !== "Unavailable (Check WHOIS link)") {
    rdapRegistrar.innerText = intel.rdap.registrar;
  } else {
    rdapRegistrar.innerHTML = `<a href="https://who.is/whois/${intel.domain}" target="_blank" class="text-cyan">Query Who.is ↗</a>`;
  }

  if (intel.rdap.created) {
    rdapCreated.innerText = intel.rdap.created.slice(0, 10);
  } else {
    rdapCreated.innerHTML = `<a href="https://lookup.icann.org/en/lookup?q=${encodeURIComponent(intel.domain)}" target="_blank" class="text-cyan">Query ICANN ↗</a>`;
  }

  if (intel.rdap.ageDays !== null && !isNaN(intel.rdap.ageDays)) {
    let ageStr = `${intel.rdap.ageDays} days`;
    if (intel.rdap.ageDays < 30) {
      ageStr += " ⚠️ [CRITICAL: < 30 DAYS]";
      rdapAge.className = "row-value mono text-red";
    } else if (intel.rdap.ageDays < 90) {
      ageStr += " ⚠️ [NEW DOMAIN]";
      rdapAge.className = "row-value mono text-yellow";
    } else {
      rdapAge.className = "row-value mono text-cyan";
    }
    rdapAge.innerText = ageStr;
  } else {
    rdapAge.innerText = "Unknown";
    rdapAge.className = "row-value mono text-muted";
  }

  if (intel.rdap.expires) {
    rdapExpires.innerText = intel.rdap.expires.slice(0, 10);
  } else {
    rdapExpires.innerText = "Unknown";
  }

  // 6. Sandbox & SSL (urlscan.io & crt.sh)
  urlscanCount.innerText = `${intel.urlscan.scansFound} scan(s) on record`;
  
  if (intel.urlscan.scansFound > 0) {
    if (urlscanVerdictRow && urlscanVerdict) {
      urlscanVerdictRow.style.display = "flex";
      if (intel.urlscan.malicious || intel.urlscan.score >= 50) {
        urlscanVerdict.innerHTML = `<span class="badge-verdict" style="background:rgba(239,68,68,0.2); color:#ef4444; border:1px solid #ef4444; font-size:0.75rem; padding:0.2rem 0.5rem;">🚨 MALICIOUS (Score: ${intel.urlscan.score})</span>`;
      } else {
        urlscanVerdict.innerHTML = `<span class="badge-verdict" style="background:rgba(16,185,129,0.2); color:#10b981; border:1px solid #10b981; font-size:0.75rem; padding:0.2rem 0.5rem;">🛡️ Clean / Unrated (${intel.urlscan.score || 0})</span>`;
      }
    }

    if (urlscanTitleRow && urlscanTitle) {
      if (intel.urlscan.title) {
        urlscanTitleRow.style.display = "flex";
        urlscanTitle.innerText = intel.urlscan.title;
        urlscanTitle.title = intel.urlscan.title;
      } else {
        urlscanTitleRow.style.display = "none";
      }
    }
  } else {
    if (urlscanVerdictRow) urlscanVerdictRow.style.display = "none";
    if (urlscanTitleRow) urlscanTitleRow.style.display = "none";
  }

  urlscanLink.innerHTML = intel.urlscan.latestUrl 
    ? `<a href="${intel.urlscan.latestUrl}" target="_blank" class="text-cyan font-bold">View Latest Scan Report ↗</a>` 
    : `<a href="https://urlscan.io/search/#domain%3A${encodeURIComponent(intel.domain)}" target="_blank" class="text-cyan">Search on urlscan.io ↗</a>`;
    
  urlscanScreenshot.innerHTML = intel.urlscan.screenshotUrl 
    ? `<a href="${intel.urlscan.screenshotUrl}" target="_blank" class="text-yellow">View High-Res Snapshot ↗</a>` 
    : `<span class="text-muted">None available</span>`;

  if (urlscanThumbWrapper && urlscanThumbImg && urlscanThumbLink) {
    if (intel.urlscan.screenshotUrl) {
      urlscanThumbWrapper.style.display = "block";
      urlscanThumbImg.src = intel.urlscan.screenshotUrl;
      urlscanThumbLink.href = intel.urlscan.latestUrl || intel.urlscan.screenshotUrl;
    } else {
      urlscanThumbWrapper.style.display = "none";
      urlscanThumbImg.src = "";
    }
  }

  if (urlscanSubmitMsg) {
    urlscanSubmitMsg.style.display = "none";
    urlscanSubmitMsg.innerHTML = "";
  }

  crtshLink.innerHTML = `<a href="https://crt.sh/?q=%25${intel.domain}" target="_blank" class="text-cyan">View crt.sh Certs ↗</a>`;

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
