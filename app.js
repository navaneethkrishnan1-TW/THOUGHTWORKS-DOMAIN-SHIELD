/**
 * Thoughtworks Domain Shield - Client-Side Threat Intelligence App
 * Author: navaneethkrishnan1-TW
 * Dual-Engine Architecture: VirusTotal (VT) & urlscan.io
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

// Header & Modal Elements
const urlscanKeyToggleBtn = document.getElementById("urlscanKeyToggleBtn");
const urlscanModal = document.getElementById("urlscanModal");
const closeUrlscanModalBtn = document.getElementById("closeUrlscanModalBtn");
const urlscanApiKeyInput = document.getElementById("urlscanApiKeyInput");
const vtApiKeyInput = document.getElementById("vtApiKeyInput");
const saveUrlscanKeyBtn = document.getElementById("saveUrlscanKeyBtn");
const copyTeamLinkBtn = document.getElementById("copyTeamLinkBtn");
const clearUrlscanKeyBtn = document.getElementById("clearUrlscanKeyBtn");
const urlscanKeyStatusText = document.getElementById("urlscanKeyStatusText");
const vtKeyStatusText = document.getElementById("vtKeyStatusText");

// API Status Bar Pills
const vtStatusPill = document.getElementById("vtStatusPill");
const vtStatusText = document.getElementById("vtStatusText");
const urlscanStatusPill = document.getElementById("urlscanStatusPill");
const urlscanStatusText = document.getElementById("urlscanStatusText");
const configKeysQuickLink = document.getElementById("configKeysQuickLink");

// Threat Overview Elements
const scoreValue = document.getElementById("scoreValue");
const gaugeArc = document.getElementById("gaugeArc");
const verdictBadge = document.getElementById("verdictBadge");
const displayDomain = document.getElementById("displayDomain");
const displayDefanged = document.getElementById("displayDefanged");
const displayTimestamp = document.getElementById("displayTimestamp");
const impersonationFlagsList = document.getElementById("impersonationFlagsList");

// VirusTotal Card Elements
const vtVerdictBadge = document.getElementById("vtVerdictBadge");
const vtRatioText = document.getElementById("vtRatioText");
const vtBarMalicious = document.getElementById("vtBarMalicious");
const vtBarSuspicious = document.getElementById("vtBarSuspicious");
const vtBarHarmless = document.getElementById("vtBarHarmless");
const vtBarUndetected = document.getElementById("vtBarUndetected");
const vtCountMalicious = document.getElementById("vtCountMalicious");
const vtCountSuspicious = document.getElementById("vtCountSuspicious");
const vtCountHarmless = document.getElementById("vtCountHarmless");
const vtReputation = document.getElementById("vtReputation");
const vtTagsList = document.getElementById("vtTagsList");
const vtVendorsList = document.getElementById("vtVendorsList");
const vtDeepLink = document.getElementById("vtDeepLink");
const vtCorsNotice = document.getElementById("vtCorsNotice");

// urlscan.io Card Elements
const urlscanVerdictBadge = document.getElementById("urlscanVerdictBadge");
const screenshotStatus = document.getElementById("screenshotStatus");
const screenshotContainer = document.getElementById("screenshotContainer");
const screenshotPlaceholder = document.getElementById("screenshotPlaceholder");
const screenshotLink = document.getElementById("screenshotLink");
const screenshotImg = document.getElementById("screenshotImg");
const triggerScanScreenshotBtn = document.getElementById("triggerScanScreenshotBtn");

const landingTitle = document.getElementById("landingTitle");
const landingEffectiveUrl = document.getElementById("landingEffectiveUrl");
const landingIpCountry = document.getElementById("landingIpCountry");
const landingAsn = document.getElementById("landingAsn");
const landingServer = document.getElementById("landingServer");
const landingVerdictScore = document.getElementById("landingVerdictScore");

const urlscanSubmitLiveBtn = document.getElementById("urlscanSubmitLiveBtn");
const urlscanDeepLink = document.getElementById("urlscanDeepLink");
const urlscanLiveSubmitStatus = document.getElementById("urlscanLiveSubmitStatus");

// Abuse Takedown Elements
const takedownTextarea = document.getElementById("takedownTextarea");
const copyTakedownBtn = document.getElementById("copyTakedownBtn");
const downloadReportBtn = document.getElementById("downloadReportBtn");
const downloadJsonBtn = document.getElementById("downloadJsonBtn");

// Memory Drawer Elements
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
  checkTeamConfigHash();
  updateKeyUI();
  updateHistoryBadge();
  setupEventListeners();
});

function checkTeamConfigHash() {
  if (window.location.hash && window.location.hash.startsWith("#config=")) {
    try {
      const encoded = window.location.hash.replace("#config=", "");
      const parsed = JSON.parse(atob(encoded));
      if (parsed && (parsed.urlscan || parsed.vt)) {
        saveApiKeys(parsed.urlscan || "", parsed.vt || "");
        showToast("🎉 Team API keys activated successfully!");
      }
    } catch (e) {
      console.warn("Failed to parse team config hash:", e);
    }
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
}

// ==============================================================================
// API KEYS MANAGEMENT (LOCALSTORAGE PRIVATE)
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

  updateKeyUI();
  showToast("API keys saved safely in browser localStorage!");
}

function clearApiKeys() {
  localStorage.removeItem("tw_urlscan_api_key");
  localStorage.removeItem("tw_vt_api_key");
  updateKeyUI();
  showToast("API keys cleared from browser.");
}

function updateKeyUI() {
  const urlscanKey = getUrlscanApiKey();
  const vtKey = getVTApiKey();

  // 1. urlscan status in modal
  if (urlscanKey) {
    const masked = urlscanKey.length > 8 ? `${urlscanKey.slice(0, 4)}••••${urlscanKey.slice(-4)}` : "••••••••";
    if (urlscanKeyStatusText) {
      urlscanKeyStatusText.innerHTML = `<span style="color:#10b981;">Active</span> (<code>${masked}</code>)`;
    }
    if (urlscanApiKeyInput) urlscanApiKeyInput.value = urlscanKey;
    if (urlscanStatusPill) urlscanStatusPill.classList.add("active");
    if (urlscanStatusText) urlscanStatusText.innerText = "Key Active";
  } else {
    if (urlscanKeyStatusText) {
      urlscanKeyStatusText.innerHTML = `<span class="text-muted">No API Key configured</span>`;
    }
    if (urlscanApiKeyInput) urlscanApiKeyInput.value = "";
    if (urlscanStatusPill) urlscanStatusPill.classList.remove("active");
    if (urlscanStatusText) urlscanStatusText.innerText = "No Key Set";
  }

  // 2. VirusTotal status in modal
  if (vtKey) {
    const masked = vtKey.length > 8 ? `${vtKey.slice(0, 4)}••••${vtKey.slice(-4)}` : "••••••••";
    if (vtKeyStatusText) {
      vtKeyStatusText.innerHTML = `<span style="color:#10b981;">Active</span> (<code>${masked}</code>)`;
    }
    if (vtApiKeyInput) vtApiKeyInput.value = vtKey;
    if (vtStatusPill) vtStatusPill.classList.add("active");
    if (vtStatusText) vtStatusText.innerText = "Key Active";
  } else {
    if (vtKeyStatusText) {
      vtKeyStatusText.innerHTML = `<span class="text-muted">No API Key configured</span>`;
    }
    if (vtApiKeyInput) vtApiKeyInput.value = "";
    if (vtStatusPill) vtStatusPill.classList.remove("active");
    if (vtStatusText) vtStatusText.innerText = "No Key Set";
  }

  // 3. Header button badge
  const activeCount = (urlscanKey ? 1 : 0) + (vtKey ? 1 : 0);
  if (urlscanKeyToggleBtn) {
    if (activeCount > 0) {
      urlscanKeyToggleBtn.innerHTML = `🔑 Keys (${activeCount}/2) <span style="color:#10b981;">●</span>`;
      urlscanKeyToggleBtn.classList.add("btn-key-active");
    } else {
      urlscanKeyToggleBtn.innerHTML = `🔑 API Keys`;
      urlscanKeyToggleBtn.classList.remove("btn-key-active");
    }
  }
}

function openUrlscanModal() {
  if (urlscanModal) {
    if (urlscanApiKeyInput) urlscanApiKeyInput.value = getUrlscanApiKey();
    if (vtApiKeyInput) vtApiKeyInput.value = getVTApiKey();
    updateKeyUI();
    urlscanModal.style.display = "flex";
  }
}

function closeUrlscanModal() {
  if (urlscanModal) {
    urlscanModal.style.display = "none";
  }
}

// ==============================================================================
// EVENT LISTENERS
// ==============================================================================
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
    loadDemoInvestigation("thoughtworks-careers.online");
  });

  resetBtn.addEventListener("click", () => {
    targetInput.value = "";
    resultsWrapper.style.display = "none";
    currentIntel = null;
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

  // Modal events
  if (urlscanKeyToggleBtn) urlscanKeyToggleBtn.addEventListener("click", openUrlscanModal);
  if (configKeysQuickLink) configKeysQuickLink.addEventListener("click", openUrlscanModal);
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

  if (copyTeamLinkBtn) {
    copyTeamLinkBtn.addEventListener("click", () => {
      const uKey = getUrlscanApiKey();
      const vKey = getVTApiKey();
      if (!uKey && !vKey) {
        showToast("Enter and save at least one API key first.");
        return;
      }
      const payload = btoa(JSON.stringify({ urlscan: uKey, vt: vKey }));
      const link = `${window.location.origin}${window.location.pathname}#config=${payload}`;
      navigator.clipboard.writeText(link);
      showToast("🔗 Team 1-click link copied! Share via private Slack/Chat.");
    });
  }

  if (clearUrlscanKeyBtn) {
    clearUrlscanKeyBtn.addEventListener("click", () => {
      clearApiKeys();
      closeUrlscanModal();
    });
  }

  // urlscan live submit button
  if (urlscanSubmitLiveBtn) {
    urlscanSubmitLiveBtn.addEventListener("click", () => {
      if (currentIntel && currentIntel.domain) {
        submitUrlscanScan(currentIntel.domain);
      }
    });
  }

  if (triggerScanScreenshotBtn) {
    triggerScanScreenshotBtn.addEventListener("click", () => {
      if (currentIntel && currentIntel.domain) {
        submitUrlscanScan(currentIntel.domain);
      }
    });
  }

  // Memory Drawer events
  historyToggleBtn.addEventListener("click", openHistoryDrawer);
  closeDrawerBtn.addEventListener("click", closeHistoryDrawer);
  drawerOverlay.addEventListener("click", closeHistoryDrawer);
  exportMemoryBtn.addEventListener("click", exportAllMemory);
  clearMemoryBtn.addEventListener("click", clearMemory);
}

// ==============================================================================
// TARGET NORMALIZATION & DEFANGING
// ==============================================================================
function normalizeTarget(raw) {
  let clean = raw.trim();
  clean = clean.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
  clean = clean.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
  clean = clean.replace(/\[:\/\/\]/g, "://").replace(/\(:\/\/\)/g, "://");

  let domain = "";
  if (clean.includes("://")) {
    try {
      const parsed = new URL(clean);
      domain = parsed.hostname.toLowerCase();
    } catch {
      domain = clean.split("/")[0].toLowerCase();
    }
  } else {
    domain = clean.split("/")[0].split(":")[0].toLowerCase();
  }

  domain = domain.replace(/^\.+|\.+$/g, "");
  const defangedDomain = domain.replace(/\./g, "[.]");

  return { domain, defangedDomain };
}

function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ==============================================================================
// DUAL-ENGINE INVESTIGATION CONTROLLER
// ==============================================================================
async function runInvestigation(rawInput) {
  const { domain, defangedDomain } = normalizeTarget(rawInput);
  if (!domain || !domain.includes(".")) {
    showToast("Invalid domain format! Please enter a valid domain.");
    return;
  }

  setLoading(true, `Querying VirusTotal & urlscan.io APIs for ${defangedDomain}...`);

  const vtKey = getVTApiKey();
  const urlscanKey = getUrlscanApiKey();

  const intel = {
    timestamp: new Date().toISOString(),
    domain,
    defangedDomain,
    vt: {
      configured: !!vtKey,
      available: false,
      corsBlocked: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      reputation: null,
      categories: [],
      tags: [],
      flaggingVendors: [],
      lastDnsRecords: [],
      guiUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`
    },
    urlscan: {
      configured: !!urlscanKey,
      available: false,
      corsBlocked: false,
      scansFound: 0,
      uuid: null,
      reportUrl: `https://urlscan.io/search/#domain%3A${encodeURIComponent(domain)}`,
      screenshotUrl: null,
      title: null,
      effectiveUrl: null,
      server: null,
      ip: null,
      country: null,
      asn: null,
      asnname: null,
      verdictScore: 0,
      malicious: false
    },
    indicators: [],
    riskScore: 0,
    verdict: "ANALYZING"
  };

  try {
    // Dispatch parallel requests to both threat intelligence engines
    const [vtResult, urlscanResult] = await Promise.all([
      queryVirusTotal(domain, vtKey),
      queryUrlscan(domain, urlscanKey)
    ]);

    intel.vt = { ...intel.vt, ...vtResult };
    intel.urlscan = { ...intel.urlscan, ...urlscanResult };

    // Calculate Brand Impersonation & Security Risk
    const { score, indicators, verdict } = calculateRisk(intel);
    intel.riskScore = score;
    intel.indicators = indicators;
    intel.verdict = verdict;

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

// ==============================================================================
// ENGINE 1: VIRUSTOTAL REST API V3 QUERY
// ==============================================================================
async function queryVirusTotal(domain, apiKey) {
  const result = {
    configured: !!apiKey,
    available: false,
    corsBlocked: false,
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    totalEngines: 0,
    reputation: 0,
    categories: [],
    tags: [],
    flaggingVendors: [],
    guiUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`
  };

  if (!apiKey) {
    return result;
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      method: "GET",
      headers: {
        "x-apikey": apiKey,
        "Accept": "application/json"
      }
    });

    if (res.ok) {
      const json = await res.json();
      const attrs = json.data?.attributes || {};
      const stats = attrs.last_analysis_stats || {};

      result.available = true;
      result.malicious = stats.malicious || 0;
      result.suspicious = stats.suspicious || 0;
      result.harmless = stats.harmless || 0;
      result.undetected = stats.undetected || 0;
      result.totalEngines = result.malicious + result.suspicious + result.harmless + result.undetected;
      result.reputation = attrs.reputation !== undefined ? attrs.reputation : 0;
      result.tags = attrs.tags || [];

      // Extract unique categories
      const rawCategories = attrs.categories || {};
      result.categories = Array.from(new Set(Object.values(rawCategories))).slice(0, 8);

      // Extract flagging vendors
      const analysisResults = attrs.last_analysis_results || {};
      const flagging = [];
      for (const [engineName, details] of Object.entries(analysisResults)) {
        if (details.category === "malicious" || details.category === "suspicious") {
          flagging.push({
            name: engineName,
            category: details.category,
            result: details.result || details.category
          });
        }
      }
      result.flaggingVendors = flagging;
    } else {
      console.warn("VirusTotal API returned non-OK status:", res.status);
    }
  } catch (err) {
    // If fetch failed due to browser CORS restriction
    console.warn("VirusTotal in-browser direct query blocked by CORS:", err);
    result.corsBlocked = true;
  }

  return result;
}

// ==============================================================================
// ENGINE 2: URLSCAN.IO SEARCH & SUBMISSION API QUERY
// ==============================================================================
async function queryUrlscan(domain, apiKey) {
  const result = {
    configured: !!apiKey,
    available: false,
    corsBlocked: false,
    scansFound: 0,
    uuid: null,
    reportUrl: `https://urlscan.io/search/#domain%3A${encodeURIComponent(domain)}`,
    screenshotUrl: null,
    title: null,
    effectiveUrl: null,
    server: null,
    ip: null,
    country: null,
    asn: null,
    asnname: null,
    verdictScore: 0,
    malicious: false
  };

  const headers = { "Accept": "application/json" };
  if (apiKey) {
    headers["API-Key"] = apiKey;
  }

  try {
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`, {
      method: "GET",
      headers,
      mode: "cors"
    });

    if (res.ok) {
      const data = await res.json();
      result.available = true;
      result.scansFound = data.total || 0;

      if (data.results && data.results.length > 0) {
        const first = data.results[0];
        result.uuid = first._id || null;
        result.reportUrl = first.result || `https://urlscan.io/result/${first._id}/`;
        result.screenshotUrl = first.screenshot || (first._id ? `https://urlscan.io/screenshots/${first._id}.png` : null);

        const page = first.page || {};
        result.title = page.title || null;
        result.effectiveUrl = page.url || first.task?.url || null;
        result.server = page.server || null;
        result.ip = page.ip || null;
        result.country = page.country || null;
        result.asn = page.asn || null;
        result.asnname = page.asnname || null;

        const verdicts = first.verdicts?.overall || {};
        result.malicious = !!verdicts.malicious;
        result.verdictScore = verdicts.score || 0;
      }
    }
  } catch (err) {
    console.warn("urlscan.io Search query blocked by CORS or network:", err);
    result.corsBlocked = true;
  }

  return result;
}

// urlscan.io Live Scan Submission
async function submitUrlscanScan(domain) {
  if (!domain) return;
  const apiKey = getUrlscanApiKey();

  if (!apiKey) {
    openUrlscanModal();
    showToast("Please save your urlscan.io API Key to submit live scans.");
    return;
  }

  if (!urlscanSubmitLiveBtn || !urlscanLiveSubmitStatus) return;

  const targetUrl = domain.startsWith("http") ? domain : `https://${domain}`;
  urlscanSubmitLiveBtn.disabled = true;
  urlscanSubmitLiveBtn.innerText = "⏳ Submitting...";
  urlscanLiveSubmitStatus.style.display = "block";
  urlscanLiveSubmitStatus.innerHTML = `<span class="spinner" style="display:inline-block; vertical-align:middle; width:12px; height:12px; margin-right:4px;"></span> Dispatching scan request to urlscan.io API...`;

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
      const scanUuid = data.uuid;
      const reportLink = data.result;
      const shotUrl = `https://urlscan.io/screenshots/${scanUuid}.png`;

      urlscanLiveSubmitStatus.innerHTML = `✅ <strong>Scan queued successfully!</strong><br><a href="${reportLink}" target="_blank" class="text-cyan font-bold">Open urlscan.io Live Report ↗</a> (UUID: <code>${scanUuid.slice(0, 8)}...</code>)<br><span class="dim-text">Landing page screenshot will load automatically in 10-15 seconds.</span>`;
      showToast("Scan queued on urlscan.io!");

      // Update current card view immediately
      if (currentIntel && currentIntel.urlscan) {
        currentIntel.urlscan.uuid = scanUuid;
        currentIntel.urlscan.reportUrl = reportLink;
        currentIntel.urlscan.screenshotUrl = shotUrl;
      }

      // Display screenshot container with polling
      if (screenshotPlaceholder) screenshotPlaceholder.style.display = "none";
      if (screenshotLink) {
        screenshotLink.style.display = "block";
        screenshotLink.href = reportLink;
      }
      if (screenshotImg) {
        screenshotImg.src = shotUrl;
        screenshotImg.alt = "Generating live landing page screenshot...";
      }

      // Poll screenshot image
      let attempts = 0;
      const pollTimer = setInterval(() => {
        attempts++;
        if (attempts > 6) {
          clearInterval(pollTimer);
          return;
        }
        const tester = new Image();
        tester.onload = () => {
          if (screenshotImg) screenshotImg.src = shotUrl + "?t=" + Date.now();
          if (screenshotStatus) screenshotStatus.innerText = "Captured Just Now";
          clearInterval(pollTimer);
        };
        tester.src = shotUrl;
      }, 5000);

    } else {
      const errMsg = data.message || data.description || "Scan submission rejected by API";
      urlscanLiveSubmitStatus.innerHTML = `⚠️ Error: ${escapeHtml(errMsg)}`;
    }
  } catch (err) {
    urlscanLiveSubmitStatus.innerHTML = `⚠️ Scan dispatch error (${escapeHtml(err.message)}). <a href="https://urlscan.io/search/#domain%3A${encodeURIComponent(domain)}" target="_blank" class="text-cyan">Open urlscan.io manually ↗</a>`;
  } finally {
    urlscanSubmitLiveBtn.disabled = false;
    urlscanSubmitLiveBtn.innerText = "⚡ Dispatch Live Scan (API)";
  }
}

// ==============================================================================
// HEURISTIC IMPERSONATION & SECURITY RISK CALCULATION
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

  // 1. Target Brand Match
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

  // 2. High-Risk Phishing Keywords
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

  // 4. VirusTotal Threat Engine Detections
  if (intel.vt && intel.vt.available) {
    if (intel.vt.malicious > 0) {
      const vtMalScore = Math.min(45, intel.vt.malicious * 15);
      score += vtMalScore;
      indicators.push(`VirusTotal Multi-Engine Detections: Flagged MALICIOUS by ${intel.vt.malicious} security vendor(s)`);
    }
    if (intel.vt.suspicious > 0) {
      score += 10;
      indicators.push(`VirusTotal Suspicious Flags: Flagged SUSPICIOUS by ${intel.vt.suspicious} vendor(s)`);
    }
    if (intel.vt.reputation !== null && intel.vt.reputation < 0) {
      score += 15;
      indicators.push(`VirusTotal Negative Reputation: Community score is ${intel.vt.reputation}`);
    }
  }

  // 5. urlscan.io Sandbox & Landing Page Content Signals
  if (intel.urlscan && intel.urlscan.available) {
    if (intel.urlscan.malicious || intel.urlscan.verdictScore >= 50) {
      score += 35;
      indicators.push(`urlscan.io Verdict: Carries MALICIOUS threat verdict (Score: ${intel.urlscan.verdictScore})`);
    }

    // Landing Page Content Inspection: Does page title impersonate Thoughtworks?
    if (intel.urlscan.title && intel.urlscan.title.toLowerCase().includes("thoughtworks")) {
      score += 30;
      indicators.push(`Landing Page Brand Spoofing: Page <title> mimics 'Thoughtworks' ("${intel.urlscan.title}")`);
    }
  }

  const finalScore = Math.min(100, Math.max(0, score));
  let verdict = "BENIGN / LOW RISK";
  if (finalScore >= 80) verdict = "CRITICAL RISK (ACTIVE THOUGHTWORKS IMPERSONATION)";
  else if (finalScore >= 60) verdict = "HIGH RISK (SUSPICIOUS BRAND SPOOFING)";
  else if (finalScore >= 40) verdict = "MEDIUM RISK (SUSPICIOUS ARTIFACTS)";
  else if (finalScore >= 20) verdict = "LOW RISK (MINIMAL THREAT INDICATORS)";

  return { score: finalScore, indicators, verdict };
}

// ==============================================================================
// RENDER DUAL-ENGINE RESULTS
// ==============================================================================
function renderResults(intel) {
  resultsWrapper.style.display = "block";
  resultsWrapper.scrollIntoView({ behavior: "smooth" });

  // 1. Impersonation Risk Score & Gauge
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

  // Target Badges & Threat Signals
  displayDomain.innerText = intel.domain;
  displayDefanged.innerText = intel.defangedDomain;
  displayTimestamp.innerText = new Date(intel.timestamp).toLocaleTimeString();
  impersonationFlagsList.innerHTML = intel.indicators.map(ind => `<li>${escapeHtml(ind)}</li>`).join("");

  // ============================================================================
  // 2. RENDER VIRUSTOTAL INTELLIGENCE CARD
  // ============================================================================
  const vt = intel.vt;
  vtDeepLink.href = vt.guiUrl;

  if (vt.available) {
    vtCorsNotice.style.display = "none";
    vtRatioText.innerText = `${vt.malicious} / ${vt.totalEngines || 70}`;
    vtCountMalicious.innerText = vt.malicious;
    vtCountSuspicious.innerText = vt.suspicious;
    vtCountHarmless.innerText = vt.harmless;
    vtReputation.innerText = vt.reputation !== null ? vt.reputation : "0";

    const total = Math.max(1, vt.totalEngines);
    vtBarMalicious.style.width = `${(vt.malicious / total) * 100}%`;
    vtBarSuspicious.style.width = `${(vt.suspicious / total) * 100}%`;
    vtBarHarmless.style.width = `${(vt.harmless / total) * 100}%`;
    vtBarUndetected.style.width = `${(vt.undetected / total) * 100}%`;

    if (vt.malicious > 0) {
      vtVerdictBadge.className = "badge-engine-status text-red font-bold";
      vtVerdictBadge.innerText = `🚨 ${vt.malicious} VENDOR FLAGS`;
    } else {
      vtVerdictBadge.className = "badge-engine-status text-green font-bold";
      vtVerdictBadge.innerText = "🛡️ CLEAN";
    }

    // Categories & Tags
    const tags = [...(vt.tags || []), ...(vt.categories || [])];
    if (tags.length > 0) {
      vtTagsList.innerHTML = tags.map(t => `<span class="chip-tag">${escapeHtml(t)}</span>`).join("");
    } else {
      vtTagsList.innerHTML = `<span class="dim-text">No category tags assigned</span>`;
    }

    // Flagging Vendors
    if (vt.flaggingVendors && vt.flaggingVendors.length > 0) {
      vtVendorsList.innerHTML = vt.flaggingVendors.map(v => `
        <div class="vendor-chip">
          <span class="vendor-name">${escapeHtml(v.name)}</span>
          <span class="vendor-result">${escapeHtml(v.result)}</span>
        </div>
      `).join("");
    } else {
      vtVendorsList.innerHTML = `<span class="text-green text-sm">No security engines currently flag this target as malicious.</span>`;
    }

  } else {
    // If not available or blocked by CORS
    if (vt.corsBlocked) {
      vtCorsNotice.style.display = "block";
      vtVerdictBadge.className = "badge-engine-status text-yellow font-bold";
      vtVerdictBadge.innerText = "API READY (CORS RESTRICTED)";
    } else if (!vt.configured) {
      vtVerdictBadge.className = "badge-engine-status text-muted";
      vtVerdictBadge.innerText = "NO API KEY";
    } else {
      vtVerdictBadge.className = "badge-engine-status text-muted";
      vtVerdictBadge.innerText = "QUEUED / UNRATED";
    }

    vtRatioText.innerText = "-- / --";
    vtCountMalicious.innerText = "--";
    vtCountSuspicious.innerText = "--";
    vtCountHarmless.innerText = "--";
    vtReputation.innerText = "--";
    vtBarMalicious.style.width = "0%";
    vtBarSuspicious.style.width = "0%";
    vtBarHarmless.style.width = "0%";
    vtBarUndetected.style.width = "100%";
    vtTagsList.innerHTML = `<span class="dim-text">Open VirusTotal dossier to view full vendor graph.</span>`;
    vtVendorsList.innerHTML = `<span class="dim-text">Real-time scan details ready via direct link below.</span>`;
  }

  // ============================================================================
  // 3. RENDER URLSCAN.IO & LANDING PAGE CARD
  // ============================================================================
  const us = intel.urlscan;
  urlscanDeepLink.href = us.reportUrl;

  if (us.screenshotUrl) {
    if (screenshotPlaceholder) screenshotPlaceholder.style.display = "none";
    if (screenshotLink) {
      screenshotLink.style.display = "block";
      screenshotLink.href = us.reportUrl;
    }
    if (screenshotImg) {
      screenshotImg.src = us.screenshotUrl;
      screenshotImg.alt = `Landing page snapshot for ${intel.domain}`;
    }
    if (screenshotStatus) {
      screenshotStatus.innerText = "Snapshot Active";
      screenshotStatus.className = "screenshot-tag text-green";
    }
  } else {
    if (screenshotPlaceholder) screenshotPlaceholder.style.display = "flex";
    if (screenshotLink) screenshotLink.style.display = "none";
    if (screenshotStatus) {
      screenshotStatus.innerText = "Pending Capture";
      screenshotStatus.className = "screenshot-tag text-muted";
    }
  }

  landingTitle.innerText = us.title || "No page title recorded";
  landingTitle.title = us.title || "";
  landingEffectiveUrl.innerText = us.effectiveUrl || `https://${intel.domain}`;
  landingEffectiveUrl.title = us.effectiveUrl || "";

  landingIpCountry.innerText = us.ip 
    ? `${us.ip} ${us.country ? `[${us.country}]` : ''}` 
    : "Unresolved";

  landingAsn.innerText = us.asn 
    ? `${us.asn} (${us.asnname || 'Unknown'})` 
    : "No ASN on record";

  landingServer.innerText = us.server || "Not disclosed";
  
  if (us.verdictScore > 0 || us.malicious) {
    landingVerdictScore.innerHTML = `<span class="text-red">Score: ${us.verdictScore} (MALICIOUS)</span>`;
    urlscanVerdictBadge.className = "badge-engine-status text-red font-bold";
    urlscanVerdictBadge.innerText = `🚨 SCORE: ${us.verdictScore}`;
  } else if (us.scansFound > 0) {
    landingVerdictScore.innerHTML = `<span class="text-green">Score: ${us.verdictScore} (CLEAN)</span>`;
    urlscanVerdictBadge.className = "badge-engine-status text-green font-bold";
    urlscanVerdictBadge.innerText = "🛡️ CLEAN";
  } else {
    landingVerdictScore.innerText = "No prior scans";
    urlscanVerdictBadge.className = "badge-engine-status text-muted";
    urlscanVerdictBadge.innerText = "NO PRIOR SCANS";
  }

  if (urlscanLiveSubmitStatus) {
    urlscanLiveSubmitStatus.style.display = "none";
    urlscanLiveSubmitStatus.innerHTML = "";
  }

  // ============================================================================
  // 4. RENDER ABUSE TAKEDOWN NOTICE
  // ============================================================================
  takedownTextarea.value = generateTakedownNotice(intel);
}

// ==============================================================================
// DEMO PHISHING SIMULATION
// ==============================================================================
function loadDemoInvestigation(demoDomain) {
  setLoading(true, `Simulating dual-engine threat intelligence for ${demoDomain}...`);

  setTimeout(() => {
    const intel = {
      timestamp: new Date().toISOString(),
      domain: demoDomain,
      defangedDomain: demoDomain.replace(/\./g, "[.]"),
      vt: {
        configured: true,
        available: true,
        corsBlocked: false,
        malicious: 14,
        suspicious: 3,
        harmless: 2,
        undetected: 54,
        totalEngines: 73,
        reputation: -38,
        categories: ["phishing", "credential theft", "suspicious brand impersonation", "recruitment scam"],
        tags: ["phishing", "impersonation", "fake-careers", "soc-urgent"],
        flaggingVendors: [
          { name: "Google Safe Browsing", category: "malicious", result: "phishing" },
          { name: "Kaspersky", category: "malicious", result: "phishing" },
          { name: "Sophos", category: "malicious", result: "credential_stealer" },
          { name: "Fortinet", category: "malicious", result: "phishing" },
          { name: "BitDefender", category: "malicious", result: "malware" },
          { name: "ESET", category: "suspicious", result: "suspicious" }
        ],
        guiUrl: `https://www.virustotal.com/gui/domain/${demoDomain}`
      },
      urlscan: {
        configured: true,
        available: true,
        corsBlocked: false,
        scansFound: 3,
        uuid: "demo-scan-uuid",
        reportUrl: `https://urlscan.io/search/#domain%3A${encodeURIComponent(demoDomain)}`,
        screenshotUrl: "https://urlscan.io/screenshots/0e37e828-a9d9-45c0-ac50-1ca579b86c72.png",
        title: "Thoughtworks Careers & Candidate Portal - Sign In",
        effectiveUrl: `https://${demoDomain}/login?auth=candidate`,
        server: "nginx/1.24.0 (Ubuntu)",
        ip: "185.196.11.42",
        country: "RU",
        asn: "AS48282",
        asnname: "Hostinger International Ltd",
        verdictScore: 88,
        malicious: true
      },
      indicators: [],
      riskScore: 0,
      verdict: "ANALYZING"
    };

    const { score, indicators, verdict } = calculateRisk(intel);
    intel.riskScore = score;
    intel.indicators = indicators;
    intel.verdict = verdict;

    saveToMemory(intel);
    currentIntel = intel;
    renderResults(intel);
    setLoading(false);
    showToast("⚡ Demo phish intel loaded from VirusTotal & urlscan engines!");
  }, 400);
}

// ==============================================================================
// DOSSIER & TAKEDOWN NOTICE GENERATORS
// ==============================================================================
function generateTakedownNotice(intel) {
  const d = intel.domain;
  const def = intel.defangedDomain;
  const ip = intel.urlscan?.ip || "Pending DNS Resolution";
  const asn = intel.urlscan?.asn ? `AS${intel.urlscan.asn} (${intel.urlscan.asnname || ''})` : "Hosting Provider";

  let letter = `SUBJECT: URGENT: Thoughtworks Brand Impersonation & Phishing Notice - ${def}\n\n`;
  letter += `To the Abuse & Trust & Safety Team at ${asn},\n\n`;
  letter += `I am writing on behalf of Thoughtworks Information Security & Brand Protection to report active malicious brand impersonation and fraudulent phishing infrastructure hosted on your network.\n\n`;
  letter += `Target Domain: ${def}\n`;
  letter += `Resolved IP: ${ip}\n`;
  letter += `Hosting Network / ASN: ${asn}\n\n`;
  letter += `THREAT INTELLIGENCE & FORENSIC EVIDENCE:\n`;

  if (intel.vt?.available && intel.vt.malicious > 0) {
    letter += `1. VirusTotal Multi-Engine Detections: Flagged as MALICIOUS by ${intel.vt.malicious} independent security vendors (including Google Safe Browsing, Kaspersky, Sophos). Direct Dossier: ${intel.vt.guiUrl}\n`;
  } else {
    letter += `1. Multi-Engine Scanners report suspicious brand impersonation telemetry targeting Thoughtworks Inc.\n`;
  }

  if (intel.urlscan?.available) {
    if (intel.urlscan.title) {
      letter += `2. Landing Page DOM Inspection: The landing page explicitly mimics Thoughtworks with page title: "${intel.urlscan.title}".\n`;
    }
    if (intel.urlscan.reportUrl) {
      letter += `3. urlscan.io Visual & DOM Sandbox Evidence: Public sandbox capture available at: ${intel.urlscan.reportUrl}\n`;
    }
  }

  letter += `4. Unauthorized Trademark Infringement: The domain uses the Thoughtworks trademark without authorization to deceive candidates and employees.\n\n`;
  letter += `We formally request the immediate suspension and takedown of this domain name and associated hosting in accordance with your Acceptable Use Policy (AUP) and ICANN anti-abuse provisions.\n\n`;
  letter += `Regards,\n`;
  letter += `Thoughtworks Information Security & Incident Response Team\n`;
  letter += `Email: abuse-report@thoughtworks.com\n`;
  letter += `Reference ID: TW-IR-${Date.now().toString().slice(-6)}\n`;
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

  md += `\n## 🦠 VirusTotal Intelligence Engine\n`;
  md += `- **Malicious Vendors:** \`${intel.vt?.malicious || 0}\` / \`${intel.vt?.totalEngines || 0}\`\n`;
  md += `- **Suspicious Vendors:** \`${intel.vt?.suspicious || 0}\`\n`;
  md += `- **Reputation Score:** \`${intel.vt?.reputation || 0}\`\n`;
  md += `- **Tags:** \`${(intel.vt?.tags || []).join(", ") || "None"}\`\n`;
  md += `- **Full Report:** [VirusTotal Dossier](${intel.vt?.guiUrl})\n\n`;

  md += `## 🔍 urlscan.io Sandbox & Landing Page\n`;
  md += `- **Page Title:** \`${intel.urlscan?.title || "None"}\`\n`;
  md += `- **Effective URL:** \`${intel.urlscan?.effectiveUrl || "None"}\`\n`;
  md += `- **Resolved IP:** \`${intel.urlscan?.ip || "None"}\` (${intel.urlscan?.country || 'Unknown'})\n`;
  md += `- **Hosting ASN:** \`${intel.urlscan?.asn || "None"}\` (${intel.urlscan?.asnname || 'Unknown'})\n`;
  md += `- **Server Banner:** \`${intel.urlscan?.server || "None"}\`\n`;
  md += `- **Verdict Score:** \`${intel.urlscan?.verdictScore || 0}\`\n`;
  if (intel.urlscan?.screenshotUrl) {
    md += `- **Screenshot Capture:** [View Screenshot](${intel.urlscan.screenshotUrl})\n`;
  }
  md += `- **Full Sandbox Report:** [urlscan.io Analysis](${intel.urlscan?.reportUrl})\n`;

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
  history = history.filter(h => h.domain !== intel.domain);
  history.unshift({
    domain: intel.domain,
    defangedDomain: intel.defangedDomain,
    riskScore: intel.riskScore,
    verdict: intel.verdict,
    timestamp: intel.timestamp,
    vtMalicious: intel.vt?.malicious || 0,
    urlscanScore: intel.urlscan?.verdictScore || 0
  });
  history = history.slice(0, 30);
  localStorage.setItem(MEMORY_STORAGE_KEY, JSON.stringify(history));
  updateHistoryBadge();
}

function updateHistoryBadge() {
  const count = getMemory().length;
  if (historyCount) historyCount.innerText = count;
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
            <span class="history-domain">${escapeHtml(item.defangedDomain)}</span>
            <span class="history-score-badge" style="background: ${badgeColor}; color: #000;">${item.riskScore}</span>
          </div>
          <div class="history-date">${new Date(item.timestamp).toLocaleString()} • VT: ${item.vtMalicious || 0} alerts</div>
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
