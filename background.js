// Background Service Worker for DB Security Scanner
// Handles network request interception and scan results

console.log('[Background] Service worker started');

// Store scanned data from network responses, keyed by tabId
let networkScanResults = {};

function getEmptyResults() {
  return {
    supabase: { url: null, anonKey: null, serviceKey: null, projectRef: null },
    firebase: { apiKey: null, databaseURL: null, projectId: null },
    custom: { urls: [], tokens: [] }
  };
}

// Debugger state
let debuggerEnabled = false;
let activeTabId = null;
const DEBUGGER_TAB_ID = 'debuggerTabId';

// Check if debugger is available
function isDebuggerAvailable() {
  return typeof chrome.debugger !== 'undefined';
}

// Start Chrome debugger for a tab
async function startDebugger(tabId) {
  if (!isDebuggerAvailable()) {
    console.log('[Background] Debugger API not available');
    return false;
  }

  if (debuggerEnabled && activeTabId === tabId) {
    return true;
  }

  try {
    // Stop previous debugger if active
    if (debuggerEnabled && activeTabId) {
      try {
        chrome.debugger.detach({ tabId: activeTabId });
      } catch (e) {}
    }

    // Start debugger on the tab
    await new Promise((resolve, reject) => {
      chrome.debugger.attach(
        { tabId: tabId },
        '1.3',
        () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        }
      );
    });

    // Enable Network domain
    await new Promise((resolve, reject) => {
      chrome.debugger.sendCommand(
        { tabId: tabId },
        'Network.enable',
        {},
        () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve();
          }
        }
      );
    });

    // Listen for network events
    chrome.debugger.onEvent.addListener(handleDebuggerEvent);
    chrome.debugger.onDetach.addListener(handleDebuggerDetach);

    debuggerEnabled = true;
    activeTabId = tabId;
    console.log('[Background] Debugger started for tab:', tabId);
    return true;
  } catch (e) {
    console.log('[Background] Debugger attach failed:', e.message);
    return false;
  }
}

// Stop debugger
function stopDebugger() {
  if (debuggerEnabled && activeTabId) {
    try {
      chrome.debugger.detach({ tabId: activeTabId });
    } catch (e) {}
    chrome.debugger.onEvent.removeListener(handleDebuggerEvent);
    chrome.debugger.onDetach.removeListener(handleDebuggerDetach);
    debuggerEnabled = false;
    activeTabId = null;
    console.log('[Background] Debugger stopped');
  }
}

// Handle debugger detach
function handleDebuggerDetach(debuggee, reason) {
  console.log('[Background] Debugger detached:', reason);
  debuggerEnabled = false;
  activeTabId = null;
}

// Handle debugger events
function handleDebuggerEvent(debuggee, message, params) {
  if (message === 'Network.responseReceived') {
    scanNetworkResponse(debuggee.tabId, params.response);
  } else if (message === 'Network.loadingFinished') {
    // Could capture response body here if needed
  }
}

// Scan network response
function scanNetworkResponse(tabId, response) {
  if (!response || !response.url || !tabId) return;

  if (!networkScanResults[tabId]) {
    networkScanResults[tabId] = getEmptyResults();
  }
  const results = networkScanResults[tabId];

  const url = response.url;

  // Check for Supabase in response URL
  if (url.includes('supabase.co') || url.includes('supabase.in') || url.includes('supabase.net')) {
    const urlMatch = url.match(/https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(?:co|in|net)/);
    if (urlMatch && !results.supabase.url) {
      results.supabase.url = urlMatch[0];
    }
  }

  // Check for Firebase
  if (url.includes('firebaseio.com') || url.includes('firebase.com')) {
    const urlMatch = url.match(/https?:\/\/[a-zA-Z0-9_-]+\.firebase(?:io|database)\.com/);
    if (urlMatch && !results.firebase.databaseURL) {
      results.firebase.databaseURL = urlMatch[0];
    }
  }
}

// Get response body using debugger
async function getResponseBody(tabId, requestId) {
  if (!debuggerEnabled || !isDebuggerAvailable()) return null;

  return new Promise((resolve) => {
    try {
      chrome.debugger.sendCommand(
        { tabId: tabId },
        'Network.getResponseBody',
        { requestId: requestId },
        (result) => {
          if (chrome.runtime.lastError) {
            resolve(null);
          } else {
            resolve(result);
          }
        }
      );
    } catch (e) {
      resolve(null);
    }
  });
}

// Scan header values
function scanHeaderValue(tabId, name, value) {
  if (!value || !tabId || tabId === -1) return;

  if (!networkScanResults[tabId]) {
    networkScanResults[tabId] = getEmptyResults();
  }
  const results = networkScanResults[tabId];

  // Check for Supabase URL
  if (value.includes('supabase.co') || value.includes('supabase.in') || value.includes('supabase.net')) {
    const urlMatch = value.match(/https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(?:co|in|net)/);
    if (urlMatch && !results.supabase.url) {
      results.supabase.url = urlMatch[0];
    }
  }

  // Check for JWT tokens
  if (name.toLowerCase() === 'authorization' && value.includes('eyJ')) {
    const tokenMatch = value.match(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
    if (tokenMatch && !results.supabase.anonKey) {
      results.supabase.anonKey = tokenMatch[0];
    }
  }
}

// Initialize webRequest listener
function initWebRequest() {
  if (!chrome.webRequest) {
    console.log('[Background] webRequest API not available');
    return;
  }

  try {
    chrome.webRequest.onSendHeaders.addListener(
      (requestDetails) => {
        if (requestDetails.requestHeaders) {
          for (const header of requestDetails.requestHeaders) {
            scanHeaderValue(requestDetails.tabId, header.name, header.value);
          }
        }
      },
      { urls: ['<all_urls>'] },
      ['requestHeaders']
    );
    console.log('[Background] webRequest listener activated');
  } catch (e) {
    console.log('[Background] webRequest error:', e.message);
  }
}

// Handle messages from popup/content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[Background] Received message:', message.type);

  if (message.type === 'GET_NETWORK_SCAN_RESULTS') {
    const tabId = message.tabId || sender.tab?.id;
    const results = (tabId && networkScanResults[tabId]) ? networkScanResults[tabId] : getEmptyResults();
    
    sendResponse({
      supabase: results.supabase,
      firebase: results.firebase,
      custom: results.custom
    });
  }
  else if (message.type === 'CLEAR_NETWORK_SCAN_RESULTS') {
    const tabId = message.tabId || sender.tab?.id;
    if (tabId) {
      delete networkScanResults[tabId];
    }
    sendResponse({ success: true });
  }
  else if (message.type === 'START_DEBUGGER') {
    // Start debugger for specific tab to capture network responses
    startDebugger(message.tabId).then((success) => {
      sendResponse({ success });
    });
    return true; // Async response
  }
  else if (message.type === 'STOP_DEBUGGER') {
    stopDebugger();
    sendResponse({ success: true });
  }
  else if (message.type === 'GET_RESPONSE_BODY') {
    // Get response body for a specific request
    if (debuggerEnabled && message.requestId) {
      getResponseBody(activeTabId, message.requestId).then((body) => {
        sendResponse({ body });
      });
    } else {
      sendResponse({ body: null });
    }
    return true; // Async response
  }
  else if (message.type === 'SUPABASE_SCAN_RESULTS') {
    const results = message.data;

    if (sender.tab?.id) {
      updateBadge(sender.tab.id, results);
    }

    // Store scan history
    chrome.storage.local.get(['scanHistory'], (data) => {
      const history = data.scanHistory || [];
      history.unshift({
        timestamp: Date.now(),
        url: sender.tab?.url,
        tabId: sender.tab?.id,
        detected: results.detected,
        vulnerabilityCount: results.vulnerabilities?.length || 0,
        criticalCount: results.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0
      });

      if (history.length > 100) {
        history.pop();
      }

      chrome.storage.local.set({ scanHistory: history });
    });

    sendResponse({ received: true });
  }

  return true;
});

function updateBadge(tabId, results) {
  if (!results.detected) {
    chrome.action.setBadgeText({ text: '', tabId: tabId });
    return;
  }

  const criticalCount = results.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0;
  const totalVulns = results.vulnerabilities?.length || 0;

  if (criticalCount > 0) {
    chrome.action.setBadgeText({ text: '!', tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId: tabId });
  } else if (totalVulns > 0) {
    chrome.action.setBadgeText({ text: totalVulns.toString(), tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#eab308', tabId: tabId });
  } else {
    chrome.action.setBadgeText({ text: '✓', tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#3ecf8e', tabId: tabId });
  }
}

// Extension installation
chrome.runtime.onInstalled.addListener((details) => {
  console.log('[Background] Extension installed:', details.reason);

  if (details.reason === 'install') {
    chrome.storage.local.set({
      scanHistory: [],
      settings: {
        autoScan: true,
        notifyOnCritical: true
      }
    });
  }

  initWebRequest();
});

// Handle tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    // Clear network scan results when page starts loading
    if (networkScanResults[tabId]) {
      delete networkScanResults[tabId];
    }
  }
  if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome://')) {
    chrome.action.setBadgeText({ text: '', tabId: tabId });
  }
});

// Handle tab removal
chrome.tabs.onRemoved.addListener((tabId) => {
  if (networkScanResults[tabId]) {
    delete networkScanResults[tabId];
  }
  if (activeTabId === tabId) {
    stopDebugger();
  }
});

// Handle tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url && !tab.url.startsWith('chrome://')) {
      chrome.tabs.sendMessage(activeInfo.tabId, { type: 'SCAN_PAGE' }).catch(() => {});
    }
  } catch (e) {}
});

// Initialize
initWebRequest();

console.log('[Background] Service worker ready');
