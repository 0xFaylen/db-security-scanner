// DB Security Scanner - Popup Script
(function() {
  'use strict';

  let currentConfig = { 
    dbType: null,
    url: null, 
    apiKey: null, 
    serviceKey: null,
    projectRef: null
  };
  
  let selectedDbType = 'all';
  let lastScanResults = null;

  document.addEventListener('DOMContentLoaded', init);

  // Helper function for click handlers - defined first
  function onClick(id, handler) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', handler);
  }

  async function init() {
    setupEventListeners();
    // Don't auto-scan, wait for user to click Scan button
    setStatus('ready', 'Tap Scan to start');
  }

  function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.db-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.db-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        selectedDbType = tab.dataset.db;
        if (lastScanResults) {
          displayResultsForType(lastScanResults, selectedDbType);
        } else {
          setStatus('ready', 'Tap Scan to start');
        }
      });
    });

    onClick('rescan-btn', () => { 
      lastScanResults = null; 
      scanPage(); 
    });
    onClick('manual-toggle-btn', toggleManualEntry);
    onClick('manual-connect-btn', manualConnect);
    onClick('dump-all-btn', dumpAllTables);
    onClick('dashboard-btn', openDashboard);
    onClick('copy-data-btn', copyData);
    onClick('download-data-btn', downloadData);
    onClick('close-data-btn', closeData);

    // Copy buttons for URL/Key
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.dataset.target;
        const el = document.getElementById(targetId);
        // Only copy if element exists, has content, and is visible
        if (el && el.textContent && el.textContent.trim() !== '' && el.style.display !== 'none') {
          copyToClipboard(el.textContent);
          btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
          setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
          }, 1500);
        }
      });
    });

    // Tables list - event delegation
    const tablesList = document.getElementById('tables-list');
    if (tablesList) {
      tablesList.addEventListener('click', (e) => {
        const tag = e.target.closest('.table-tag');
        if (tag && tag.dataset.table) {
          fetchTableData(tag.dataset.table);
        }
      });
    }

    // Dynamic placeholder for manual URL
    const manualDbType = document.getElementById('manual-db-type');
    const manualUrl = document.getElementById('manual-url');
    if (manualDbType && manualUrl) {
      const placeholders = {
        supabase: 'e.g., https://xxx.supabase.co',
        firebase: 'e.g., https://xxx.firebaseio.com',
        custom: 'e.g., https://api.example.com/v1'
      };
      
      // Update placeholder when DB type changes
      manualDbType.addEventListener('change', () => {
        manualUrl.placeholder = placeholders[manualDbType.value] || 'URL';
      });
      
      // Set initial placeholder safely
      manualUrl.placeholder = placeholders[manualDbType.value] || 'URL';
    }
  }

  function toggleManualEntry() {
    const manualEntry = document.getElementById('manual-entry');
    const toggleBtn = document.getElementById('manual-toggle-btn');
    if (manualEntry && toggleBtn) {
      manualEntry.classList.toggle('hidden');
      toggleBtn.textContent = manualEntry.classList.contains('hidden') ? 'Enter Manually' : 'Cancel';
    }
  }

  // ============ SCANNING ============

  async function scanPage() {
    setStatus('scanning', 'Scanning...');

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      // Start debugger to capture network responses
      try {
        await chrome.runtime.sendMessage({ type: 'START_DEBUGGER', tabId: tab.id });
      } catch (e) {
        console.log('Debugger not available:', e.message);
      }

      // Get network scan results from background script
      let networkResults = null;
      try {
        networkResults = await chrome.runtime.sendMessage({ type: 'GET_NETWORK_SCAN_RESULTS' });
      } catch (e) {}

      // Fetch and scan loaded resources (Sources files)
      let resourceResults = null;
      try {
        resourceResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: scanLoadedResources
        });
        if (resourceResults?.[0]?.result) {
          resourceResults = resourceResults[0].result;
        }
      } catch (e) {
        console.log('Resource scanning failed:', e.message);
      }

      // Try content script first
      try {
        const contentResults = await chrome.tabs.sendMessage(tab.id, { type: 'GET_RESULTS' });
        if (contentResults && hasAnyDatabaseData(contentResults)) {
          // Merge with network and resource results
          lastScanResults = mergeResults(contentResults, networkResults, resourceResults);
          displayResultsForType(lastScanResults, selectedDbType);
          return;
        }
      } catch (e) {}

      // Fallback to direct scan
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: scanForDatabases
      });

      if (results?.[0]?.result) {
        // Merge page scan with network and resource results
        lastScanResults = mergeResults(results[0].result, networkResults, resourceResults);
        displayResultsForType(lastScanResults, selectedDbType);
        return;
      }

      // If no page results but have network/resource results
      if ((networkResults && hasAnyDatabaseData(networkResults)) ||
          (resourceResults && hasAnyDatabaseData(resourceResults))) {
        lastScanResults = mergeResults(
          { supabase: {}, firebase: {}, custom: { urls: [], tokens: [] }, jwts: [] },
          networkResults,
          resourceResults
        );
        displayResultsForType(lastScanResults, selectedDbType);
        return;
      }

      showNoDetection();
    } catch (error) {
      console.error('Scan error:', error);
      showNoDetection();
    }
  }

  // Scan loaded resources (Sources files) - fetches same-origin JS bundles
  async function scanLoadedResources() {
    const results = {
      supabase: { detected: false, url: null, anonKey: null, serviceKey: null, projectRef: null },
      firebase: { detected: false, apiKey: null, databaseURL: null, projectId: null },
      custom: { urls: [], tokens: [] }
    };

    try {
      // Get all loaded resources
      const resources = performance.getEntriesByType('resource');
      const jsResources = resources.filter(r =>
        r.name.includes('.js') ||
        r.name.includes('.ts') ||
        r.name.includes('.jsx') ||
        r.name.includes('.tsx') ||
        r.name.includes('chunk') ||
        r.name.includes('bundle') ||
        r.name.includes('main') ||
        r.name.includes('app.') ||
        r.name.includes('index.')
      );

      // Limit to first 50 resources to avoid too many requests
      const resourcesToScan = jsResources.slice(0, 50);

      for (const resource of resourcesToScan) {
        try {
          // Only fetch same-origin resources
          const url = new URL(resource.name, location.href);
          if (url.origin !== location.origin) continue;

          const response = await fetch(resource.name);
          if (!response.ok) continue;

          const text = await response.text();

          // Scan for Supabase
          if (!results.supabase.url) {
            const urlMatch = text.match(/https?:\/\/([a-zA-Z0-9_-]{2,})\.supabase\.(?:co|in|net)/);
            if (urlMatch) {
              results.supabase.detected = true;
              results.supabase.url = urlMatch[0];
              results.supabase.projectRef = urlMatch[1];
            }
          }

          // Scan for Supabase keys
          if (!results.supabase.anonKey) {
            const keyPatterns = [
              /VITE_SUPABASE_ANON_KEY["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/,
              /NEXT_PUBLIC_SUPABASE_ANON_KEY["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/,
              /REACT_APP_SUPABASE_ANON_KEY["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/,
              /SUPABASE_ANON_KEY["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/,
              /supabaseAnonKey\s*=\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/,
              /anonKey\s*=\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/,
              /"VITE_SUPABASE_ANON_KEY"\s*:\s*"([^"]+)"/,
              /"SUPABASE_URL"\s*:\s*"([^"]+)"/,
              /createClient\s*\(\s*["']([^"']+supabase[^"']*)["']\s*,\s*["'](eyJ[^"']+)["']/
            ];

            for (const pattern of keyPatterns) {
              const match = text.match(pattern);
              if (match) {
                results.supabase.detected = true;
                const key = match[2] || match[1];
                if (key.startsWith('eyJ')) {
                  results.supabase.anonKey = key;
                }
                if (match[1] && match[1].includes('supabase') && !results.supabase.url) {
                  results.supabase.url = match[1];
                }
                if (results.supabase.anonKey) break;
              }
            }
          }

          // Scan for import.meta.env patterns
          if (!results.supabase.url || !results.supabase.anonKey) {
            const metaEnvMatch = text.match(/import\.meta\.env\s*=\s*\{([^}]+)\}/s);
            if (metaEnvMatch) {
              const envContent = metaEnvMatch[1];

              if (!results.supabase.url) {
                const urlVal = envContent.match(/"VITE_SUPABASE_URL"\s*:\s*"([^"]+)"/) ||
                              envContent.match(/"NEXT_PUBLIC_SUPABASE_URL"\s*:\s*"([^"]+)"/);
                if (urlVal) {
                  results.supabase.detected = true;
                  results.supabase.url = urlVal[1];
                }
              }

              if (!results.supabase.anonKey) {
                const keyVal = envContent.match(/"VITE_SUPABASE_ANON_KEY"\s*:\s*"([^"]+)"/) ||
                               envContent.match(/"NEXT_PUBLIC_SUPABASE_ANON_KEY"\s*:\s*"([^"]+)"/);
                if (keyVal) {
                  results.supabase.detected = true;
                  results.supabase.anonKey = keyVal[1];
                }
              }
            }
          }

          // Scan for service keys
          if (!results.supabase.serviceKey) {
            const serviceKeyMatch = text.match(/(?:VITE_SUPABASE_SERVICE_KEY|NEXT_PUBLIC_SUPABASE_SERVICE_KEY|serviceKey|supabaseServiceKey)["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/);
            if (serviceKeyMatch) {
              results.supabase.detected = true;
              results.supabase.serviceKey = serviceKeyMatch[1];
            }
          }

          // Scan for Firebase
          const fbApiKeyMatch = text.match(/(?:VITE_FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|firebaseApiKey|apiKey)["']?\s*[:=]\s*["']?(AIza[0-9A-Za-z_-]{35})/);
          if (fbApiKeyMatch) {
            results.firebase.detected = true;
            results.firebase.apiKey = fbApiKeyMatch[1];
          }

          const fbDbUrlMatch = text.match(/https?:\/\/([a-zA-Z0-9_-]+)\.firebase(?:io|database)\.com/);
          if (fbDbUrlMatch && !results.firebase.databaseURL) {
            results.firebase.detected = true;
            results.firebase.databaseURL = fbDbUrlMatch[0];
            results.firebase.projectId = fbDbUrlMatch[1];
          }

        } catch (e) {
          // Skip failed fetches
        }
      }
    } catch (e) {
      console.error('Resource scan error:', e);
    }

    return results;
  }

  function mergeResults(pageResults, networkResults, resourceResults) {
    // Start with page results
    const merged = JSON.parse(JSON.stringify(pageResults || {
      supabase: { detected: false },
      firebase: { detected: false },
      custom: { urls: [], tokens: [] },
      jwts: []
    }));

    // Merge Supabase results (network first, then resources)
    const supabaseSources = [networkResults?.supabase, resourceResults?.supabase];

    for (const source of supabaseSources) {
      if (!source) continue;

      if (source.url && !merged.supabase.url) {
        merged.supabase.url = source.url;
        merged.supabase.detected = true;
      }
      if (source.anonKey && !merged.supabase.anonKey) {
        merged.supabase.anonKey = source.anonKey;
        merged.supabase.detected = true;
      }
      if (source.serviceKey && !merged.supabase.serviceKey) {
        merged.supabase.serviceKey = source.serviceKey;
        merged.supabase.detected = true;
      }
      if (source.projectRef && !merged.supabase.projectRef) {
        merged.supabase.projectRef = source.projectRef;
      }
    }

    // Merge Firebase results
    const firebaseSources = [networkResults?.firebase, resourceResults?.firebase];

    for (const source of firebaseSources) {
      if (!source) continue;

      if (source.apiKey && !merged.firebase.apiKey) {
        merged.firebase.apiKey = source.apiKey;
        merged.firebase.detected = true;
      }
      if (source.databaseURL && !merged.firebase.databaseURL) {
        merged.firebase.databaseURL = source.databaseURL;
        merged.firebase.detected = true;
      }
      if (source.projectId && !merged.firebase.projectId) {
        merged.firebase.projectId = source.projectId;
      }
    }

    // Merge custom URLs
    const customUrls = new Set([
      ...(merged.custom?.urls || []),
      ...(networkResults?.custom?.urls || []),
      ...(resourceResults?.custom?.urls || [])
    ]);
    merged.custom = { urls: [...customUrls], tokens: [], detected: customUrls.size > 0 };

    return merged;
  }

  function hasAnyDatabaseData(results) {
    return results.supabase?.url || results.supabase?.anonKey || 
           results.firebase?.apiKey || results.firebase?.databaseURL ||
           (results.custom?.urls?.length > 0 && results.custom?.urls.some(isRealApiUrl));
  }

  // Main scan function - runs in page context
  function scanForDatabases() {
    const results = {
      supabase: { detected: false, url: null, anonKey: null, serviceKey: null, projectRef: null },
      firebase: { detected: false, apiKey: null, databaseURL: null, projectId: null },
      custom: { detected: false, urls: [], tokens: [] },
      jwts: []
    };

    const sources = [];
    sources.push(document.documentElement.outerHTML);
    
    document.querySelectorAll('script').forEach(s => {
      if (s.textContent) sources.push(s.textContent);
    });

    try {
      for (let i = 0; i < localStorage.length; i++) {
        sources.push(localStorage.getItem(localStorage.key(i)) || '');
      }
    } catch (e) {}

    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        sources.push(sessionStorage.getItem(sessionStorage.key(i)) || '');
      }
    } catch (e) {}

    const windowProps = ['supabase', 'supabaseClient', '_supabase', 'firebaseConfig', 'firebase', 
                         '__NEXT_DATA__', '__NUXT__', 'env', 'ENV', 'config', 'CONFIG'];
    windowProps.forEach(prop => {
      try {
        if (window[prop] !== undefined) {
          sources.push(JSON.stringify(window[prop]));
        }
      } catch (e) {}
    });

    try {
      performance.getEntriesByType('resource').forEach(entry => {
        sources.push(entry.name);
      });
    } catch (e) {}

    const allText = sources.join('\n');

    // ============ VITE import.meta.env PATTERNS ============
    // Pattern: import.meta.env = { "VITE_SUPABASE_URL": "...", "VITE_SUPABASE_ANON_KEY": "..." }
    const viteMetaEnvPattern = /import\.meta\.env\s*=\s*\{([^}]+)\}/gi;
    while ((match = viteMetaEnvPattern.exec(allText)) !== null) {
      const envContent = match[1];
      const urlMatch = envContent.match(/"VITE_SUPABASE_URL"\s*:\s*"([^"]+)"/) ||
                       envContent.match(/'VITE_SUPABASE_URL'\s*:\s*'([^']+)'/);
      const keyMatch = envContent.match(/"VITE_SUPABASE_ANON_KEY"\s*:\s*"([^"]+)"/) ||
                       envContent.match(/'VITE_SUPABASE_ANON_KEY'\s*:\s*'([^']+)'/);
      if (urlMatch || keyMatch) {
        results.supabase.detected = true;
        if (urlMatch) results.supabase.url = urlMatch[1];
        if (keyMatch) results.supabase.anonKey = keyMatch[1];
      }
    }

    // Pattern: import.meta.env.VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY
    const viteMetaPropPattern = /import\.meta\.env\.(VITE_SUPABASE_URL|VITE_SUPABASE_ANON_KEY|VITE_SUPABASE_KEY|VITE_SUPABASE_SERVICE_KEY|NEXT_PUBLIC_SUPABASE_URL|NEXT_PUBLIC_SUPABASE_ANON_KEY|REACT_APP_SUPABASE_URL|REACT_APP_SUPABASE_ANON_KEY|SUPABASE_URL|SUPABASE_ANON_KEY)\s*["']?\s*[:=]\s*["']?([^"'\s,}]+)["']?/gi;
    while ((match = viteMetaPropPattern.exec(allText)) !== null) {
      const propName = match[1].toUpperCase();
      const value = match[2].trim();
      if (propName.includes('URL')) {
        if (value.includes('supabase')) {
          results.supabase.detected = true;
          results.supabase.url = value;
        }
      } else if (propName.includes('KEY') && value.startsWith('eyJ')) {
        results.supabase.detected = true;
        if (!results.supabase.anonKey) results.supabase.anonKey = value;
      }
    }

    // ============ process.env PATTERNS ============
    // Pattern: process.env.VITE_SUPABASE_URL = "..."
    const processEnvPattern = /process\.env\.(VITE_SUPABASE_URL|VITE_SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_URL|NEXT_PUBLIC_SUPABASE_ANON_KEY|REACT_APP_SUPABASE_URL|REACT_APP_SUPABASE_ANON_KEY|SUPABASE_URL|SUPABASE_ANON_KEY|SUPABASE_KEY)\s*=\s*["']([^"']+)["']/gi;
    while ((match = processEnvPattern.exec(allText)) !== null) {
      const propName = match[1].toUpperCase();
      const value = match[2];
      if (propName.includes('URL')) {
        results.supabase.detected = true;
        results.supabase.url = value;
      } else if (propName.includes('KEY') && value.startsWith('eyJ')) {
        results.supabase.detected = true;
        if (!results.supabase.anonKey) results.supabase.anonKey = value;
      }
    }

    // Pattern: process.env.VITE_SUPABASE_URL || "" or similar
    const processEnvOrPattern = /process\.env\.(VITE_SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|REACT_APP_SUPABASE_URL)\s*\|\|[\s\S]*?["']([^"']+supabase[^"']*)["']/gi;
    while ((match = processEnvOrPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      results.supabase.url = match[1];
    }

    // ============ CONSOLE.LOG PATTERNS ============
    // Pattern: console.log("=== Supabase Configuration ===") followed by URL/Key logs
    const consoleConfigPattern = /console\.log\s*\(\s*["']=== Supabase Configuration ===["'][\s\S]*?console\.log\s*\([^)]*SUPABASE_URL[^)]*,\s*([^)]+)\)/gi;
    while ((match = consoleConfigPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
    }

    // Pattern: console.log("VITE_SUPABASE_URL:", supabaseUrl) - extract from variable
    const consoleLogUrlPattern = /console\.log\s*\([^)]*VITE_SUPABASE_URL[^)]*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi;
    while ((match = consoleLogUrlPattern.exec(allText)) !== null) {
      const varName = match[1];
      const varPattern = new RegExp(`const\\s+${varName}\\s*=\\s*["']([^"']+supabase[^"']*)["']`, 'gi');
      let varMatch;
      while ((varMatch = varPattern.exec(allText)) !== null) {
        results.supabase.detected = true;
        results.supabase.url = varMatch[1];
      }
    }

    // Pattern: Direct console.log with Supabase URL
    const consoleLogDirectUrlPattern = /console\.log\s*\([^)]*["']https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(co|in|net)["'][^)]*\)/gi;
    while ((match = consoleLogDirectUrlPattern.exec(allText)) !== null) {
      const urlInLog = match[0].match(/https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(co|in|net)/gi);
      if (urlInLog) {
        results.supabase.detected = true;
        results.supabase.url = urlInLog[0];
      }
    }

    // Pattern: console.log with anon key in output
    const consoleLogKeyPattern = /console\.log\s*\([^)]*(VITE_SUPABASE_ANON_KEY|SUPABASE_ANON_KEY|anonKey)[^)]*,\s*["']?(eyJ[^\s"']+)["']?\s*\)/gi;
    while ((match = consoleLogKeyPattern.exec(allText)) !== null) {
      const keyInLog = match[2] || match[0].match(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
      if (keyInLog) {
        results.supabase.detected = true;
        if (!results.supabase.anonKey) results.supabase.anonKey = typeof keyInLog === 'string' ? keyInLog : keyInLog[0];
      }
    }

    // ============ DIRECT VARIABLE ASSIGNMENTS ============
    // Pattern: const supabaseUrl = "https://xxx.supabase.co"
    const directUrlPattern = /(?:const|let|var)\s+(?:supabaseUrl|supabaseURL|supabase_url|SUPABASE_URL|supabaseProjectUrl|apiUrl|baseUrl|apiBaseUrl)\s*=\s*["'](https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(?:co|in|net))["']/gi;
    while ((match = directUrlPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.url) results.supabase.url = match[1];
    }

    // Pattern: const supabaseAnonKey = "eyJ..."
    const directKeyPattern = /(?:const|let|var)\s+(?:supabaseAnonKey|supabaseAnonKey|supabaseAnon_Key|supabase_key|anonKey|ANON_KEY|SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY)\s*=\s*["'](eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/gi;
    while ((match = directKeyPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.anonKey) results.supabase.anonKey = match[1];
    }

    // Pattern: window.supabaseUrl = "..."
    const windowUrlPattern = /(?:window\.)?(?:supabaseUrl|supabaseURL|SUPABASE_URL)\s*=\s*["'](https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(?:co|in|net))["']/gi;
    while ((match = windowUrlPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.url) results.supabase.url = match[1];
    }

    // Pattern: window.supabaseAnonKey = "..."
    const windowKeyPattern = /(?:window\.)?(?:supabaseAnonKey|anonKey|SUPABASE_ANON_KEY)\s*=\s*["'](eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/gi;
    while ((match = windowKeyPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.anonKey) results.supabase.anonKey = match[1];
    }

    // ============ createClient PATTERNS ============
    // Pattern: createClient(supabaseUrl, supabaseAnonKey) - extract from arguments
    const createClientPattern = /createClient\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi;
    while ((match = createClientPattern.exec(allText)) !== null) {
      const urlVar = match[1];
      const keyVar = match[2];
      
      // Find URL variable value
      const urlVarPattern = new RegExp(`(?:const|let|var)\\s+${urlVar}\\s*=\\s*["'](https?://[^"']+supabase[^"']*)["']`, 'gi');
      let urlVarMatch;
      while ((urlVarMatch = urlVarPattern.exec(allText)) !== null) {
        results.supabase.detected = true;
        if (!results.supabase.url) results.supabase.url = urlVarMatch[1];
      }
      
      // Find key variable value
      const keyVarPattern = new RegExp(`(?:const|let|var)\\s+${keyVar}\\s*=\\s*["'](eyJ[^"']+)["']`, 'gi');
      let keyVarMatch;
      while ((keyVarMatch = keyVarPattern.exec(allText)) !== null) {
        results.supabase.detected = true;
        if (!results.supabase.anonKey) results.supabase.anonKey = keyVarMatch[1];
      }
    }

    // Pattern: createClient with direct string URL
    const createClientDirectPattern = /createClient\s*\(\s*["'](https?:\/\/[^"']+supabase[^"']*)["']\s*,\s*["'](eyJ[^"']+)["']\s*\)/gi;
    while ((match = createClientDirectPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.url) results.supabase.url = match[1];
      if (!results.supabase.anonKey) results.supabase.anonKey = match[2];
    }

    // ============ .env FILE CONTENT PATTERNS ============
    // Pattern: VITE_SUPABASE_URL=https://xxx.supabase.co (in any text)
    const envFilePattern = /(?:VITE_|NEXT_PUBLIC_|REACT_APP_)?SUPABASE(?:_URL|_ANON_KEY|_KEY)?\s*=\s*(?:["']?)?(https?:\/\/[a-zA-Z0-9_-]+\.supabase\.(?:co|in|net)|eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/gi;
    while ((match = envFilePattern.exec(allText)) !== null) {
      const value = match[1];
      if (value.includes('supabase')) {
        results.supabase.detected = true;
        if (!results.supabase.url) results.supabase.url = value;
      } else if (value.startsWith('eyJ')) {
        results.supabase.detected = true;
        if (!results.supabase.anonKey) results.supabase.anonKey = value;
      }
    }

    // ============ WINDOW.__ENV__ / __NEXT_DATA__ PATTERNS ============
    // Pattern: window.__ENV__ = { VITE_SUPABASE_URL: "...", VITE_SUPABASE_ANON_KEY: "..." }
    const windowEnvPattern = /window\.__ENV__\s*=\s*\{([^}]+)\}/gi;
    while ((match = windowEnvPattern.exec(allText)) !== null) {
      const envContent = match[1];
      const urlMatch = envContent.match(/VITE_SUPABASE_URL["']?\s*:\s*["']?([^"'\s,}]+)/);
      const keyMatch = envContent.match(/VITE_SUPABASE_ANON_KEY["']?\s*:\s*["']?([^"'\s,}]+)/);
      if (urlMatch || keyMatch) {
        results.supabase.detected = true;
        if (urlMatch) results.supabase.url = urlMatch[1];
        if (keyMatch && keyMatch[1].startsWith('eyJ')) results.supabase.anonKey = keyMatch[1];
      }
    }

    // Pattern: window.__NEXT_DATA__ with env or config
    const nextDataPattern = /window\.__NEXT_DATA__\s*=\s*\{([^}]+)\}/gi;
    while ((match = nextDataPattern.exec(allText)) !== null) {
      const nextContent = match[1];
      const envMatch = nextContent.match(/"env"\s*:\s*\{([^}]+)\}/);
      if (envMatch) {
        const envContent = envMatch[1];
        const urlMatch = envContent.match(/(?:NEXT_PUBLIC_)?SUPABASE_URL["']?\s*:\s*["']?([^"'\s,}]+)/);
        const keyMatch = envContent.match(/(?:NEXT_PUBLIC_)?SUPABASE_ANON_KEY["']?\s*:\s*["']?([^"'\s,}]+)/);
        if (urlMatch || keyMatch) {
          results.supabase.detected = true;
          if (urlMatch) results.supabase.url = urlMatch[1];
          if (keyMatch) results.supabase.anonKey = keyMatch[1];
        }
      }
    }

    // Pattern: globalThis.__ENV__
    const globalEnvPattern = /globalThis\.__ENV__\s*=\s*\{([^}]+)\}/gi;
    while ((match = globalEnvPattern.exec(allText)) !== null) {
      const envContent = match[1];
      const urlMatch = envContent.match(/(?:VITE_|NEXT_PUBLIC_)?SUPABASE_URL["']?\s*:\s*["']?([^"'\s,}]+)/);
      const keyMatch = envContent.match(/(?:VITE_|NEXT_PUBLIC_)?SUPABASE_ANON_KEY["']?\s*:\s*["']?([^"'\s,}]+)/);
      if (urlMatch || keyMatch) {
        results.supabase.detected = true;
        if (urlMatch) results.supabase.url = urlMatch[1];
        if (keyMatch && keyMatch[1].startsWith('eyJ')) results.supabase.anonKey = keyMatch[1];
      }
    }

    // Pattern: globalThis.process.env
    const globalProcessEnvPattern = /globalThis\.process\.env\s*=\s*\{([^}]+)\}/gi;
    while ((match = globalProcessEnvPattern.exec(allText)) !== null) {
      const envContent = match[1];
      const urlMatch = envContent.match(/(?:VITE_|NEXT_PUBLIC_|REACT_APP_)?SUPABASE_URL["']?\s*:\s*["']?([^"'\s,}]+)/);
      const keyMatch = envContent.match(/(?:VITE_|NEXT_PUBLIC_|REACT_APP_)?SUPABASE_ANON_KEY["']?\s*:\s*["']?([^"'\s,}]+)/);
      if (urlMatch || keyMatch) {
        results.supabase.detected = true;
        if (urlMatch) results.supabase.url = urlMatch[1];
        if (keyMatch) results.supabase.anonKey = keyMatch[1];
      }
    }

    // Pattern: import.meta.env in script tags (raw text)
    const rawMetaEnvPattern = /import\.meta\.env\s*=\s*\{([^}]{0,500})\}/gi;
    while ((match = rawMetaEnvPattern.exec(allText)) !== null) {
      const envContent = match[1];
      const urlMatch = envContent.match(/(?:VITE_|NEXT_PUBLIC_)?SUPABASE_URL["']?\s*[:=]\s*["']?([^"'\s,}]+)/);
      const keyMatch = envContent.match(/(?:VITE_|NEXT_PUBLIC_)?SUPABASE_ANON_KEY["']?\s*[:=]\s*["']?([^"'\s,}]+)/);
      if (urlMatch || keyMatch) {
        results.supabase.detected = true;
        if (urlMatch && urlMatch[1].includes('supabase')) results.supabase.url = urlMatch[1];
        if (keyMatch && keyMatch[1].startsWith('eyJ')) results.supabase.anonKey = keyMatch[1];
      }
    }

    // Pattern: TypeScript declare global or interface
    const tsDeclarePattern = /(?:declare|interface)\s+(?:Env|ProcessEnv|WindowEnv)\s*\{([^}]+)\}/gi;
    while ((match = tsDeclarePattern.exec(allText)) !== null) {
      const declareContent = match[1];
      const urlMatch = declareContent.match(/(?:VITE_|NEXT_PUBLIC_)?SUPABASE_URL\??\s*:\s*["']?([^"'\s;]+)/);
      const keyMatch = declareContent.match(/(?:VITE_|NEXT_PUBLIC_)?SUPABASE_ANON_KEY\??\s*:\s*["']?([^"'\s;]+)/);
      if (urlMatch || keyMatch) {
        results.supabase.detected = true;
        if (urlMatch) results.supabase.url = urlMatch[1];
        if (keyMatch && keyMatch[1].startsWith('eyJ')) results.supabase.anonKey = keyMatch[1];
      }
    }

    // Pattern: Data attributes in HTML
    const dataAttrPattern = /data-(?:supabase-url|supabase-url|supabase-url)\s*=\s*["']([^"']+supabase[^"']*)["']/gi;
    while ((match = dataAttrPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.url) results.supabase.url = match[1];
    }

    // Pattern: JSON config in script tags
    const jsonConfigPattern = /<script[^>]*type\s*=\s*["']application\/json["'][^>]*>([^<]+)<\/script>/gi;
    while ((match = jsonConfigPattern.exec(allText)) !== null) {
      try {
        const jsonContent = JSON.parse(match[1]);
        const urlVal = jsonContent.VITE_SUPABASE_URL || jsonContent.NEXT_PUBLIC_SUPABASE_URL || jsonContent.SUPABASE_URL;
        const keyVal = jsonContent.VITE_SUPABASE_ANON_KEY || jsonContent.NEXT_PUBLIC_SUPABASE_ANON_KEY || jsonContent.SUPABASE_ANON_KEY;
        if (urlVal || keyVal) {
          results.supabase.detected = true;
          if (urlVal) results.supabase.url = urlVal;
          if (keyVal && keyVal.startsWith('eyJ')) results.supabase.anonKey = keyVal;
        }
      } catch (e) {}
    }

    // ============ Supabase URLs ============
    const supabaseUrlPattern = /https?:\/\/([a-zA-Z0-9_-]{2,})\.supabase\.(co|in|net)/gi;
    while ((match = supabaseUrlPattern.exec(allText)) !== null) {
      results.supabase.detected = true;
      if (!results.supabase.url) {
        results.supabase.url = match[0];
        results.supabase.projectRef = match[1];
      }
    }

    // ============ FIREBASE CONFIG PATTERNS ============
    // Vite import.meta.env for Firebase
    const viteFirebaseMetaPattern = /import\.meta\.env\s*=\s*\{([^}]+)\}/gi;
    while ((match = viteFirebaseMetaPattern.exec(allText)) !== null) {
      const envContent = match[1];
      const apiKeyMatch = envContent.match(/"VITE_FIREBASE_API_KEY"\s*:\s*"([^"]+)"/) ||
                          envContent.match(/'VITE_FIREBASE_API_KEY'\s*:\s*'([^']+)'/);
      const dbUrlMatch = envContent.match(/"VITE_FIREBASE_DATABASE_URL"\s*:\s*"([^"]+)"/) ||
                         envContent.match(/'VITE_FIREBASE_DATABASE_URL'\s*:\s*'([^']+)'/);
      const projIdMatch = envContent.match(/"VITE_FIREBASE_PROJECT_ID"\s*:\s*"([^"]+)"/) ||
                         envContent.match(/'VITE_FIREBASE_PROJECT_ID'\s*:\s*'([^']+)'/);
      if (apiKeyMatch || dbUrlMatch || projIdMatch) {
        results.firebase.detected = true;
        if (apiKeyMatch) results.firebase.apiKey = apiKeyMatch[1];
        if (dbUrlMatch) results.firebase.databaseURL = dbUrlMatch[1];
        if (projIdMatch) results.firebase.projectId = projIdMatch[1];
      }
    }

    // process.env for Firebase
    const firebaseEnvPattern = /process\.env\.(VITE_FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|VITE_FIREBASE_DATABASE_URL|NEXT_PUBLIC_FIREBASE_DATABASE_URL|REACT_APP_FIREBASE_DATABASE_URL|VITE_FIREBASE_PROJECT_ID|NEXT_PUBLIC_FIREBASE_PROJECT_ID|REACT_APP_FIREBASE_PROJECT_ID)\s*=\s*["']([^"']+)["']/gi;
    while ((match = firebaseEnvPattern.exec(allText)) !== null) {
      const propName = match[1].toUpperCase();
      const value = match[2];
      results.firebase.detected = true;
      if (propName.includes('API_KEY')) results.firebase.apiKey = value;
      if (propName.includes('DATABASE_URL')) results.firebase.databaseURL = value;
      if (propName.includes('PROJECT_ID')) results.firebase.projectId = value;
    }

    // Firebase config object in code
    const firebaseConfigPattern = /(?:const|let|var)\s*(?:firebaseConfig|firebaseConfigObj|firebaseConfigData)\s*=\s*\{([^}]+)\}/gi;
    while ((match = firebaseConfigPattern.exec(allText)) !== null) {
      const configContent = match[1];
      const apiKeyMatch = configContent.match(/apiKey\s*:\s*["']([^"']+)["']/);
      const dbUrlMatch = configContent.match(/databaseURL\s*:\s*["']([^"']+)["']/);
      const projIdMatch = configContent.match(/projectId\s*:\s*["']([^"']+)["']/);
      if (apiKeyMatch || dbUrlMatch || projIdMatch) {
        results.firebase.detected = true;
        if (apiKeyMatch && apiKeyMatch[1].startsWith('AIza')) results.firebase.apiKey = apiKeyMatch[1];
        if (dbUrlMatch) results.firebase.databaseURL = dbUrlMatch[1];
        if (projIdMatch) results.firebase.projectId = projIdMatch[1];
      }
    }

    // Direct Firebase variable assignments
    const firebaseDirectPattern = /(?:const|let|var)\s+(?:firebaseApiKey|apiKey|firebaseDatabaseUrl|databaseUrl|firebaseProjectId|projectId)\s*=\s*["']([^"']+)["']/gi;
    while ((match = firebaseDirectPattern.exec(allText)) !== null) {
      const value = match[1];
      if (value.startsWith('AIza')) {
        results.firebase.detected = true;
        if (!results.firebase.apiKey) results.firebase.apiKey = value;
      } else if (value.includes('firebaseio') || value.includes('firebase.com')) {
        results.firebase.detected = true;
        if (!results.firebase.databaseURL) results.firebase.databaseURL = value;
      } else if (!results.firebase.projectId) {
        results.firebase.detected = true;
        results.firebase.projectId = value;
      }
    }

    // initializeApp with config
    const initializeAppPattern = /initializeApp\s*\(\s*\{([^}]+)\}\s*\)/gi;
    while ((match = initializeAppPattern.exec(allText)) !== null) {
      const configContent = match[1];
      const apiKeyMatch = configContent.match(/apiKey\s*:\s*["']([^"']+)["']/);
      const dbUrlMatch = configContent.match(/databaseURL\s*:\s*["']([^"']+)["']/);
      if (apiKeyMatch || dbUrlMatch) {
        results.firebase.detected = true;
        if (apiKeyMatch && apiKeyMatch[1].startsWith('AIza')) results.firebase.apiKey = apiKeyMatch[1];
        if (dbUrlMatch) results.firebase.databaseURL = dbUrlMatch[1];
      }
    }

    // Firebase URLs
    const firebaseUrlPattern = /https?:\/\/([a-zA-Z0-9_-]+)\.firebase(io|database)\.com/gi;
    while ((match = firebaseUrlPattern.exec(allText)) !== null) {
      results.firebase.detected = true;
      if (!results.firebase.databaseURL) {
        results.firebase.databaseURL = match[0];
        results.firebase.projectId = match[1];
      }
    }

    // Firebase API Keys
    const firebaseKeyPattern = /(AIza[0-9A-Za-z_-]{35})/g;
    while ((match = firebaseKeyPattern.exec(allText)) !== null) {
      results.firebase.detected = true;
      results.firebase.apiKey = match[1];
    }

    // JWT tokens
    const jwtPattern = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
    const foundJwts = allText.match(jwtPattern) || [];
    const uniqueJwts = [...new Set(foundJwts)];
    
    uniqueJwts.forEach(jwt => {
      try {
        const parts = jwt.split('.');
        if (parts.length !== 3) return;
        
        let padded = parts[1];
        while (padded.length % 4 !== 0) padded += '=';
        const payload = JSON.parse(atob(padded));
        
        if (payload.iss?.includes('supabase') || payload.role === 'anon' || payload.role === 'service_role' || payload.ref) {
          results.supabase.detected = true;
          
          if (payload.role === 'service_role') {
            results.supabase.serviceKey = jwt;
          } else {
            results.supabase.anonKey = results.supabase.anonKey || jwt;
          }
          
          if (payload.ref && !results.supabase.url) {
            results.supabase.url = `https://${payload.ref}.supabase.co`;
            results.supabase.projectRef = payload.ref;
          }
        }
        
        if (payload.aud?.includes('firebase') || payload.firebase) {
          results.firebase.detected = true;
        }
        
        results.jwts.push({ jwt, payload, type: 'unknown' });
      } catch (e) {}
    });

    // Custom APIs (only if no major DB found)
    if (!results.supabase.detected && !results.firebase.detected) {
      const apiPatterns = [
        /https?:\/\/[^\s"'<>]+api[^\s"'<>]*/gi,
        /https?:\/\/[^\s"'<>]+\/api\/v\d+[^\s"'<>]*/gi
      ];

      apiPatterns.forEach(pattern => {
        while ((match = pattern.exec(allText)) !== null) {
          const url = match[0].replace(/["']/g, '');
          if (isRealApiUrl(url) && !results.custom.urls.includes(url)) {
            results.custom.urls.push(url);
            results.custom.detected = true;
          }
        }
      });
    }

    return results;
  }

  function isRealApiUrl(url) {
    if (!url) return false;
    
    const garbagePatterns = [
      /googleapis\.com\/storage\//, /cloudinary\.com/, /cdn\./,
      /google-analytics\.com/, /facebook\.com\/tr/, / DoubleClick\.net/,
      /sentry\.io/, /hotjar\.com/, /mixpanel\.com/, /segment\.io/,
      /intercom\.io/, /stripe\.com\/js/, /paypal\.com\/js/,
      /googletagmanager\.com/, /gpt-engineer/, /aws\.amazon\.com\/s3/,
      /netlify\.com/, /vercel\.com/, /github\.com\/assets/,
      /raw\.githubusercontent/
    ];
    
    for (const pattern of garbagePatterns) {
      if (pattern.test(url)) return false;
    }
    
    return true;
  }

  // ============ DISPLAY ============

  function getBestMatchType(results) {
    if (results.supabase?.url || results.supabase?.anonKey) return 'supabase';
    if (results.firebase?.databaseURL || results.firebase?.apiKey) return 'firebase';
    if (results.custom?.urls?.length > 0) return 'custom';
    return null;
  }

  function displayResultsForType(results, filterType) {
    let typeData = null;
    let dbType = null;

    if (filterType === 'supabase') {
      if (results.supabase?.url || results.supabase?.anonKey) {
        dbType = 'supabase';
        typeData = results.supabase;
      }
    } else if (filterType === 'firebase') {
      if (results.firebase?.databaseURL || results.firebase?.apiKey) {
        dbType = 'firebase';
        typeData = results.firebase;
      }
    } else if (filterType === 'custom') {
      if (results.custom?.urls?.length > 0) {
        dbType = 'custom';
        typeData = results.custom;
      }
    } else {
      dbType = getBestMatchType(results);
      if (dbType) typeData = results[dbType];
    }

    if (!typeData) {
      showNoDetection();
      return;
    }

    if (dbType === 'supabase') {
      currentConfig = {
        dbType: 'supabase',
        url: typeData.url,
        apiKey: typeData.anonKey || typeData.serviceKey,
        serviceKey: typeData.serviceKey,
        projectRef: typeData.projectRef
      };
    } else if (dbType === 'firebase') {
      currentConfig = {
        dbType: 'firebase',
        url: typeData.databaseURL,
        apiKey: typeData.apiKey,
        projectRef: typeData.projectId
      };
    } else {
      currentConfig = {
        dbType: 'custom',
        url: typeData.urls?.[0] || null,
        apiKey: typeData.tokens?.[0]?.jwt || null
      };
    }

    showResultsUI(dbType);
  }

  function showResultsUI(dbType) {
    setStatus('detected', `${dbType} detected!`);
    document.getElementById('no-detection')?.classList.add('hidden');
    document.getElementById('detection-results')?.classList.remove('hidden');

    const badge = document.getElementById('db-type-badge');
    if (badge) {
      badge.textContent = dbType.charAt(0).toUpperCase() + dbType.slice(1);
      badge.className = `db-badge ${dbType} visible`;
    }

    const icon = document.getElementById('result-db-icon');
    const name = document.getElementById('result-db-name');
    
    if (icon) {
      if (dbType === 'supabase') {
        icon.innerHTML = `<svg viewBox="0 0 109 113" style="width:24px;height:24px">
          <path d="M63.7076 110.284C60.8481 113.885 55.0502 111.912 54.9813 107.314L53.9738 40.0627L99.1935 40.0627C107.384 40.0627 111.952 49.5228 106.859 55.9374L63.7076 110.284Z" fill="url(#paint0_linear)"/>
          <path d="M45.317 2.07103C48.1765 -1.53037 53.9745 0.442937 54.0434 5.041L54.4849 72.2922H9.83113C1.64038 72.2922 -2.92775 62.8321 2.1655 56.4175L45.317 2.07103Z" fill="#3ECF8E"/>
          <defs>
          <linearGradient id="paint0_linear" x1="53.9738" y1="54.974" x2="94.1635" y2="71.8295" gradientUnits="userSpaceOnUse">
          <stop stop-color="#249361"/>
          <stop offset="1" stop-color="#3ECF8E"/>
          </linearGradient>
          </defs>
        </svg>`;
        icon.style.color = '#3ECF8E';
      } else if (dbType === 'firebase') {
        icon.innerHTML = `<svg viewBox="0 0 600 600" style="width:24px;height:24px">
          <path d="M213.918 560.499C237.166 569.856 262.387 575.408 288.87 576.333C324.71 577.585 358.792 570.175 389.261 556.099C352.724 541.744 319.634 520.751 291.392 494.651C273.086 523.961 246.01 547.113 213.918 560.499Z" fill="#FF9100"/>
          <path d="M291.389 494.66C226.923 435.038 187.815 348.743 191.12 254.092C191.228 251.019 191.39 247.947 191.58 244.876C180.034 241.89 167.98 240.068 155.576 239.635C137.821 239.015 120.626 241.217 104.393 245.788C87.1838 275.933 76.7989 310.521 75.5051 347.569C72.1663 443.18 130.027 526.723 213.914 560.508C246.007 547.121 273.082 523.998 291.389 494.66Z" fill="#FFC400"/>
          <path d="M291.39 494.657C306.378 470.671 315.465 442.551 316.523 412.254C319.306 332.559 265.731 264.003 191.581 244.873C191.391 247.944 191.229 251.016 191.121 254.089C187.816 348.74 226.924 435.035 291.39 494.657Z" fill="#FF9100"/>
          <path d="M308.231 20.8584C266 54.6908 232.652 99.302 212.475 150.693C200.924 180.129 193.665 211.748 191.546 244.893C265.696 264.023 319.272 332.579 316.489 412.273C315.431 442.57 306.317 470.663 291.355 494.677C319.595 520.804 352.686 541.77 389.223 556.124C462.56 522.224 514.593 449.278 517.606 362.997C519.558 307.096 498.08 257.273 467.731 215.219C435.68 170.742 308.231 20.8584 308.231 20.8584Z" fill="#DD2C00"/>
        </svg>`;
        icon.style.color = '#FF9100';
      } else {
        icon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:24px;height:24px">
          <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
          <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
          <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
        </svg>`;
        icon.style.color = 'var(--accent-sage)';
      }
    }
    
    if (name) name.textContent = dbType.charAt(0).toUpperCase() + dbType.slice(1);

    // Show URL - hide element if not found
    const urlEl = document.getElementById('project-url');
    if (urlEl) {
      if (currentConfig.url) {
        urlEl.textContent = currentConfig.url;
        urlEl.style.display = '';
      } else {
        urlEl.textContent = '';
        urlEl.style.display = 'none';
      }
    }

    // Show API key - hide element if not found
    const anonKeyEl = document.getElementById('anon-key');
    const displayKey = currentConfig.serviceKey || currentConfig.apiKey;
    if (anonKeyEl) {
      if (displayKey) {
        anonKeyEl.textContent = displayKey;
        anonKeyEl.parentElement.style.display = '';
      } else {
        anonKeyEl.textContent = '';
        anonKeyEl.parentElement.style.display = 'none';
      }
    }

    const serviceKeyItem = document.getElementById('service-key-item');
    if (currentConfig.serviceKey && serviceKeyItem) {
      serviceKeyItem.classList.remove('hidden');
      setText('service-key', currentConfig.serviceKey);
    } else if (serviceKeyItem) {
      serviceKeyItem.classList.add('hidden');
    }

    discoverTables();
  }

  function showNoDetection() {
    setStatus('not-detected', 'Nothing found');
    
    document.getElementById('no-detection')?.classList.remove('hidden');
    document.getElementById('detection-results')?.classList.add('hidden');
    
    const badge = document.getElementById('db-type-badge');
    if (badge) badge.classList.remove('visible');
    
    const noDetectionText = document.getElementById('no-detection-text');
    if (noDetectionText) {
      noDetectionText.textContent = 'No database detected on this page';
    }
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function setStatus(status, text) {
    const indicator = document.getElementById('detection-status');
    const statusText = document.getElementById('status-text');
    if (indicator) indicator.className = 'status-indicator ' + status;
    if (statusText) {
      statusText.textContent = text;
      statusText.className = status;
    }
  }

  // ============ TABLES ============

  // Store all keys found during scanning for fallback
  let allFoundKeys = [];

  async function discoverTables() {
    const tablesList = document.getElementById('tables-list');
    if (!tablesList) return;

    if (!currentConfig.url) {
      tablesList.innerHTML = '<p class="muted">Need URL</p>';
      return;
    }

    tablesList.innerHTML = '<p class="muted">Loading...</p>';

    // Collect ALL possible keys to try
    const allKeysToTry = [];

    // 1. Add currently loaded key first
    if (currentConfig.apiKey) {
      allKeysToTry.push({ key: currentConfig.apiKey, type: 'current_anon', source: 'current' });
    }
    if (currentConfig.serviceKey) {
      allKeysToTry.push({ key: currentConfig.serviceKey, type: 'current_service', source: 'current' });
    }

    // 2. Scan page for ALL keys
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const scanResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: aggressiveKeyScan
      });

      if (scanResult?.[0]?.result) {
        const { keys, url } = scanResult[0].result;

        // Add all found keys
        keys.forEach(k => {
          if (k.key && !allKeysToTry.find(existing => existing.key === k.key)) {
            allKeysToTry.push({ key: k.key, type: k.type, source: 'page_scan' });
          }
        });

        // Update URL if we found one
        if (url && !currentConfig.url) {
          currentConfig.url = url;
        }
      }
    } catch (e) {
      console.error('Key scan error:', e);
    }

    // 3. Also try known key patterns directly
    const knownPatterns = [
      // Try common Supabase project refs if we have URL
      { pattern: /supabase\.co\/auth\/v1\/pk\/public\/(eyJ[^\s"']+)/, type: 'public_key' },
      { pattern: /apikey["']?\s*[:=]\s*["']?(eyJ[^\s"']+)/, type: 'api_key' },
      { pattern: /Authorization:\s*Bearer\s*(eyJ[^\s"']+)/, type: 'auth_header' },
      { pattern: /"anon_key"\s*:\s*"(eyJ[^"]+)"/, type: 'json_anon' },
      { pattern: /"service_key"\s*:\s*"(eyJ[^"]+)"/, type: 'json_service' },
    ];

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const patternResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (patterns) => {
          const allText = document.documentElement.outerHTML;
          const found = [];
          patterns.forEach(p => {
            let match;
            const regex = new RegExp(p.pattern.source, 'gi');
            while ((match = regex.exec(allText)) !== null) {
              if (match[1]) {
                found.push(match[1]);
              }
            }
          });
          return [...new Set(found)];
        },
        args: [knownPatterns.map(p => p.pattern.source)]
      });

      if (patternResult?.[0]?.result) {
        patternResult[0].result.forEach(key => {
          if (key && !allKeysToTry.find(existing => existing.key === key)) {
            allKeysToTry.push({ key, type: 'pattern_match', source: 'pattern' });
          }
        });
      }
    } catch (e) {
      console.error('Pattern scan error:', e);
    }

    // 4. Try each key until one works
    tablesList.innerHTML = '<p class="muted">Connecting...</p>';

    for (let i = 0; i < allKeysToTry.length; i++) {
      const keyInfo = allKeysToTry[i];
      if (!keyInfo.key || !keyInfo.key.startsWith('eyJ')) continue;

      tablesList.innerHTML = `<p class="muted">Connecting... (${i + 1}/${allKeysToTry.length})</p>`;

      const result = await tryAccessTables(keyInfo.key);

      // Skip timeouts and continue to next key
      if (result.status === 0) {
        continue;
      }

      if (result.success) {
        // Update config with working key
        if (keyInfo.type === 'current_service' || keyInfo.type === 'service' || keyInfo.type === 'json_service') {
          currentConfig.serviceKey = keyInfo.key;
        } else {
          currentConfig.apiKey = keyInfo.key;
        }
        updateKeyDisplay(keyInfo.key);

        if (result.tables.length > 0) {
          tablesList.innerHTML = result.tables.map(t => `<span class="table-tag" data-table="${t}">${t}</span>`).join(' ');
        } else {
          tablesList.innerHTML = '<p class="muted">No tables (protected)</p>';
        }
        return;
      }
    }

    // All keys failed
    tablesList.innerHTML = '<p class="muted">No valid key found</p>';
  }

  // Helper function to try access with timeout
  async function tryAccessTables(key) {
    if (!key || !currentConfig.url) {
      return { success: false, status: null, tables: [], error: 'Missing key or URL' };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

      const response = await fetch(`${currentConfig.url}/rest/v1/`, {
        headers: { 'apikey': key, 'Authorization': `Bearer ${key}` },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const schema = await response.json();
        const tables = Object.keys(schema.paths || {})
          .filter(p => p !== '/' && !p.includes('/rpc'))
          .map(p => p.replace(/^\//, '').split('/')[0])
          .filter((v, i, a) => a.indexOf(v) === i);

        return { success: true, status: response.status, tables };
      }

      return { success: false, status: response.status, tables: [], error: null };
    } catch (error) {
      if (error.name === 'AbortError') {
        return { success: false, status: 0, tables: [], error: 'Timeout' };
      }
      return { success: false, status: null, tables: [], error: error.message };
    }
  }

  // Aggressive key scanning - finds ALL possible keys
  function aggressiveKeyScan() {
    const keys = [];
    const sources = [];

    // Collect from everywhere
    sources.push(document.documentElement.outerHTML);
    document.querySelectorAll('script').forEach(s => {
      if (s.textContent) sources.push(s.textContent);
    });
    document.querySelectorAll('*').forEach(el => {
      const attrs = el.attributes;
      for (let i = 0; i < attrs.length; i++) {
        sources.push(`${attrs[i].name}=${attrs[i].value}`);
      }
    });

    try {
      for (let i = 0; i < localStorage.length; i++) {
        sources.push(localStorage.getItem(localStorage.key(i)) || '');
      }
    } catch (e) {}

    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        sources.push(sessionStorage.getItem(sessionStorage.key(i)) || '');
      }
    } catch (e) {}

    // Also check cookies
    document.cookie.split(';').forEach(c => {
      sources.push(c.trim());
    });

    // Check window object for any exposed keys
    const windowKeys = ['supabase', '_supabase', 'supabaseClient', 'SUPABASE', 'ENV', 'config'];
    windowKeys.forEach(k => {
      try {
        if (window[k]) {
          sources.push(JSON.stringify(window[k]));
        }
      } catch (e) {}
    });

    const allText = sources.join('\n');

    // Find URL
    const urlMatch = allText.match(/https?:\/\/([a-zA-Z0-9_-]{2,})\.supabase\.(co|in|net)/);
    const url = urlMatch ? urlMatch[0] : null;

    // Find ALL JWT tokens (very aggressive)
    const jwtPattern = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
    const jwts = [...new Set(allText.match(jwtPattern) || [])];

    jwts.forEach(jwt => {
      try {
        const parts = jwt.split('.');
        if (parts.length !== 3) return;

        let padded = parts[1];
        while (padded.length % 4 !== 0) padded += '=';
        const payload = JSON.parse(atob(padded));

        let type = 'anon';
        if (payload.role === 'service_role') {
          type = 'service';
        } else if (payload.role === 'authenticated') {
          type = 'authenticated';
        } else if (payload.role === 'anon') {
          type = 'anon';
        }

        // Check if key belongs to this project
        let belongsToProject = true;
        if (url && payload.ref) {
          belongsToProject = url.includes(payload.ref);
        }
        // Also check iss claim
        if (payload.iss && payload.iss.includes('supabase') && url) {
          if (!payload.iss.includes(new URL(url).hostname)) {
            belongsToProject = false;
          }
        }

        if (belongsToProject) {
          keys.push({ key: jwt, type, role: payload.role, ref: payload.ref });
        }
      } catch (e) {}
    });

    // Find explicit key assignments
    const explicitPatterns = [
      /(?:VITE_|NEXT_PUBLIC_|REACT_APP_)?SUPABASE(?:_ANON|_SERVICE)?_?KEY\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/gi,
      /supabase(?:Anon|Service|anon|service)?Key\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/gi,
      /apikey\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/gi,
      /"apiKey"\s*:\s*"(eyJ[^"]+)"/gi,
      /createClient\s*\([^,]+,\s*(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/gi
    ];

    explicitPatterns.forEach(pattern => {
      let match;
      const regex = new RegExp(pattern.source, 'gi');
      while ((match = regex.exec(allText)) !== null) {
        if (match[1]) {
          const key = match[1];
          const type = match[0].toLowerCase().includes('service') ? 'service' : 'anon';
          if (!keys.find(k => k.key === key)) {
            keys.push({ key, type, role: type === 'service' ? 'service_role' : 'anon' });
          }
        }
      }
    });

    return { keys, url };
  }

  function updateKeyDisplay(key) {
    const anonKeyEl = document.getElementById('anon-key');
    if (anonKeyEl) {
      anonKeyEl.textContent = key;
      // Make sure the element is visible
      const parent = anonKeyEl.parentElement;
      if (parent) parent.style.display = '';
    }
  }

  async function fetchTableData(tableName) {
    if (!currentConfig.url) {
      alert('Missing URL');
      return;
    }

    const dataOutput = document.getElementById('data-output');
    const dataResults = document.getElementById('data-results');

    if (dataOutput && dataResults) {
      dataResults.classList.remove('hidden');
      dataOutput.textContent = `Connecting to ${tableName}...`;
    }

    // Collect ALL possible keys
    const allKeysToTry = [];

    if (currentConfig.apiKey) {
      allKeysToTry.push({ key: currentConfig.apiKey, type: 'current' });
    }
    if (currentConfig.serviceKey) {
      allKeysToTry.push({ key: currentConfig.serviceKey, type: 'service' });
    }

    // Scan page for all keys
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const scanResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: aggressiveKeyScan
      });

      if (scanResult?.[0]?.result) {
        scanResult[0].result.keys.forEach(k => {
          if (k.key && !allKeysToTry.find(existing => existing.key === k.key)) {
            allKeysToTry.push({ key: k.key, type: k.type });
          }
        });
      }
    } catch (e) {
      console.error('Key scan error:', e);
    }

    // Try each key
    let successData = null;

    for (let i = 0; i < allKeysToTry.length; i++) {
      const keyInfo = allKeysToTry[i];
      if (!keyInfo.key || !keyInfo.key.startsWith('eyJ')) continue;

      if (dataOutput) dataOutput.textContent = `Connecting... (${i + 1}/${allKeysToTry.length})`;

      const result = await tryFetchTable(tableName, keyInfo.key);

      // Skip timeouts
      if (result.status === 0) {
        continue;
      }

      if (result.success) {
        successData = result.data;

        // Update config
        if (keyInfo.type === 'service' || keyInfo.type === 'current_service') {
          currentConfig.serviceKey = keyInfo.key;
        } else {
          currentConfig.apiKey = keyInfo.key;
        }
        updateKeyDisplay(keyInfo.key);
        break;
      }
    }

    if (dataOutput) {
      if (successData) {
        const count = Array.isArray(successData) ? successData.length : 0;
        dataOutput.textContent = `=== ${tableName} (${count}) ===\n\n${JSON.stringify(successData, null, 2)}`;
      } else {
        dataOutput.textContent = 'No valid key found';
      }
    }
  }

  async function tryFetchTable(tableName, key) {
    if (!key || !currentConfig.url) {
      return { success: false, status: null, data: null };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(
        `${currentConfig.url}/rest/v1/${tableName}?select=*&limit=100`,
        { headers: { 'apikey': key, 'Authorization': `Bearer ${key}` }, signal: controller.signal }
      );

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        return { success: true, status: response.status, data };
      }

      return { success: false, status: response.status, data: null };
    } catch (error) {
      if (error.name === 'AbortError') {
        return { success: false, status: 0, data: null, error: 'Timeout' };
      }
      return { success: false, status: null, data: null, error: error.message };
    }
  }

  async function dumpAllTables() {
    if (!currentConfig.url) {
      alert('Missing URL');
      return;
    }

    const dataOutput = document.getElementById('data-output');
    const dataResults = document.getElementById('data-results');

    if (dataOutput && dataResults) {
      dataResults.classList.remove('hidden');
      dataOutput.textContent = 'Dumping...';
    }

    // Collect ALL possible keys
    const allKeysToTry = [];

    if (currentConfig.apiKey) {
      allKeysToTry.push({ key: currentConfig.apiKey, type: 'current' });
    }
    if (currentConfig.serviceKey) {
      allKeysToTry.push({ key: currentConfig.serviceKey, type: 'service' });
    }

    // Scan page for all keys
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const scanResult = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: aggressiveKeyScan
      });

      if (scanResult?.[0]?.result) {
        scanResult[0].result.keys.forEach(k => {
          if (k.key && !allKeysToTry.find(existing => existing.key === k.key)) {
            allKeysToTry.push({ key: k.key, type: k.type });
          }
        });
      }
    } catch (e) {
      console.error('Key scan error:', e);
    }

    // Try each key
    let successData = null;
    let tableCount = 0;

    for (let i = 0; i < allKeysToTry.length; i++) {
      const keyInfo = allKeysToTry[i];
      if (!keyInfo.key || !keyInfo.key.startsWith('eyJ')) continue;

      if (dataOutput) dataOutput.textContent = `Connecting... (${i + 1}/${allKeysToTry.length})`;

      const dumpResult = await tryDumpAll(keyInfo.key);

      // Skip timeouts
      if (dumpResult.status === 0) {
        continue;
      }

      if (dumpResult.success) {
        successData = dumpResult.data;
        tableCount = dumpResult.tableCount;

        // Update config
        if (keyInfo.type === 'service' || keyInfo.type === 'current_service') {
          currentConfig.serviceKey = keyInfo.key;
        } else {
          currentConfig.apiKey = keyInfo.key;
        }
        updateKeyDisplay(keyInfo.key);
        break;
      }
    }

    if (dataOutput) {
      if (successData) {
        dataOutput.textContent = `=== ${tableCount} tables ===\n\n${JSON.stringify(successData, null, 2)}`;
      } else {
        dataOutput.textContent = 'No valid key found';
      }
    }
  }

  async function tryDumpAll(key) {
    if (!key || !currentConfig.url) {
      return { success: false, status: null, data: {}, tableCount: 0 };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      // Get schema first
      const schemaRes = await fetch(`${currentConfig.url}/rest/v1/`, {
        headers: { 'apikey': key, 'Authorization': `Bearer ${key}` },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!schemaRes.ok) {
        return { success: false, status: schemaRes.status, data: {}, tableCount: 0 };
      }

      const schema = await schemaRes.json();
      const tables = Object.keys(schema.paths || {})
        .filter(p => p !== '/' && !p.includes('/rpc'))
        .map(p => p.replace(/^\//, '').split('/')[0])
        .filter((v, i, a) => a.indexOf(v) === i);

      let allData = {};

      for (const table of tables) {
        try {
          const controller2 = new AbortController();
          const timeoutId2 = setTimeout(() => controller2.abort(), 3000);

          const response = await fetch(
            `${currentConfig.url}/rest/v1/${table}?select=*&limit=100`,
            { headers: { 'apikey': key, 'Authorization': `Bearer ${key}` }, signal: controller2.signal }
          );

          clearTimeout(timeoutId2);

          if (response.ok) {
            const data = await response.json();
            if (Array.isArray(data) && data.length > 0) {
              allData[table] = data;
            }
          }
        } catch (e) {}
      }

      return { success: true, status: 200, data: allData, tableCount: Object.keys(allData).length };
    } catch (error) {
      return { success: false, status: null, data: {}, tableCount: 0, error: error.message };
    }
  }

  // ============ MANUAL CONNECT ============

  function manualConnect() {
    const dbType = document.getElementById('manual-db-type')?.value || 'custom';
    const url = document.getElementById('manual-url')?.value?.trim();
    const key = document.getElementById('manual-key')?.value?.trim();

    if (!url && !key) {
      alert('Enter URL or API Key');
      return;
    }

    let projectUrl = url;
    if (dbType === 'supabase' && url && !url.includes('://')) {
      projectUrl = `https://${url}.supabase.co`;
    }

    const fakeResults = {
      supabase: { detected: false },
      firebase: { detected: false },
      custom: { detected: false, urls: [], tokens: [] }
    };

    if (dbType === 'supabase') {
      fakeResults.supabase = { detected: true, url: projectUrl, anonKey: key, projectRef: url };
    } else if (dbType === 'firebase') {
      fakeResults.firebase = { detected: true, databaseURL: projectUrl, apiKey: key };
    } else {
      fakeResults.custom = { 
        detected: true, 
        urls: projectUrl ? [projectUrl] : [],
        tokens: key ? [{ jwt: key, type: 'manual' }] : []
      };
    }

    lastScanResults = fakeResults;
    selectedDbType = dbType;
    
    document.querySelectorAll('.db-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.db-tab[data-db="${dbType}"]`)?.classList.add('active');
    
    const manualEntry = document.getElementById('manual-entry');
    const toggleBtn = document.getElementById('manual-toggle-btn');
    if (manualEntry) manualEntry.classList.add('hidden');
    if (toggleBtn) toggleBtn.textContent = 'Enter Manually';
    
    displayResultsForType(fakeResults, dbType);
  }

  function openDashboard() {
    if (currentConfig.dbType === 'supabase' && currentConfig.projectRef) {
      chrome.tabs.create({ url: `https://supabase.com/dashboard/project/${currentConfig.projectRef}` });
    } else {
      alert('Dashboard not available');
    }
  }

  // ============ COPY / DOWNLOAD ============

  function copyData() {
    const dataOutput = document.getElementById('data-output');
    if (!dataOutput || !dataOutput.textContent) return;
    
    const text = dataOutput.textContent.trim();
    if (text === '-' || text === 'Loading...' || text.includes('Error')) return;
    
    let textToCopy = text;
    const jsonMatch = text.match(/=== .+? ===\s*\n\n([\s\S]*)/);
    if (jsonMatch) {
      textToCopy = jsonMatch[1].trim();
    }
    
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(textToCopy).then(() => {
        showCopyFeedback('copy-data-btn');
      }).catch(() => {
        fallbackCopy(textToCopy, 'copy-data-btn');
      });
    } else {
      fallbackCopy(textToCopy, 'copy-data-btn');
    }
  }

  function fallbackCopy(text, btnId) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      showCopyFeedback(btnId);
    } catch (e) {
      console.error('Copy failed:', e);
    }
    document.body.removeChild(textarea);
  }

  function showCopyFeedback(btnId) {
    const btn = document.getElementById(btnId);
    if (btn) {
      const originalHTML = btn.innerHTML;
      btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      setTimeout(() => {
        btn.innerHTML = originalHTML;
      }, 1500);
    }
  }

  function downloadData() {
    const dataOutput = document.getElementById('data-output');
    if (!dataOutput || !dataOutput.textContent) return;
    
    const text = dataOutput.textContent.trim();
    if (text === '-' || text === 'Loading...' || text.includes('Error')) return;
    
    let jsonData = text;
    const jsonMatch = text.match(/=== .+? ===\s*\n\n([\s\S]*)/);
    if (jsonMatch) {
      jsonData = jsonMatch[1].trim();
    }
    
    try {
      const parsed = JSON.parse(jsonData);
      jsonData = JSON.stringify(parsed, null, 2);
    } catch (e) {}
    
    let filename = 'data';
    if (currentConfig.dbType === 'supabase' && currentConfig.projectRef) {
      filename = currentConfig.projectRef;
    }
    filename += `-${new Date().toISOString().split('T')[0]}.json`;
    
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }

  function closeData() {
    const dataResults = document.getElementById('data-results');
    const dataOutput = document.getElementById('data-output');
    if (dataResults) dataResults.classList.add('hidden');
    if (dataOutput) dataOutput.textContent = '-';
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
  }
})();
