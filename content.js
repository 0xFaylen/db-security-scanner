// DB Security Scanner - Content Script v3.0
// Supports: Supabase, Firebase, Custom APIs
(function() {
  'use strict';

  console.log('[DBScanner] Content script v3.0 - Multi-database support');

  const DBDetector = {
    results: {
      detected: false,
      dbType: null,
      supabase: { url: null, anonKey: null, serviceKey: null, projectRef: null },
      firebase: { config: null, apiKey: null, projectId: null, authDomain: null, databaseURL: null },
      custom: { urls: [], tokens: [] },
      jwts: [],
      vulnerabilities: [],
      sources: [],
      scannedUrls: []
    },

    patterns: {
      jwt: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
      supabaseUrl: /https?:\/\/([a-zA-Z0-9_-]+)\.supabase\.(co|in|net)/g,
      firebaseUrl: /https?:\/\/([a-zA-Z0-9_-]+)\.firebaseio\.com/g,
      firebaseApiKey: /["']?(AIza[A-Za-z0-9_-]{35})["']?/g,
      apiUrl: /["']?(https?:\/\/[^"'\s]+\/api[^"'\s]*)["']?/g
    },

    async init() {
      console.log('[DBScanner] Starting multi-database scan...');
      
      this.resetResults();
      
      // Scan all sources
      this.scanDOM();
      this.scanScripts();
      this.scanStorage();
      this.scanWindowObjects();
      this.scanPerformanceEntries();
      this.interceptNetwork();
      
      // Deep scan
      await this.fetchExternalScripts();
      await this.scanOtherPages();

      this.analyzeVulnerabilities();
      this.reportResults();
      
      console.log('[DBScanner] Scan complete:', this.results);
    },

    resetResults() {
      this.results = {
        detected: false,
        dbType: null,
        supabase: { url: null, anonKey: null, serviceKey: null, projectRef: null },
        firebase: { config: null, apiKey: null, projectId: null, authDomain: null, databaseURL: null },
        custom: { urls: [], tokens: [] },
        jwts: [],
        vulnerabilities: [],
        sources: [],
        scannedUrls: []
      };
    },

    scanDOM() {
      this.extractFromText(document.documentElement.outerHTML, 'DOM');
    },

    scanScripts() {
      document.querySelectorAll('script').forEach((script, i) => {
        if (script.textContent) {
          this.extractFromText(script.textContent, `script-${i}`);
        }
        // Check for Firebase/Supabase in script src
        const src = script.src || '';
        if (src.includes('supabase')) {
          this.results.detected = true;
          this.results.dbType = this.results.dbType || 'supabase';
          this.results.sources.push('script-src: supabase');
        }
        if (src.includes('firebase') || src.includes('gstatic.com/firebasejs')) {
          this.results.detected = true;
          this.results.dbType = this.results.dbType || 'firebase';
          this.results.sources.push('script-src: firebase');
        }
      });

      // Data attributes
      document.querySelectorAll('[data-supabase-url], [data-firebase-config], [data-api-key]').forEach(el => {
        Object.values(el.dataset).forEach(v => this.extractFromText(v, 'data-attr'));
      });
    },

    scanStorage() {
      // LocalStorage
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key) || '';
          
          if (key.includes('supabase') || key.includes('sb-')) {
            this.results.detected = true;
            this.results.dbType = this.results.dbType || 'supabase';
            try {
              const parsed = JSON.parse(value);
              if (parsed.access_token) this.addJwt(parsed.access_token, 'localStorage');
            } catch (e) {}
          }
          
          if (key.includes('firebase')) {
            this.results.detected = true;
            this.results.dbType = this.results.dbType || 'firebase';
          }
          
          this.extractFromText(value, `ls:${key}`);
        }
      } catch (e) {}

      // SessionStorage
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          const value = sessionStorage.getItem(key) || '';
          this.extractFromText(value, `ss:${key}`);
        }
      } catch (e) {}

      // Cookies
      this.extractFromText(document.cookie, 'cookies');
    },

    scanWindowObjects() {
      const windowProps = [
        // Supabase
        'supabase', 'supabaseClient', '_supabase', '__SUPABASE__',
        // Firebase
        'firebase', 'firebaseConfig', '_firebase', '__FIREBASE__',
        // Common
        '__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__',
        'env', 'ENV', '__env__', 'config', 'CONFIG', 'appConfig',
        // Next.js 13+
        '__next_f',
        // API
        'apiConfig', 'API_CONFIG', 'API_URL'
      ];

      // Check self.__next_f specifically (array of chunks)
      if (window.self && window.self.__next_f) {
        try {
           const str = JSON.stringify(window.self.__next_f);
           this.extractFromText(str, 'window.self.__next_f');
        } catch(e) {}
      }

      windowProps.forEach(prop => {
        try {
          const value = window[prop];
          if (value) this.inspectObject(value, `window.${prop}`, 0);
        } catch (e) {}
      });

      // Deep scan for firebase/supabase in window
      try {
        Object.keys(window).forEach(key => {
          const lk = key.toLowerCase();
          if (lk.includes('supabase') || lk.includes('firebase') || 
              lk.includes('config') || lk.includes('api')) {
            try { this.inspectObject(window[key], `window.${key}`, 0); } catch (e) {}
          }
        });
      } catch (e) {}
    },

    inspectObject(obj, path, depth) {
      if (depth > 4 || obj === null || obj === undefined || typeof obj === 'function') return;

      try {
        const str = typeof obj === 'string' ? obj : JSON.stringify(obj);
        this.extractFromText(str, path);
      } catch (e) {}

      if (typeof obj === 'object') {
        // Supabase specific
        if (obj.supabaseUrl || obj.SUPABASE_URL) {
          this.results.detected = true;
          this.results.dbType = this.results.dbType || 'supabase';
          this.results.supabase.url = obj.supabaseUrl || obj.SUPABASE_URL;
        }
        if (obj.supabaseKey || obj.supabaseAnonKey || obj.SUPABASE_ANON_KEY) {
          this.addJwt(obj.supabaseKey || obj.supabaseAnonKey || obj.SUPABASE_ANON_KEY, path);
        }

        // Firebase specific
        if (obj.apiKey && obj.authDomain && obj.projectId) {
          this.results.detected = true;
          this.results.dbType = this.results.dbType || 'firebase';
          this.results.firebase.config = obj;
          this.results.firebase.apiKey = obj.apiKey;
          this.results.firebase.projectId = obj.projectId;
          this.results.firebase.authDomain = obj.authDomain;
          this.results.firebase.databaseURL = obj.databaseURL;
        }

        // Recurse
        const propsToCheck = ['url', 'apiKey', 'anonKey', 'key', 'headers', 'config', 
                            'props', 'pageProps', 'env', 'firebase', 'supabase'];
        propsToCheck.forEach(prop => {
          if (obj[prop] !== undefined) {
            this.inspectObject(obj[prop], `${path}.${prop}`, depth + 1);
          }
        });
      }
    },

    scanPerformanceEntries() {
      if (!window.performance) return;

      try {
        performance.getEntriesByType('resource').forEach(entry => {
          const url = entry.name;
          
          // Supabase
          if (url.includes('supabase')) {
            this.results.detected = true;
            this.results.dbType = this.results.dbType || 'supabase';
            
            const urlMatch = url.match(/https?:\/\/([a-zA-Z0-9_-]+)\.supabase\.(co|in|net)/);
            if (urlMatch) {
              this.results.supabase.url = this.results.supabase.url || urlMatch[0];
              this.results.supabase.projectRef = this.results.supabase.projectRef || urlMatch[1];
            }

            // API key in URL
            const keyInUrl = url.match(/[?&]apikey=([^&]+)/i);
            if (keyInUrl) this.addJwt(decodeURIComponent(keyInUrl[1]), 'url-param');
          }
          
          // Firebase
          if (url.includes('firebaseio.com') || url.includes('firebasestorage')) {
            this.results.detected = true;
            this.results.dbType = this.results.dbType || 'firebase';
            
            const fbMatch = url.match(/https?:\/\/([a-zA-Z0-9_-]+)\.firebaseio\.com/);
            if (fbMatch) {
              this.results.firebase.projectId = this.results.firebase.projectId || fbMatch[1];
              this.results.firebase.databaseURL = fbMatch[0];
            }
          }
        });
      } catch (e) {}
    },

    interceptNetwork() {
      const self = this;

      // Fetch intercept
      const originalFetch = window.fetch;
      window.fetch = function(...args) {
        try {
          const url = args[0]?.toString?.() || args[0]?.url || args[0];
          const options = args[1] || {};
          
          if (url) {
            if (url.includes('supabase')) {
              self.results.detected = true;
              self.results.dbType = self.results.dbType || 'supabase';
              
              const headers = options.headers;
              if (headers) {
                const apikey = headers.apikey || headers.apiKey || headers['apikey'];
                const auth = headers.Authorization || headers.authorization;
                if (apikey) self.addJwt(apikey, 'fetch-apikey');
                if (auth) self.addJwt(auth.replace(/^Bearer\s+/i, ''), 'fetch-auth');
              }
            }
            
            if (url.includes('firebaseio.com')) {
              self.results.detected = true;
              self.results.dbType = self.results.dbType || 'firebase';
            }
          }
        } catch (e) {}
        return originalFetch.apply(this, args);
      };

      // XHR intercept
      const originalOpen = XMLHttpRequest.prototype.open;
      const originalSetHeader = XMLHttpRequest.prototype.setRequestHeader;
      
      XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        if (url?.includes('supabase')) {
          self.results.detected = true;
          self.results.dbType = self.results.dbType || 'supabase';
        }
        if (url?.includes('firebaseio.com')) {
          self.results.detected = true;
          self.results.dbType = self.results.dbType || 'firebase';
        }
        return originalOpen.apply(this, arguments);
      };

      XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
        if (this._url?.includes('supabase')) {
          if (name.toLowerCase() === 'apikey') self.addJwt(value, 'xhr-apikey');
          if (name.toLowerCase() === 'authorization') self.addJwt(value.replace(/^Bearer\s+/i, ''), 'xhr-auth');
        }
        return originalSetHeader.apply(this, arguments);
      };
    },

    async fetchExternalScripts() {
      const scripts = document.querySelectorAll('script[src]');
      
      for (const script of scripts) {
        try {
          const src = script.src;
          if (!src || this.results.scannedUrls.includes(src)) continue;
          
          // Only scan same-origin or common bundle patterns
          const isSameOrigin = src.startsWith(window.location.origin);
          const isBundlePattern = /chunk|bundle|main|app|index|vendor|runtime/i.test(src);
          
          if (isSameOrigin || isBundlePattern) {
            this.results.scannedUrls.push(src);
            const response = await fetch(src);
            if (response.ok) {
              const text = await response.text();
              this.extractFromText(text, `js:${src.split('/').pop()}`);
            }
          }
        } catch (e) {}
      }
    },

    async scanOtherPages() {
      const links = new Set();
      document.querySelectorAll('a[href]').forEach(a => {
        const href = a.href;
        if (href.startsWith(window.location.origin) && !href.includes('#')) {
          links.add(href);
        }
      });

      let count = 0;
      for (const link of links) {
        if (count >= 3) break;
        if (this.results.scannedUrls.includes(link)) continue;
        
        try {
          this.results.scannedUrls.push(link);
          const response = await fetch(link);
          if (response.ok) {
            const text = await response.text();
            this.extractFromText(text, `page:${link.split('/').pop() || 'index'}`);
            count++;
          }
        } catch (e) {}
      }
    },

    extractFromText(text, location) {
      if (!text || typeof text !== 'string') return;

      // JWTs
      const jwts = text.match(this.patterns.jwt) || [];
      jwts.forEach(jwt => this.addJwt(jwt, location));

      // Supabase URLs
      let match;
      const supaRegex = new RegExp(this.patterns.supabaseUrl.source, 'g');
      while ((match = supaRegex.exec(text)) !== null) {
        this.results.detected = true;
        this.results.dbType = this.results.dbType || 'supabase';
        this.results.supabase.url = this.results.supabase.url || match[0];
        this.results.supabase.projectRef = this.results.supabase.projectRef || match[1];
      }

      // Firebase URLs
      const fbRegex = new RegExp(this.patterns.firebaseUrl.source, 'g');
      while ((match = fbRegex.exec(text)) !== null) {
        this.results.detected = true;
        this.results.dbType = this.results.dbType || 'firebase';
        this.results.firebase.projectId = this.results.firebase.projectId || match[1];
        this.results.firebase.databaseURL = match[0];
      }

      // Firebase API Keys
      const fbKeyRegex = new RegExp(this.patterns.firebaseApiKey.source, 'g');
      while ((match = fbKeyRegex.exec(text)) !== null) {
        this.results.detected = true;
        this.results.dbType = this.results.dbType || 'firebase';
        this.results.firebase.apiKey = this.results.firebase.apiKey || match[1];
      }

      // Custom API URLs (if no primary DB found)
      if (!this.results.supabase.url && !this.results.firebase.projectId) {
        const apiRegex = new RegExp(this.patterns.apiUrl.source, 'g');
        while ((match = apiRegex.exec(text)) !== null) {
          const url = match[1];
          if (url && !url.includes('google') && !url.includes('facebook') && 
              !this.results.custom.urls.includes(url)) {
            this.results.custom.urls.push(url);
          }
        }
      }
    },

    addJwt(jwt, location) {
      if (!jwt || !jwt.startsWith('eyJ') || jwt.length < 50) return;

      // Check if already added
      if (this.results.jwts.find(j => j.jwt === jwt)) return;

      try {
        const parts = jwt.split('.');
        if (parts.length !== 3) return;
        
        let padded = parts[1];
        while (padded.length % 4 !== 0) padded += '=';
        const payload = JSON.parse(atob(padded));

        const jwtInfo = { jwt, payload, type: 'unknown', location };

        // Classify
        if (payload.iss?.includes('supabase') || payload.role === 'anon' || payload.role === 'service_role') {
          jwtInfo.type = 'supabase';
          this.results.detected = true;
          this.results.dbType = this.results.dbType || 'supabase';
          
          if (payload.role === 'service_role') {
            this.results.supabase.serviceKey = jwt;
          } else {
            this.results.supabase.anonKey = this.results.supabase.anonKey || jwt;
          }
          
          if (payload.ref) {
            this.results.supabase.projectRef = payload.ref;
            this.results.supabase.url = this.results.supabase.url || `https://${payload.ref}.supabase.co`;
          }
        } else if (payload.firebase || payload.aud?.includes('firebase')) {
          jwtInfo.type = 'firebase';
          this.results.detected = true;
          this.results.dbType = this.results.dbType || 'firebase';
        } else if (payload.auth === 'ROLE_USER' || payload.auth === 'ROLE_ADMIN') {
          jwtInfo.type = 'spring-boot';
        } else if (payload.cognito) {
          jwtInfo.type = 'aws-cognito';
        } else if (payload.oid) {
          jwtInfo.type = 'azure-ad';
        } else if (payload.nonce) {
          jwtInfo.type = 'auth0';
        }

        this.results.jwts.push(jwtInfo);

        // Add to custom if not identified
        if (jwtInfo.type === 'unknown' || jwtInfo.type === 'spring-boot') {
          this.results.custom.tokens.push(jwtInfo);
        }

      } catch (e) {}
    },

    analyzeVulnerabilities() {
      const vulns = [];

      // Supabase vulnerabilities
      if (this.results.supabase.serviceKey) {
        vulns.push({
          id: 'SUPA-001', severity: 'CRITICAL',
          title: 'Supabase Service Key Exposed',
          description: 'Service role key bypasses ALL Row Level Security!'
        });
      }

      if (this.results.supabase.anonKey && this.results.supabase.url) {
        vulns.push({
          id: 'SUPA-003', severity: 'MEDIUM',
          title: 'Supabase Configuration Found',
          description: 'Anon key detected. Test RLS policies.'
        });
      } else if (this.results.supabase.url && !this.results.supabase.anonKey) {
        vulns.push({
          id: 'SUPA-002', severity: 'INFO',
          title: 'Supabase URL Found (No Key)',
          description: 'URL detected but key not found. Check Network tab.'
        });
      }

      // Firebase vulnerabilities
      if (this.results.firebase.apiKey) {
        vulns.push({
          id: 'FIRE-001', severity: 'MEDIUM',
          title: 'Firebase API Key Exposed',
          description: 'Check Firebase Security Rules and validate domains.'
        });
      }

      if (this.results.firebase.databaseURL) {
        vulns.push({
          id: 'FIRE-002', severity: 'INFO',
          title: 'Firebase Realtime DB URL Found',
          description: 'Test read/write access to database.'
        });
      }

      // Other JWTs
      const otherJwts = this.results.jwts.filter(j => j.type !== 'supabase' && j.type !== 'firebase');
      if (otherJwts.length > 0) {
        vulns.push({
          id: 'JWT-001', severity: 'INFO',
          title: 'Other JWT Tokens Found',
          description: `Found ${otherJwts.length} token(s): ${otherJwts.map(j => j.type).join(', ')}`
        });
      }

      // Custom APIs
      if (this.results.custom.urls.length > 0) {
        vulns.push({
          id: 'API-001', severity: 'INFO',
          title: 'Custom API Endpoints Found',
          description: `Found ${this.results.custom.urls.length} API endpoint(s).`
        });
      }

      this.results.vulnerabilities = vulns;
    },

    reportResults() {
      // Store in window for popup access
      window.__DB_SCAN_RESULTS__ = this.results;
      window.__SUPABASE_SCAN_RESULTS__ = this.results; // Backward compatibility

      // Send to extension
      try {
        chrome.runtime.sendMessage({ type: 'DB_SCAN_RESULTS', data: this.results });
      } catch (e) {}

      // Store in extension storage
      try {
        chrome.storage.local.set({
          [`scan_${window.location.hostname}`]: {
            timestamp: Date.now(),
            url: window.location.href,
            results: this.results
          }
        });
      } catch (e) {}
    }
  };

  // Run scan
  DBDetector.init();
  setTimeout(() => DBDetector.init(), 3000);

  // Message listener
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_PAGE') {
      DBDetector.init();
      sendResponse({ status: 'ok', results: DBDetector.results });
    }
    if (message.type === 'GET_RESULTS') {
      sendResponse(DBDetector.results);
    }
    return true;
  });

})();
