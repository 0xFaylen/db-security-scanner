# DB Security Scanner

A Chrome extension for detecting Supabase, Firebase, and Custom API configurations and scanning for security vulnerabilities on your own websites.

## Features

### Detection Capabilities
- **Multi-Database Support**: Detects Supabase, Firebase, and Custom APIs.
- **Project URL Detection**: Identifies project URLs from DOM, Network, and Source files.
- **API Key Extraction**: Finds anon keys, service keys (if exposed), Firebase API keys, and JWT tokens.
- **Endpoint Discovery**: Maps REST and Realtime endpoints.

### Vulnerability Analysis
- **Service Key Exposure**: Alerts if administrative keys are exposed.
- **Table Enumeration**: Discovers accessible database tables.
- **Data Access**: Attempts to fetch data from tables to verify RLS policies.
- **Database Dump**: Option to dump all accessible table data to JSON.

## Installation

### Option 1: Download Release (Recommended)
1. Go to the [Releases page](../../releases) (once uploaded to GitHub)
2. Download `db-security-scanner-v2.1.0.zip`
3. Unzip the file to a folder
4. Open Chrome and navigate to `chrome://extensions/`
5. Enable "Developer mode" (toggle in top-right)
6. Click "Load unpacked" and select the unzipped folder

### Option 2: Clone from Source
1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select the folder containing this extension

## Usage

1. Navigate to a website you own that uses Supabase or Firebase.
2. Click the extension icon to open the scanner.
3. **Detection**: The extension automatically scans the page and network traffic for credentials.
4. **Analysis**:
   - View detected URL and Keys.
   - Click "Connect" (if not auto-connected) to list tables.
   - Click on a table name to preview data.
   - Use "Dump All" to export all accessible data.
5. **Dashboard**: For Supabase, quick link to the project dashboard (if project ref is found).

## Important Security Notes

- **Only use on websites you own or have explicit permission to test.**
- **Never expose service role keys in frontend code.**
- **Always enable RLS (Row Level Security) on all Supabase tables.**
- **Secure Firebase Security Rules.**

## File Structure

```
/
├── manifest.json      # Extension configuration
├── popup.html         # Extension popup UI
├── popup.js           # Popup logic
├── styles.css         # Popup styling
├── content.js         # Page scanning script
├── background.js      # Service worker
└── icons/             # Extension icons
```

## Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any website. Unauthorized security testing may violate laws and terms of service.

## License

MIT License - Use responsibly for security research and authorized testing only.
