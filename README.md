# 🛡️ IntelBot

![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)
![Slack Bolt](https://img.shields.io/badge/SDK-Slack_Bolt-green.svg)
![Docker](https://img.shields.io/badge/Container-Podman%2FDocker-2496ED.svg)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)
![Version](https://img.shields.io/badge/Version-2.8-blue.svg)

**A ChatOps-powered threat intelligence bot for Slack.**

IntelBot is a security automation tool that brings OSINT (Open Source Intelligence) capabilities directly into your Slack workspace. Query threat intelligence APIs, manage IOC blocklists, and share indicators - all without leaving your chat.

Originally built for the [Illinois Cyber Foundation](https://illinoiscyberfoundation.org/), IntelBot is also meant to be used by security teams, SOCs, and threat intelligence sharing communities.

---

## 🚀 Features

### 🧠 Active Intelligence
* **Multi-Source Lookup:** Automatically queries **AbuseIPDB** (IPs), **VirusTotal** (Hashes/URLs), and **Whois** (Domain Age).
* **Severity Scoring:** Intelligent threat assessment on 0-100 scale with CRITICAL/HIGH/MEDIUM/LOW labels.
* **Multi-Hash Support:** Detects and identifies MD5, SHA-1, and SHA-256 hashes automatically.
* **Phishing Detector:** Flags domains registered in the last 30 days (configurable threshold).
* **Sandbox Integration:** Submits suspicious URLs to **URLScan.io** for safe analysis.
* **Infrastructure Scanning:** Checks **Shodan** for open ports and CVEs on target IPs.
* **🆕 API Rate Limiting (v2.8):** Tracks usage against free-tier quotas and warns before hitting limits.

### 🛡️ Safety & Context
* **Auto-Defanging:** Malicious URLs are converted to `hxxp://bad[.]com` to prevent accidental clicks.
* **Internal Memory:** Checks if an indicator is *already* in your IOC blocklist before wasting API credits.
* **Smart Unshortening:** Expands `bit.ly` links before scanning to find the real threat.
* **IP Validation:** Rejects malformed IPs (like `999.999.999.999`) before lookup.

### 📋 IOC Management
* **Chat-to-File:** Add IPs/Domains to the blocklist directly from Slack.
* **Attribution:** Supports adding "Reasons" for blocks (e.g., "Log4j Scanner").
* **Public Feed:** Writes to a text file served via Nginx for firewalls to consume.
* **Search Capability:** Search the IOC list with `!search` command.
* **Statistics:** View IOC additions, top contributors, and cache performance.
* **Thread-Safe:** File locking prevents corruption from concurrent access.
* **🆕 RBAC (v2.8):** Only channel admins/managers can delete IOCs - prevents accidental removals.
* **🆕 Multi-Format Export (v2.8):** Auto-generates JSON and STIX 2.1 formats for SIEM integration.

### ⚡ Performance & Reliability
* **Response Caching:** 5-minute TTL cache reduces API calls and speeds up repeat queries.
* **Configurable Thresholds:** Customize threat detection sensitivity via environment variables.
* **Production Logging:** Rotating log files (10MB max, 5 backups) with full audit trail.
* **Modular Architecture:** Clean separation of concerns for easy maintenance and testing.

---

## 🛠️ Prerequisites

You need the following API Keys (Free Tiers work for all):
1.  **Slack App Token** (`xapp-...`) & **Bot Token** (`xoxb-...`)
2.  **VirusTotal** (File/URL Reputation)
3.  **AbuseIPDB** (IP Reputation)
4.  **Shodan** (Infrastructure Scan)
5.  **URLScan.io** (Sandboxing)

---

## ⚙️ Installation (Docker/Podman)

This bot is designed to run in a container (Podman recommended on RHEL/CentOS).

### 1. Clone Repository
```bash
git clone https://github.com/codykretsinger/ilcf-intel-bot
cd ilcf-intel-bot
```

### 2. Configure Environment
Copy the example environment file and add your API keys:
```bash
cp .env.example .env
```

Edit `.env` with your credentials:
```bash
# Slack Credentials (required)
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token

# API Keys (all optional but recommended)
VT_API_KEY=your_virustotal_key
ABUSE_IPDB_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
URLSCAN_API_KEY=your_urlscan_key

# IOC Management
IOC_FILE_PATH=/data/iocs.txt
IOC_PUBLIC_URL=https://your-domain.com/intel/iocs.txt
```

### 3. Build & Run

**Option A: Docker/Podman (Recommended)**
```bash
# Build the image
podman build -t intel-bot .

# Run the container
podman run -d \
  --name intel-bot \
  --restart unless-stopped \
  --env-file .env \
  -v ./data:/data \
  intel-bot
```

**Option B: Python (Direct)**
```bash
# Install dependencies
pip install -r requirements.txt

# Run the bot
python intel_bot.py
```
## 🤖 Command Reference

### Intelligence Gathering

| Command | Description | Example |
|---------|-------------|---------|
| `!intel <target>` | **Main Tool.** Checks IP, Hash, or URL against all enabled engines (VirusTotal, AbuseIPDB, Whois). Includes intelligent severity scoring (0-100) and caching. | `!intel 8.8.8.8`<br>`!intel malware.exe`<br>`!intel hxxp://bad[.]com` |
| `!scan <url>` | Submits a URL to the **URLScan.io** sandbox for safe analysis. Returns screenshot and verdict. | `!scan http://sus-login.com` |
| `!shodan <ip>` | Checks **Shodan** for open ports, OS version, tags, and known CVE vulnerabilities. | `!shodan 1.2.3.4` |

### IOC Blocklist Management

| Command | Description | Example |
|---------|-------------|---------|
| `!add <target> <reason>` | Adds an IP or domain to the blocklist with attribution. Auto-syncs to TXT, JSON, and STIX 2.1 formats. | `!add 1.2.3.4 Log4j Scanner`<br>`!add bad.com Phishing Site` |
| `!del <target>` | 🔒 **Admin Only** - Removes an indicator from the blocklist. Requires channel admin/manager permissions. | `!del 1.2.3.4` |
| `!list` | Shows public URLs for all IOC export formats (TXT, JSON, STIX 2.1). | `!list` |
| `!search <query>` | Search the IOC blocklist for matching indicators. Supports partial matching. | `!search 192.168`<br>`!search malware` |

### Statistics & Monitoring

| Command | Description | Example |
|---------|-------------|---------|
| `!stats` | Show comprehensive statistics: IOC totals (all-time, today, this week), top contributors, recent additions, and cache performance metrics. | `!stats` |
| `!limits` | 🆕 **v2.8** - View detailed API rate limit status for all services with usage bars, percentages, and remaining quota. | `!limits` |
| `!help` | Display comprehensive help menu with all available commands and feature notes. | `!help` |

### Command Notes

- **Auto-Defanging:** All malicious URLs are automatically converted to safe format (`hxxp://bad[.]com`)
- **Response Caching:** Queries are cached for 5 minutes to reduce API usage
- **Thread Replies:** All responses are sent as threaded replies to keep the channel clean
- **Multi-Format IOCs:** All blocklist modifications automatically sync to TXT, JSON, and STIX 2.1 formats

## 🌐 Optional: Nginx Configuration

To serve the IOC list publicly (for firewall/SIEM consumption), add this to your Nginx server block:
```nginx
location /intel/ {
    alias /var/www/intel/;
    autoindex on;
    default_type text/plain;

    # Security: Block source code access
    location ~ \.(py|env|git)$ {
        deny all;
    }
}
```

Then mount the same directory to the container:
```bash
podman run -d \
  --name intel-bot \
  --restart unless-stopped \
  --env-file .env \
  -v /var/www/intel:/data \
  intel-bot
```

## 🐛 Troubleshooting

**"Unhandled Request" warnings in logs**
- This is normal. The bot hears all messages in the channel but ignores non-commands.
- Console warnings are suppressed in v2.8+.

**Duplicate responses in Slack**
- You likely have multiple bot containers running.
- Check: `podman ps` - should show only one `intel-bot` container.
- Fix: `podman rm -f $(podman ps -a -q --filter name=intel-bot)`

**Bot not responding to commands**
- Ensure Socket Mode is **enabled** in Slack App settings.
- Verify Event Subscriptions include `message.channels`.
- Check bot token has correct scopes (`chat:write`, `channels:history`, `users:read`).

**API rate limit warnings**
- Use `!limits` command to check current usage.
- Consider upgrading to paid API tiers for higher quotas.
- Adjust rate limits in `.env` if you have paid plans.

---

## 📄 License

MIT License - Copyright (c) 2022-2025 Illinois Cyber Foundation, Inc.

See [LICENSE](LICENSE) file for full text.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

For major changes, please discuss in an issue first.

---

**Built with ❤️ & 🍻 by Cody Kretsinger for the cybersecurity community**