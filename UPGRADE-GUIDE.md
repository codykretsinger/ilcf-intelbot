# IntelBot Upgrade Guide

This guide provides step-by-step migration instructions for upgrading between IntelBot versions. Upgrades are listed from **newest to oldest**.

---

## Table of Contents

- [Upgrading from v2.7 to v2.8](#upgrading-from-v27-to-v28)
- [Upgrading from v2.6 to v2.7](#upgrading-from-v26-to-v27)
- [General Upgrade Best Practices](#general-upgrade-best-practices)

---

## Upgrading from v2.7 to v2.8

**Migration Time:** ~5 minutes
**Downtime:** Yes (brief restart)
**Breaking Changes:** None (all additive features)

### What's New in v2.8

- **🔒 RBAC**: `!del` command restricted to channel admins/managers only
- **📊 API Rate Limit Tracking**: Monitor quota usage with warnings
- **📤 Multi-Format IOC Exports**: Auto-generate JSON and STIX 2.1
- **🆕 `!limits` Command**: View detailed API quota status

### Step 1: Backup Current Installation

```bash
cd /path/to/intel-butt
cp intel_bot.py intel_bot_backup.py
cp .env .env.backup
cp iocs.txt iocs.txt.backup
```

### Step 2: Pull New Code

```bash
git pull origin main
```

**New files in v2.8:**
- `api_limits.py` - Rate limit tracker
- `export_formats.py` - JSON/STIX generator

**Updated files:**
- `intel_bot.py` (main file, now v2.8)
- `utils.py` - Added `check_user_is_admin()`
- `handlers.py` - RBAC, `!limits` command, multi-format list
- `ioc_manager.py` - Calls `sync_all_formats()` after add/remove
- `config.py` - Added IOC_JSON_PATH, IOC_STIX_PATH

### Step 3: Environment Variables

**No new required variables!** All v2.7 variables still work.

**Optional new variables** (uses free-tier defaults if not set):

```bash
# API Rate Limits (optional - only if you have paid plans)
# VT_DAILY_LIMIT=500
# VT_MINUTE_LIMIT=4
# ABUSEIPDB_DAILY_LIMIT=1000
# SHODAN_MONTHLY_LIMIT=100
# URLSCAN_DAILY_LIMIT=50
```

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

**No new dependencies!** All v2.8 features use Python stdlib + existing packages.

### Step 5: Deploy

#### Option A: Podman/Docker (Recommended)

```bash
# Build new image
podman build -t intel-bot:v2.8 .

# Stop old container
podman stop intel-bot
podman rm intel-bot

# Run new container
podman run -d \
  --name intel-bot \
  --restart unless-stopped \
  --env-file .env \
  -v /path/to/intel-data:/data:Z \
  intel-bot:v2.8

# Verify
podman logs -f intel-bot
# Should see: ⚡ IntelBot v2.8 Starting Up...
```

#### Option B: Direct Python

```bash
# Stop old bot
kill $(pgrep -f intel_bot)

# Run new bot
python intel_bot.py

# Or with screen/tmux
screen -S intel-bot python intel_bot.py
```

### Step 6: Verify v2.8 Features

Test in Slack:

```
!help          # Should show v2.8 in header
!limits        # NEW: Show API rate limit status
!list          # Should show 3 format URLs (TXT, JSON, STIX)
!add 1.2.3.4   # Should report "Exported to JSON & STIX formats"
!del 1.2.3.4   # If not admin, shows 🚫 Permission Denied
```

**Check filesystem:**
```bash
ls -lh /path/to/intel-data/
# Should see:
# iocs.txt   (original)
# iocs.json  (auto-generated)
# iocs.stix  (auto-generated)
```

### Rollback Plan (If Needed)

```bash
# Restore backup
cp intel_bot_backup.py intel_bot.py
cp .env.backup .env

# Restart
podman restart intel-bot
# OR
python intel_bot.py
```

---

## Upgrading from v2.6 to v2.7

**Migration Time:** ~10 minutes
**Downtime:** Yes (brief restart)
**Breaking Changes:** None (100% backward compatible)

### What's New in v2.7

- **🧠 Severity Scoring**: Automated 0-100 threat assessment
- **⚡ Response Caching**: 5-minute TTL cache (63% faster responses)
- **🔍 `!search` Command**: Search IOC blocklist
- **📊 `!stats` Command**: View IOC and cache statistics
- **⚙️ Configurable Thresholds**: Customize detection sensitivity
- **🏗️ Modular Architecture**: Refactored into 6 specialized modules

### Step 1: Backup Current Installation

```bash
cd /path/to/intel-butt
cp intel_bot.py intel_bot_v26_backup.py
cp .env .env.backup
cp iocs.txt iocs.txt.backup
```

### Step 2: Pull New Code

```bash
git pull origin main
```

**New files in v2.7:**
```
config.py          # Centralized configuration
utils.py           # Shared utilities
cache.py           # Response caching
api_clients.py     # External API wrappers
ioc_manager.py     # IOC file operations
handlers.py        # Slack command handlers
intel_bot.py       # Main application (now modular)
```

### Step 3: Update Environment Variables

**All existing variables still work!** New optional variables:

```bash
# Caching (optional - enabled by default)
CACHE_ENABLED=true
CACHE_TTL=300               # 5 minutes
CACHE_MAX_SIZE=500          # 500 entries max

# Configurable Thresholds (optional)
THRESHOLD_ABUSE_CRITICAL=80           # AbuseIPDB critical score
THRESHOLD_ABUSE_SUSPICIOUS=20         # AbuseIPDB suspicious score
THRESHOLD_DOMAIN_NEW_DAYS=30          # Domain age threshold
THRESHOLD_DOMAIN_CRITICAL_DAYS=2      # Newly registered threshold

# API Timeouts (optional)
API_TIMEOUT=10              # General API timeout (seconds)
URL_EXPAND_TIMEOUT=5        # URL expansion timeout

# Log Level (optional)
LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

**No new dependencies!** v2.7 uses only Python stdlib additions:
- `ipaddress` (stdlib)
- `logging.handlers` (stdlib)
- `threading` (stdlib)
- `collections` (stdlib)

Existing dependencies from v2.6 still required:
- `slack-bolt`
- `python-dotenv`
- `requests`
- `shodan`
- `python-whois`
- `filelock`

### Step 5: Deploy

#### Option A: Clean Cutover (Recommended)

```bash
# Stop old bot
kill $(pgrep -f intel_bot)

# Run new bot
python intel_bot.py
```

#### Option B: Podman/Docker

```bash
# Rebuild image
podman build -t intel-bot:v2.7 .

# Stop old container
podman stop intel-bot
podman rm intel-bot

# Run new container (same env file works)
podman run -d \
  --name intel-bot \
  --restart unless-stopped \
  --env-file .env \
  -v /path/to/intel:/data \
  intel-bot:v2.7
```

### Step 6: Verify v2.7 Features

Test in Slack:

```
!help         # Should show v2.7 in the header
!stats        # NEW: Should show IOC and cache stats
!search test  # NEW: Should search IOC file
!intel 1.1.1.1   # Should show SEVERITY ASSESSMENT section
```

**Check logs:**
```bash
tail -f logs/intel_bot.log

# Should see:
# ============================================================
# ⚡ IntelBot v2.7 Starting Up...
# ============================================================
# 📡 API Status:
#   VirusTotal: ✅ Enabled
#   ...
# 💾 Cache: ✅ Enabled
#   TTL: 300s
#   Max Size: 500 items
```

### Performance Expected

Based on testing with 1,000 simulated queries:

| Metric | v2.6 | v2.7 | Improvement |
|--------|------|------|-------------|
| Avg Response Time | 847ms | 312ms | **63% faster** |
| API Calls Made | 1,000 | 412 | **59% reduction** |
| Cache Hit Rate | N/A | 58.8% | - |
| Memory Usage | 45MB | 52MB | +7MB (negligible) |

### Troubleshooting

**Issue: "Module not found" errors**

Fix:
```bash
cd /path/to/intel-butt
python3 -c "import config; import cache; print('Modules OK')"
```

Must be running from the intel-butt directory.

**Issue: Cache not working**

Check:
```bash
grep CACHE_ENABLED .env
# Should show: CACHE_ENABLED=true
```

Test:
```
!intel 1.1.1.1
!stats   # Check hit rate
!intel 1.1.1.1   # Should be instant (cached)
!stats   # Hit rate should increase
```

**Issue: Stats show 0 items but IOC file has data**

Cause: Old IOC entries (before v2.6) may not have timestamps.

Fix: Future additions will work correctly. Old entries won't show in stats.

### Rollback Plan (If Needed)

```bash
# Stop new bot
kill $(pgrep -f intel_bot)

# Restore backup
cp intel_bot_v26_backup.py intel_bot.py
cp .env.backup .env

# Start old bot
python intel_bot.py
```

---

## General Upgrade Best Practices

### Before Every Upgrade

1. **Read Release Notes**: Check [RELEASE-NOTES.md](RELEASE-NOTES.md) for breaking changes
2. **Backup Everything**:
   ```bash
   cp intel_bot.py intel_bot_backup.py
   cp .env .env.backup
   cp iocs.txt iocs.txt.backup
   ```
3. **Test in Dev**: If possible, test upgrade in non-production environment first
4. **Schedule Downtime**: Notify team of brief service interruption

### During Upgrade

1. **Pull Code**: `git pull origin main`
2. **Review Changes**: Check which files were modified
3. **Update Dependencies**: `pip install -r requirements.txt`
4. **Update Environment**: Add new optional variables to `.env`
5. **Deploy**: Restart bot with new code

### After Upgrade

1. **Monitor Logs**: Watch for errors or warnings
2. **Test Commands**: Verify all bot commands work as expected
3. **Check Metrics**: For v2.7+, use `!stats` to monitor cache performance
4. **Verify Exports**: For v2.8+, check JSON/STIX files are generated

### If Something Goes Wrong

1. **Check Logs**: `tail -f logs/intel_bot.log`
2. **Verify Environment**: Ensure all required env vars are set
3. **Test Modules**: `python3 -c "import config; print(config.Config.get_summary())"`
4. **Rollback**: Restore from backup and restart
5. **Report Issue**: Open GitHub issue with log excerpts

---

## Compatibility Matrix

| Upgrade Path | Backward Compatible | Data Migration | Downtime Required |
|--------------|---------------------|----------------|-------------------|
| v2.6 → v2.7 | ✅ Yes | ❌ No | ⚠️ Brief restart |
| v2.7 → v2.8 | ✅ Yes | ❌ No | ⚠️ Brief restart |
| v2.6 → v2.8 | ✅ Yes | ❌ No | ⚠️ Brief restart |

**Note:** All upgrades are backward compatible. No data migration required. IOC file format unchanged across all versions.

---

## Getting Help

- **Issues**: https://github.com/ILCF-BSides/intel-butt/issues
- **Slack**: #intel-sharing channel
- **Documentation**: See project root directory

---

## License

MIT License - Copyright (c) 2022-2025 Illinois Cyber Foundation, Inc.
