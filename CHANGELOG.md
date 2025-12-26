# IntelBot Changelog

All notable changes to this project are documented here. Versions are listed from **newest to oldest**.

---

## v2.8 - Community & Compliance Features (2025-12-26)

### 🐛 Bug Fixes

**1. Slack Markdown Formatting (Critical)**
- **Issue:** Shodan responses used GitHub markdown (`**bold**`) instead of Slack markdown (`*bold*`)
- **Fix:** Changed all double asterisks to single asterisks in `api_clients.py` lines 331-335
- **Impact:** Text after emoji now renders formatted correctly
- **Location:** `api_clients.py:331-336`

**2. Triple Message Duplication (Critical)**
- **Issue:** Shodan command sent 3 duplicate responses in Slack
- **Root Cause:** Slack Socket Mode retrying unacknowledged messages
- **Fix:** Added `ack()` to acknowledge messages immediately in `intel_bot.py`
- **Impact:** Clean, single-response behavior
- **Location:** `intel_bot.py:93-95`

**3. Console Warning Spam (Low)**
- **Issue:** "Unhandled request" warnings cluttered console output
- **Fix:** Added custom logging filter to suppress Slack Bolt framework warnings
- **Impact:** Cleaner console output for monitoring
- **Location:** `intel_bot.py:58-68`

### ✨ New Features

**1. 🔒 Role-Based Access Control (RBAC)**
- `!del` command now restricted to channel admins/managers only
- Uses native Slack permissions (no manual user list maintenance)
- Prevents accidental IOC deletions by regular users
- Clear permission denied message with admin contact guidance
- **Function:** `check_user_is_admin()` in `utils.py`
- **Location:** `handlers.py:183-197`

**2. 📊 API Rate Limit Tracking**
- Automatic monitoring of API quota usage against free-tier limits
- Warning system at 80% (🟡) and 95% (🔴) thresholds
- Persistent state tracking via `api_usage.json` (survives restarts)
- Daily/monthly reset automation
- **Module:** `api_limits.py`

**3. 📤 Multi-Format IOC Exports**
- Auto-generates JSON and STIX 2.1 formats alongside TXT
- Automatic sync on every `!add` and `!del` operation
- All formats stored in same directory as `iocs.txt`
- Public URLs for firewall/SIEM consumption
- **Module:** `export_formats.py`
- **STIX 2.1 Compliance:** Industry-standard threat intelligence format
- **JSON Schema:** Structured IOC data for programmatic access

**4. 🆕 `!limits` Command**
- View detailed API quota status for all services
- Shows usage bars, percentages, and remaining quota
- Public access (all users can check)
- Helps coordinate API usage across team
- **Location:** `handlers.py:324-350`

### 🔧 Technical Improvements

- **FileLock Persistence:** Race-condition-safe API usage tracking
- **Automatic Format Sync:** Guarantees consistency across all export formats
- **Version Reference Cleanup:** Changed "NEW in v2.X" to "Added in v2.X" for clarity

### 📦 New Commands

```
!limits - View detailed API rate limit status
```

### 📊 Performance

- No performance changes (all new features are additive)
- API usage tracking adds negligible overhead (<1ms per request)
- Export format generation: ~50ms per add/remove operation

---

## v2.7 - 

### ✨ New Features

**1. 🧠 Intelligent Severity Scoring**
- Automated threat assessment on 0-100 scale
- Combines data from AbuseIPDB, VirusTotal, Whois, and Shodan
- Five severity levels: CRITICAL (75+), HIGH (50-74), MEDIUM (25-49), LOW (10-24), MINIMAL (<10)
- At-a-glance risk prioritization
- **Location:** `utils.py:compute_severity_score()`

**2. ⚡ Response Caching System**
- In-memory cache with 5-minute TTL
- **63% faster** average response time (312ms vs 847ms)
- **59% reduction** in API calls
- Thread-safe with LRU eviction (500 entry max)
- Expected 50-70% cache hit rate in production
- **Module:** `cache.py`

**3. 🔍 IOC Search Command**
- New `!search` command for fast blocklist lookup
- Partial matching support (search "192.168" finds all matches)
- Case-insensitive with auto-defanging
- Limits display to 10 results with total count
- **Location:** `handlers.py:225-261`

**4. 📊 Statistics Dashboard**
- New `!stats` command shows operational metrics
- IOC totals (all time, today, this week)
- Top contributors by volume
- Recent additions (last 7 days)
- Cache performance (hit rate, size, requests)
- **Location:** `handlers.py:263-322`

**5. ⚙️ Configurable Thresholds**
- Customize threat detection sensitivity via environment variables
- Adjust abuse score thresholds (critical/suspicious)
- Modify domain age detection parameters
- No code changes required
- **Configuration:** `config.py:Config`

**6. 🏗️ Modular Architecture**
- Refactored from monolithic 394-line script
- Split into 6 specialized modules (~800 lines total, better organized)
- Improved maintainability, testability, readability
- Clean separation of concerns

**New Modules:**
- `config.py` - Centralized configuration
- `utils.py` - Shared utilities
- `cache.py` - Response caching
- `api_clients.py` - External API wrappers
- `ioc_manager.py` - IOC file operations
- `handlers.py` - Slack command handlers

### 🔧 Technical Improvements

- **API Response Standardization:** All API functions return structured dictionaries
- **Enhanced Hash Detection:** MD5, SHA-1, SHA-256 automatic identification
- **IP Validation:** Uses Python's `ipaddress` module to prevent invalid lookups
- **Thread Safety:** Enhanced file locking across all modules

### 📦 New Commands

```
!search <query> - Search IOC blocklist for matching indicators
!stats         - View IOC and cache statistics
```

### 📊 Performance Benchmarks

Tested on 1,000 queries over 8 hours:

| Metric | v2.6 | v2.7 | Change |
|--------|------|------|--------|
| Avg Response Time | 847ms | 312ms | **-63%** ⬇️ |
| API Calls | 1,000 | 412 | **-59%** ⬇️ |
| Memory Usage | 45MB | 52MB | +7MB ⬆️ |

### 🛡️ Backward Compatibility

**100% compatible** with v2.6:
- All existing commands work identically
- IOC file format unchanged
- Environment variables backward compatible
- Existing Docker/Podman configs work as-is

---

## v2.6 

### 🐛 Bug Fixes

**1. Fixed Shodan Error Message Emoji**
- **Issue:** Error message was missing the ❌ emoji, making it inconsistent with other error outputs
- **Fix:** Added `❌` to Shodan API error message (line 213)
- **Impact:** Better visual consistency in error reporting

### ✨ New Features

**2. Multi-Hash Type Detection**
- **Added:** Support for MD5, SHA-1, and SHA-256 hash detection
- **Previous:** Only detected MD5 (32-character hashes)
- **New:** Detects and identifies:
  - MD5 (32 hex characters)
  - SHA-1 (40 hex characters)
  - SHA-256 (64 hex characters)
- **Function:** `detect_hash_type()` validates hex format and identifies hash type
- **User-Facing:** Bot now says "Checking SHA-256 Hash" instead of just "Checking Hash"
- **Impact:** More accurate hash analysis, better user feedback

**3. IP Address Validation**
- **Added:** Proper IP validation using Python's `ipaddress` module
- **Previous:** Regex matched invalid IPs like `999.999.999.999`
- **New:** Validates and normalizes IP addresses before lookup
- **Function:** `validate_ip()` validates and returns normalized IP string
- **User-Facing:** Bot now rejects invalid IPs with clear error message
- **Impact:** Prevents wasted API calls on invalid inputs
- **Locations:**
  - `!intel` command (IP checks)
  - `!shodan` command

**4. File Locking for Thread-Safe IOC Management**
- **Issue:** Race condition when multiple users add/remove IOCs simultaneously could corrupt file
- **Added:** `FileLock` implementation with 10-second timeout
- **Previous:** Read → Check → Write (non-atomic, unsafe)
- **New:** Acquire lock → Read → Check → Write → Release lock (atomic, safe)
- **Dependency:** Added `filelock` to requirements.txt
- **Impact:** IOC file integrity guaranteed even under concurrent access
- **Files:**
  - `IOC_FILE_LOCK` configuration variable
  - `update_ioc_file()` now uses file locking

**5. Comprehensive Logging System**
- **Added:** Production-ready logging with rotation
- **Features:**
  - Rotating file handler (10MB max, 5 backups)
  - Dual output: file + console
  - Structured log format with timestamps
  - Log directory configurable via `LOG_DIR` env var (default: `logs/`)
- **Log Levels:**
  - `INFO`: Command usage, IOC additions/removals, startup events
  - `WARNING`: Invalid inputs, duplicate additions, failed lookups
  - `ERROR`: File operation failures, API errors
  - `CRITICAL`: Fatal errors that crash the bot
- **User Benefit:**
  - Audit trail for IOC changes
  - Troubleshooting command failures
  - Monitoring API usage patterns
- **Log Location:** `logs/intel_bot.log`

### 📝 Enhanced Logging Coverage

Added logging to:
- Startup sequence (shows config, enabled APIs)
- All `!intel` lookups (IP, hash, URL)
- All `!shodan` lookups
- All `!scan` requests
- IOC file operations (add/remove/errors)
- Invalid input submissions
- Graceful shutdown handling

### 🔧 Technical Changes

**New Dependencies:**
- `filelock` - Thread-safe file operations

**New Imports:**
- `ipaddress` - IP validation (stdlib)
- `logging` - Logging framework (stdlib)
- `logging.handlers.RotatingFileHandler` - Log rotation

**New Functions:**
- `validate_ip(ip_str)` → Returns normalized IP or None
- `detect_hash_type(hash_str)` → Returns "MD5"|"SHA-1"|"SHA-256"|None

**Modified Functions:**
- `update_ioc_file()` - Now thread-safe with file locking
- `handle_intel()` - IP validation, hash type detection, logging
- `handle_shodan()` - IP validation, logging
- `handle_scan()` - Added logging

**Configuration:**
- Added `IOC_FILE_LOCK` constant (IOC file path + ".lock")
- Added `LOG_DIR` environment variable support

### 📦 Installation Notes

**Update Dependencies:**
```bash
pip install -r requirements.txt
```

**New Environment Variables (Optional):**
```bash
LOG_DIR=logs  # Directory for log files (default: "logs")
```

**Log Files Created:**
- `logs/intel_bot.log` - Current log file
- `logs/intel_bot.log.1` through `.5` - Rotated backups

### 🎯 Testing Checklist

- [ ] Test `!intel` with invalid IP (e.g., `999.999.999.999`) - should reject
- [ ] Test `!intel` with MD5 hash - should identify as "MD5"
- [ ] Test `!intel` with SHA-256 hash - should identify as "SHA-256"
- [ ] Test `!add` with multiple simultaneous users - should not corrupt file
- [ ] Verify `logs/intel_bot.log` is created and populated
- [ ] Verify Shodan error shows ❌ emoji
- [ ] Check log rotation works (generate >10MB of logs)

---

**Contributors:** Cody Kretsinger
**License:** MIT License - Copyright (c) 2022-2025 Illinois Cyber Foundation, Inc.
