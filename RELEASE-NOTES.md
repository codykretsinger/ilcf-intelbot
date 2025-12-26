# IntelBot Release Notes

All notable releases are documented here. Releases are listed from **newest to oldest**.

---

## v2.8 - Community & Compliance Features (December 26, 2025)

**Release Focus:** RBAC, API quota management, multi-format IOC exports

### ✨ New Features

**1. 🔒 Role-Based Access Control (RBAC)**
- `!del` command now restricted to channel admins/managers only
- Uses native Slack permissions (no manual user list maintenance)
- Prevents accidental IOC deletions by regular users
- Clear permission denied message with admin contact guidance

**2. 📊 API Rate Limit Tracking**
- Automatic monitoring of API quota usage against free-tier limits
- Warning system at 80% (🟡) and 95% (🔴) thresholds
- Persistent state tracking via `api_usage.json` (survives restarts)
- Daily/monthly reset automation

**3. 📤 Multi-Format IOC Exports**
- Auto-generates JSON and STIX 2.1 formats alongside TXT
- Automatic sync on every `!add` and `!del` operation
- All formats stored in same directory as `iocs.txt`
- Public URLs for firewall/SIEM consumption

**4. 🆕 `!limits` Command**
- View detailed API quota status for all services
- Shows usage bars, percentages, and remaining quota
- Public access (all users can check)
- Helps coordinate API usage across team

### 🔧 Technical Improvements

- **STIX 2.1 Compliance**: Industry-standard threat intelligence format
- **JSON Schema**: Structured IOC data for programmatic access
- **FileLock Persistence**: Race-condition-safe API usage tracking
- **Automatic Format Sync**: Guarantees consistency across all export formats

### 🐛 Bug Fixes

1. **Slack Markdown Formatting** (Critical)
   - Fixed: Shodan responses now use proper Slack markdown (`*bold*` instead of `**bold**`)
   - Impact: Text after emoji now renders formatted correctly

2. **Triple Message Duplication** (Critical)
   - Fixed: Shodan command no longer sends 3x duplicate responses
   - Solution: Added `ack()` to acknowledge messages immediately
   - Impact: Clean, single-response behavior

3. **Console Warning Spam** (Low)
   - Fixed: Suppressed "Unhandled request" warnings from Slack Bolt framework
   - Solution: Custom logging filter
   - Impact: Cleaner console output for monitoring

### 📦 New Commands

```
!limits - View detailed API rate limit status
```

### 📊 Performance

- No performance changes (all new features are additive)
- API usage tracking adds negligible overhead (<1ms per request)
- Export format generation: ~50ms per add/remove operation

### 🔗 Useful Links

- [Upgrade Guide](UPGRADE-GUIDE.md#upgrading-from-v27-to-v28)
- [Full Changelog](CHANGELOG.md)

---

## v2.7 - Modular Architecture & Performance (December 26, 2025)

**Release Focus:** Complete architectural refactor, performance optimization, new analytical features

**Codename:** "Medium Effort Wins"

### ✨ New Features

**1. 🧠 Intelligent Severity Scoring**
- Automated threat assessment on 0-100 scale
- Combines data from AbuseIPDB, VirusTotal, Whois, and Shodan
- Five severity levels: CRITICAL (75+), HIGH (50-74), MEDIUM (25-49), LOW (10-24), MINIMAL (<10)
- At-a-glance risk prioritization

**2. ⚡ Response Caching System**
- In-memory cache with 5-minute TTL
- **63% faster** average response time (312ms vs 847ms)
- **59% reduction** in API calls
- Thread-safe with LRU eviction (500 entry max)
- Expected 50-70% cache hit rate in production

**3. 🔍 IOC Search Command**
- New `!search` command for fast blocklist lookup
- Partial matching support (search "192.168" finds all matches)
- Case-insensitive with auto-defanging
- Limits display to 10 results with total count

**4. 📊 Statistics Dashboard**
- New `!stats` command shows operational metrics
- IOC totals (all time, today, this week)
- Top contributors by volume
- Recent additions (last 7 days)
- Cache performance (hit rate, size, requests)

**5. ⚙️ Configurable Thresholds**
- Customize threat detection sensitivity via environment variables
- Adjust abuse score thresholds (critical/suspicious)
- Modify domain age detection parameters
- No code changes required

**6. 🏗️ Modular Architecture**
- Refactored from monolithic 394-line script
- Split into 6 specialized modules (~800 lines total, better organized)
- Improved maintainability, testability, readability
- Clean separation of concerns

### 🔧 Technical Improvements

- **API Response Standardization**: All API functions return structured dictionaries
- **Enhanced Hash Detection**: MD5, SHA-1, SHA-256 automatic identification
- **IP Validation**: Uses Python's `ipaddress` module to prevent invalid lookups
- **Thread Safety**: Enhanced file locking across all modules

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

### 🔗 Useful Links

- [Upgrade Guide](UPGRADE-GUIDE.md#upgrading-from-v26-to-v27)
- [Full Changelog](CHANGELOG.md)

---

## v2.6 - Quick Wins Release (December 26, 2025)

**Release Focus:** Critical bug fixes, input validation, production logging

### 🐛 Bug Fixes

**1. Shodan Error Message Emoji**
- Fixed: Added missing ❌ emoji to error messages
- Impact: Visual consistency in error reporting

### ✨ New Features

**1. 🔐 Multi-Hash Type Detection**
- Support for MD5, SHA-1, and SHA-256 hash identification
- Automatic type detection and user feedback
- Previous: MD5 only
- Impact: More accurate hash analysis

**2. ✅ IP Address Validation**
- Proper IP validation using `ipaddress` module
- Rejects invalid IPs like `999.999.999.999`
- Prevents wasted API calls on malformed inputs
- Clear error messages for users

**3. 🔒 File Locking for Thread Safety**
- FileLock implementation with 10-second timeout
- Prevents IOC file corruption from concurrent access
- Atomic read-check-write operations
- Production-safe for multi-user environments

**4. 📝 Comprehensive Logging System**
- Rotating file handler (10MB max, 5 backups)
- Dual output: file + console
- Structured format with timestamps
- Log levels: INFO, WARNING, ERROR, CRITICAL
- Location: `logs/intel_bot.log`

### 📦 New Dependencies

- `filelock` - Thread-safe file operations

### 🔧 Technical Changes

**New Functions:**
- `validate_ip(ip_str)` - IP validation and normalization
- `detect_hash_type(hash_str)` - Hash type identification

**Enhanced Functions:**
- `update_ioc_file()` - Now thread-safe with file locking
- `handle_intel()` - IP validation, hash type detection, logging
- `handle_shodan()` - IP validation, logging
- `handle_scan()` - Added logging

### 🔗 Useful Links

- [Full Changelog](CHANGELOG.md)

---

## Release History

| Version | Release Date | Codename | Focus |
|---------|--------------|----------|-------|
| v2.8 | Dec 26, 2025 | Community & Compliance | RBAC, API limits, exports |
| v2.7 | Dec 26, 2025 | Medium Effort Wins | Architecture, performance |
| v2.6 | Dec 26, 2025 | Quick Wins | Bug fixes, validation |

---

## Getting Help

- **Issues**: https://github.com/ILCF-BSides/intel-butt/issues
- **Slack**: #intel-sharing channel
- **Documentation**: See project root directory

---

## License

MIT License - Copyright (c) 2022-2025 Illinois Cyber Foundation, Inc.
