"""
IntelBot Slack Command Handlers
All Slack message handlers for bot commands
"""
import re
import logging

from utils import defang, validate_ip, detect_hash_type, expand_url, extract_domain, calculate_severity_score, format_severity_verdict, check_user_is_admin
from api_clients import check_abuseipdb, check_virustotal_hash, check_virustotal_url, check_virustotal_ip, check_virustotal_domain, check_domain_age, check_shodan_ip, scan_url_sandbox
from ioc_manager import check_internal_list, update_ioc_file, search_ioc_file, get_ioc_stats
from cache import response_cache
from api_limits import rate_tracker
from config import Config

logger = logging.getLogger("IntelBot.Handlers")


def handle_intel(message, say):
    """
    Main intelligence lookup command.
    Checks IPs, hashes, URLs, and domains against multiple threat intel sources.
    """
    text = message.get("text", "").replace("<", "").replace(">", "").split("|")[0]
    ts = message['ts']
    response = []

    # Severity tracking for final assessment
    severity_data = {
        "abuse_score": 0,
        "vt_detections": 0,
        "domain_age_days": 999,
        "shodan_vulns": 0
    }

    # 0. CHECK INTERNAL LIST FIRST
    parts = text.split()
    if len(parts) > 1:
        internal_match = check_internal_list(parts[1])
        if internal_match:
            response.append(f"⚠️ **INTERNAL MATCH:** This is already in our Blocklist!\n> `{internal_match}`")

    # 1. IP Check
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if ip_match:
        ip = ip_match.group(0)
        validated_ip = validate_ip(ip)
        if validated_ip:
            say(f"🔎 *Checking IP:* `{defang(validated_ip)}`...", thread_ts=ts)

            # VirusTotal IP check
            vt_ip_result = check_virustotal_ip(validated_ip)
            vt_verdict = f"*VirusTotal:* {vt_ip_result['verdict']}"
            if vt_ip_result.get('url'):
                vt_verdict += f" | <{vt_ip_result['url']}|View Report>"
            response.append(vt_verdict)
            severity_data["vt_detections"] = vt_ip_result["detections"]

            # AbuseIPDB
            abuse_result = check_abuseipdb(validated_ip)
            abuse_verdict = f"*AbuseIPDB:* {abuse_result['verdict']}"
            abuse_verdict += f" | <https://www.abuseipdb.com/check/{validated_ip}|View Report>"
            response.append(abuse_verdict)
            severity_data["abuse_score"] = abuse_result["score"]

            # Shodan (if available)
            shodan_result = check_shodan_ip(validated_ip)
            if shodan_result['vulns'] > 0:
                response.append(f"*Shodan:* {shodan_result['vulns']} CVEs found! | <https://www.shodan.io/host/{validated_ip}|View Report>")
                severity_data["shodan_vulns"] = shodan_result['vulns']

            logger.info(f"IP lookup: {validated_ip}")
        else:
            say(f"⚠️ Invalid IP address: `{ip}`", thread_ts=ts)
            logger.warning(f"Invalid IP submitted: {ip}")
            ip_match = None  # Reset so we don't skip other checks

    # 2. Hash Check (MD5, SHA-1, SHA-256)
    hash_match = re.search(r'\b[a-fA-F0-9]{32,64}\b', text)
    if hash_match:
        f_hash = hash_match.group(0)
        hash_type = detect_hash_type(f_hash)
        if hash_type:
            say(f"🔎 *Checking {hash_type} Hash:* `{f_hash}`...", thread_ts=ts)

            vt_result = check_virustotal_hash(f_hash)
            vt_verdict = f"*VirusTotal:* {vt_result['verdict']}"
            vt_verdict += f" | <https://www.virustotal.com/gui/file/{f_hash}|View Report>"
            response.append(vt_verdict)
            severity_data["vt_detections"] = vt_result["detections"]

            logger.info(f"Hash lookup: {f_hash} (Type: {hash_type})")
        else:
            say(f"⚠️ Invalid hash format detected: `{f_hash}`", thread_ts=ts)

    # 3. URL/Domain Check
    url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    if url_match and not ip_match:
        raw_url = url_match.group(0)
        say(f"🔎 *Checking URL & Domain:* `{defang(raw_url)}`...", thread_ts=ts)

        final_url = expand_url(raw_url)
        domain = extract_domain(final_url)

        # VirusTotal URL check
        vt_url_result = check_virustotal_url(final_url)
        vt_url_verdict = f"*VirusTotal (URL):* {vt_url_result['verdict']}"
        # Use base64-encoded URL ID for VT link
        import base64
        url_id = base64.urlsafe_b64encode(final_url.encode()).decode().strip("=")
        vt_url_verdict += f" | <https://www.virustotal.com/gui/url/{url_id}|View Report>"
        response.append(vt_url_verdict)
        severity_data["vt_detections"] = vt_url_result["detections"]

        # VirusTotal Domain check
        vt_domain_result = check_virustotal_domain(domain)
        vt_domain_verdict = f"*VirusTotal (Domain):* {vt_domain_result['verdict']}"
        if vt_domain_result.get('url'):
            vt_domain_verdict += f" | <{vt_domain_result['url']}|View Report>"
        response.append(vt_domain_verdict)
        # Add domain detections to severity (take max of URL and domain)
        severity_data["vt_detections"] = max(severity_data["vt_detections"], vt_domain_result["detections"])

        # Domain age check
        domain_result = check_domain_age(domain)
        response.append(f"*Whois Age:* {domain_result['verdict']}")
        severity_data["domain_age_days"] = domain_result["age_days"]

    # 4. Calculate and display severity assessment
    if any([ip_match, hash_match, url_match]):
        score, label, emoji = calculate_severity_score(**severity_data)
        severity_verdict = format_severity_verdict(score, label, emoji)
        response.append(severity_verdict)

    if not response:
        say("No valid indicators found. Try `!help`.", thread_ts=ts)
    else:
        say("\n".join(response), thread_ts=ts)


def handle_scan(message, say):
    """Submit URL to URLScan.io sandbox."""
    text = message.get("text", "").replace("<", "").replace(">", "").split("|")[0]
    url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    if url_match:
        url = url_match.group(0)
        logger.info(f"URLScan requested: {url}")
        say(scan_url_sandbox(url), thread_ts=message['ts'])
    else:
        say("❌ Please provide a valid URL (starting with http/https).", thread_ts=message['ts'])


def handle_shodan(message, say):
    """Check IP on Shodan for ports and vulnerabilities."""
    text = message.get("text", "")
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if ip_match:
        ip = ip_match.group(0)
        validated_ip = validate_ip(ip)
        if validated_ip:
            logger.info(f"Shodan lookup requested: {validated_ip}")
            result = check_shodan_ip(validated_ip)
            say(result['verdict'], thread_ts=message['ts'])
        else:
            say(f"❌ Invalid IP address: `{ip}`. Please provide a valid IPv4 address.", thread_ts=message['ts'])
            logger.warning(f"Invalid IP submitted to !shodan: {ip}")
    else:
        say("❌ Please provide a valid IP address.", thread_ts=message['ts'])


def handle_add_ioc(message, say):
    """Add indicator to IOC blocklist."""
    text = message.get("text", "").replace("<", "").replace(">", "").split("|")[0]
    parts = text.split()
    if len(parts) > 1:
        indicator = parts[1]
        reason = " ".join(parts[2:]) if len(parts) > 2 else "No reason provided"
        result = update_ioc_file("add", indicator, message.get("user"), reason)
        say(result, thread_ts=message['ts'])
    else:
        say("❌ Usage: `!add <indicator> [optional reason]`", thread_ts=message['ts'])


def handle_remove_ioc(message, say, app):
    """
    Remove indicator from IOC blocklist (ADMIN ONLY).
    Requires workspace admin or channel creator permissions.
    """
    user_id = message.get("user")
    channel_id = message.get("channel")

    # RBAC check - restrict to admins only
    if not check_user_is_admin(app, user_id, channel_id):
        say(
            "🚫 *Permission Denied*\n"
            "> Only channel managers/admins can remove IOCs.\n"
            "> Contact an admin if this indicator needs removal.",
            thread_ts=message['ts']
        )
        logger.warning(f"User {user_id} attempted !del without permissions")
        return

    # Permission granted, proceed with removal
    text = message.get("text", "").replace("<", "").replace(">", "").split("|")[0]
    parts = text.split()
    if len(parts) > 1:
        result = update_ioc_file("remove", parts[1], user_id)
        say(result, thread_ts=message['ts'])
    else:
        say("❌ Usage: `!del <indicator>`", thread_ts=message['ts'])


def handle_list_ioc(message, say):
    """Show public URLs of IOC lists in all formats."""
    response = (
        "📋 *IOC Blocklist - Available Formats*\n\n"
        "*Available Formats:*\n"
        f"> 📄 Text: {Config.IOC_PUBLIC_URL}\n"
        f"> 📊 JSON: {Config.IOC_JSON_URL}\n"
        f"> 🔗 STIX 2.1: {Config.IOC_STIX_URL}\n\n"
        "_All formats are auto-synced when IOCs are added/removed_"
    )
    say(response, thread_ts=message['ts'])


def handle_search_ioc(message, say):
    """
    Search IOC file for matching indicators.
    Added in v2.7
    """
    text = message.get("text", "").replace("<", "").replace(">", "").split("|")[0]
    parts = text.split()

    if len(parts) < 2:
        say("❌ Usage: `!search <query>` - Search for indicators in the IOC list", thread_ts=message['ts'])
        return

    query = " ".join(parts[1:])
    logger.info(f"IOC search requested: {query}")

    matches = search_ioc_file(query)

    if not matches:
        say(f"🔍 No results found for: `{defang(query)}`", thread_ts=message['ts'])
        return

    # Limit results to 10 to avoid spam
    display_matches = matches[:10]
    more_count = len(matches) - 10

    response = f"🔍 *Search Results for:* `{defang(query)}`\n\n"
    for match in display_matches:
        # Defang the entire line for safety
        response += f"> {defang(match)}\n"

    if more_count > 0:
        response += f"\n_...and {more_count} more results (showing first 10)_"

    response += f"\n\n*Total Matches:* {len(matches)}"

    say(response, thread_ts=message['ts'])


def handle_stats(message, say):
    """
    Show IOC file and cache statistics.
    Added in v2.7
    """
    logger.info("Stats requested")

    # Get IOC stats
    ioc_stats = get_ioc_stats()

    # Get cache stats
    cache_stats = response_cache.get_stats()

    # Get rate limit summary
    rate_summary = rate_tracker.get_usage_summary()

    # Build response
    response = "📊 *IntelBot Statistics*\n\n"

    # IOC Stats
    response += "*🛡️ IOC Blocklist:*\n"
    response += f"> Total Indicators: `{ioc_stats['total']}`\n"
    response += f"> Added Today: `{ioc_stats['today']}`\n"
    response += f"> Added This Week: `{ioc_stats['this_week']}`\n"

    # Top contributors
    if ioc_stats['top_contributors']:
        response += "\n*👥 Top Contributors:*\n"
        for user, count in ioc_stats['top_contributors'][:3]:
            response += f"> {user}: `{count}` additions\n"

    # Recent additions
    if ioc_stats['recent_additions']:
        response += "\n*🆕 Recent Additions (Last 7 Days):*\n"
        for item in ioc_stats['recent_additions'][:3]:
            days_text = "today" if item['days_ago'] == 0 else f"{item['days_ago']}d ago"
            response += f"> `{defang(item['indicator'])}` ({days_text})\n"

    # Cache stats
    if Config.CACHE_ENABLED:
        response += "\n*💾 Response Cache:*\n"
        response += f"> Hit Rate: `{cache_stats['hit_rate']}%`\n"
        response += f"> Cached Items: `{cache_stats['size']}/{cache_stats['max_size']}`\n"
        response += f"> Total Requests: `{cache_stats['total_requests']}`\n"
        response += f"> Hits: `{cache_stats['hits']}` | Misses: `{cache_stats['misses']}`\n"
    else:
        response += "\n*💾 Response Cache:* Disabled\n"

    # API Rate Limit Summary (compact version)
    response += "\n*📡 API Usage (Daily):*\n"
    for api, periods in rate_summary.items():
        if 'daily' in periods:
            stats = periods['daily']
            emoji = "🟢" if stats['percentage'] < 80 else "🟡" if stats['percentage'] < 95 else "🔴"
            response += f"> {emoji} {api.upper()}: {stats['current']}/{stats['limit']} ({stats['percentage']}%)\n"

    response += "\n_Use `!limits` for detailed API quota information_"

    say(response, thread_ts=message['ts'])


def handle_api_limits(message, say):
    """
    Show current API usage and rate limits.
    Added in v2.8 - Public access for transparency
    """
    logger.info("API limits requested")
    summary = rate_tracker.get_usage_summary()

    response = "📊 *API Rate Limit Status*\n\n"

    for api, periods in summary.items():
        response += f"*{api.upper()}*\n"
        for period, stats in periods.items():
            bar_length = 20
            filled = int((stats['percentage'] / 100) * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)

            emoji = "🟢" if stats['percentage'] < 80 else "🟡" if stats['percentage'] < 95 else "🔴"

            response += f"> {emoji} {period.capitalize()}: {stats['current']}/{stats['limit']} ({stats['percentage']}%)\n"
            response += f"> {bar} ({stats['remaining']} remaining)\n"
        response += "\n"

    response += "_Limits reset daily (monthly for Shodan). Use `!stats` for overall bot statistics._"

    say(response, thread_ts=message['ts'])


def handle_help(message, say):
    """Show command reference."""
    help_text = (
        "🛡️ *IntelBot v2.8 Command Reference*\n\n"
        "*Analysis & Threat Hunting:*\n"
        "> `!intel <target>` : Main command with *direct report links*! Checks:\n"
        ">   • IPs: VirusTotal, AbuseIPDB, Shodan\n"
        ">   • Domains: VirusTotal (domain + URL), Whois age\n"
        ">   • Hashes: VirusTotal file analysis\n"
        ">   • All results include clickable links to full reports!\n"
        "> `!scan <url>` : Submits a URL to *URLScan.io* sandbox for deep analysis.\n"
        "> `!shodan <ip>` : Checks *Shodan* for open ports, OS, and vulnerabilities.\n\n"
        "*Blocklist Management:*\n"
        "> `!add <target> [reason]` : Adds IP/Domain/Hash to the IOC blocklist.\n"
        "> `!del <target>` : 🔒 **(Admin Only)** Removes an item from the list.\n"
        "> `!list` : Shows public links to IOC files (TXT, JSON, STIX formats).\n"
        "> `!search <query>` : Search the IOC list for matching indicators.\n\n"
        "*Statistics & Monitoring:*\n"
        "> `!stats` : Show IOC list, cache, and API usage statistics.\n"
        "> `!limits` : 🆕 View detailed API rate limit status.\n\n"
        "_Note: Malicious URLs are automatically 'defanged' (hxxp://) for safety._\n"
        "_Responses are cached for 5 minutes to reduce API usage._\n"
        "_IOC list auto-exported to JSON & STIX 2.1 formats._"
    )
    say(help_text, thread_ts=message['ts'])
