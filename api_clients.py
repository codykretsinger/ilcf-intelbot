"""
IntelBot API Clients
Wrappers for external threat intelligence APIs with caching
"""
import base64
import requests
import shodan
import whois
import logging
from datetime import datetime

from config import Config
from cache import response_cache, get_cache_key

logger = logging.getLogger("IntelBot.API")

# Initialize Shodan client
shodan_client = None
if Config.SHODAN_API_KEY:
    shodan_client = shodan.Shodan(Config.SHODAN_API_KEY)


def check_virustotal_url(target_url):
    """
    Check URL reputation on VirusTotal.

    Args:
        target_url: URL to check

    Returns:
        dict: {"verdict": str, "detections": int, "total": int, "raw": str}
    """
    if not Config.VT_API_KEY:
        return {"verdict": "❌ VirusTotal API key not configured", "detections": 0, "total": 0, "raw": "N/A"}

    # Check cache first
    cache_key = get_cache_key("url", target_url, "virustotal")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": Config.VT_API_KEY}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=Config.API_TIMEOUT)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            verdict = "🚨 MALICIOUS" if malicious > 0 else "✅ Clean"

            result = {
                "verdict": f"{verdict} ({malicious}/{total} engines)",
                "detections": malicious,
                "total": total,
                "raw": f"{malicious}/{total}"
            }
        elif resp.status_code == 404:
            result = {"verdict": "❓ URL not found in VT", "detections": 0, "total": 0, "raw": "0/0"}
        else:
            result = {"verdict": f"❌ VT Error: {resp.status_code}", "detections": 0, "total": 0, "raw": "N/A"}

        # Cache the result
        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL)

        return result

    except Exception as e:
        logger.error(f"VirusTotal URL check failed: {str(e)}")
        return {"verdict": f"❌ Error: {str(e)}", "detections": 0, "total": 0, "raw": "N/A"}


def check_virustotal_hash(file_hash):
    """
    Check file hash reputation on VirusTotal.

    Args:
        file_hash: MD5, SHA-1, or SHA-256 hash

    Returns:
        dict: {"verdict": str, "detections": int, "total": int, "raw": str}
    """
    if not Config.VT_API_KEY:
        return {"verdict": "❌ VirusTotal API key not configured", "detections": 0, "total": 0, "raw": "N/A"}

    # Check cache
    cache_key = get_cache_key("hash", file_hash, "virustotal")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": Config.VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=Config.API_TIMEOUT)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            verdict = "🚨 MALICIOUS" if malicious > 0 else "✅ Clean"

            result = {
                "verdict": f"{verdict} ({malicious}/{total} detections)",
                "detections": malicious,
                "total": total,
                "raw": f"{malicious}/{total}"
            }
        elif resp.status_code == 404:
            result = {"verdict": "❓ Hash not found", "detections": 0, "total": 0, "raw": "0/0"}
        else:
            result = {"verdict": "❌ Error", "detections": 0, "total": 0, "raw": "N/A"}

        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL)

        return result

    except Exception as e:
        logger.error(f"VirusTotal hash check failed: {str(e)}")
        return {"verdict": f"❌ Error: {str(e)}", "detections": 0, "total": 0, "raw": "N/A"}


def check_virustotal_ip(ip):
    """
    Check IP reputation on VirusTotal.

    Args:
        ip: IP address to check

    Returns:
        dict: {"verdict": str, "detections": int, "total": int, "url": str}
    """
    if not Config.VT_API_KEY:
        return {"verdict": "❌ VirusTotal API key not configured", "detections": 0, "total": 0, "url": None}

    # Check cache
    cache_key = get_cache_key("ip", ip, "virustotal")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": Config.VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=Config.API_TIMEOUT)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            total = sum(stats.values())

            combined = malicious + suspicious
            verdict = "🚨 MALICIOUS" if combined > 0 else "✅ Clean"

            result = {
                "verdict": f"{verdict} ({malicious}/{total} flagged)",
                "detections": malicious,
                "total": total,
                "url": f"https://www.virustotal.com/gui/ip-address/{ip}"
            }
        elif resp.status_code == 404:
            result = {"verdict": "❓ IP not found in VT", "detections": 0, "total": 0, "url": f"https://www.virustotal.com/gui/ip-address/{ip}"}
        else:
            result = {"verdict": f"❌ VT Error: {resp.status_code}", "detections": 0, "total": 0, "url": None}

        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL)

        return result

    except Exception as e:
        logger.error(f"VirusTotal IP check failed: {str(e)}")
        return {"verdict": f"❌ Error: {str(e)}", "detections": 0, "total": 0, "url": None}


def check_virustotal_domain(domain):
    """
    Check domain reputation on VirusTotal.

    Args:
        domain: Domain name to check

    Returns:
        dict: {"verdict": str, "detections": int, "total": int, "url": str}
    """
    if not Config.VT_API_KEY:
        return {"verdict": "❌ VirusTotal API key not configured", "detections": 0, "total": 0, "url": None}

    # Check cache
    cache_key = get_cache_key("domain", domain, "virustotal")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": Config.VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=Config.API_TIMEOUT)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            total = sum(stats.values())

            combined = malicious + suspicious
            verdict = "🚨 MALICIOUS" if combined > 0 else "✅ Clean"

            result = {
                "verdict": f"{verdict} ({malicious}/{total} flagged)",
                "detections": malicious,
                "total": total,
                "url": f"https://www.virustotal.com/gui/domain/{domain}"
            }
        elif resp.status_code == 404:
            result = {"verdict": "❓ Domain not found in VT", "detections": 0, "total": 0, "url": f"https://www.virustotal.com/gui/domain/{domain}"}
        else:
            result = {"verdict": f"❌ VT Error: {resp.status_code}", "detections": 0, "total": 0, "url": None}

        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL)

        return result

    except Exception as e:
        logger.error(f"VirusTotal domain check failed: {str(e)}")
        return {"verdict": f"❌ Error: {str(e)}", "detections": 0, "total": 0, "url": None}


def check_abuseipdb(ip):
    """
    Check IP reputation on AbuseIPDB.

    Args:
        ip: IP address to check

    Returns:
        dict: {"verdict": str, "score": int, "reports": int, "raw": str}
    """
    if not Config.ABUSE_IPDB_KEY:
        return {"verdict": "❌ AbuseIPDB API key not configured", "score": 0, "reports": 0, "raw": "N/A"}

    # Check cache
    cache_key = get_cache_key("ip", ip, "abuseipdb")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': Config.ABUSE_IPDB_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=Config.API_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()['data']
            score = data['abuseConfidenceScore']
            reports = data['totalReports']

            # Use configurable thresholds
            if score > Config.THRESHOLD_ABUSE_CRITICAL:
                verdict = "🚨 HIGH CONFIDENCE ABUSE"
            elif score > Config.THRESHOLD_ABUSE_SUSPICIOUS:
                verdict = "⚠️ Suspicious"
            else:
                verdict = "✅ Clean"

            result = {
                "verdict": f"{verdict} (Score: {score}%). Reports: {reports}",
                "score": score,
                "reports": reports,
                "raw": f"{score}%"
            }
        else:
            result = {"verdict": "❌ IPDB Error", "score": 0, "reports": 0, "raw": "N/A"}

        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL)

        return result

    except Exception as e:
        logger.error(f"AbuseIPDB check failed: {str(e)}")
        return {"verdict": f"❌ Error: {str(e)}", "score": 0, "reports": 0, "raw": "N/A"}


def check_shodan_ip(ip):
    """
    Check IP on Shodan for open ports and vulnerabilities.

    Args:
        ip: IP address to check

    Returns:
        dict: {"verdict": str, "ports": list, "vulns": int, "os": str}
    """
    if not shodan_client:
        return {"verdict": "❌ Shodan API key missing", "ports": [], "vulns": 0, "os": "Unknown"}

    # Check cache
    cache_key = get_cache_key("ip", ip, "shodan")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    try:
        from utils import defang
        host = shodan_client.host(ip)
        ports = host.get('ports', [])
        tags = host.get('tags', [])
        os_ver = host.get('os', 'Unknown')
        vulns = len(host.get('vulns', []))

        verdict = f"🌍 *Shodan Report for {defang(ip)}*\n"
        verdict += f"> *OS:* {os_ver} | *Open Ports:* {ports}\n"
        verdict += f"> *Tags:* {tags}\n"
        if vulns > 0:
            verdict += f"> 🚨 *Known Vulnerabilities:* {vulns} CVEs detected!"

        result = {
            "verdict": verdict,
            "ports": ports,
            "vulns": vulns,
            "os": os_ver,
            "tags": tags
        }

        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL * 2)  # Cache longer for Shodan

        return result

    except shodan.APIError as e:
        error_msg = f"❌ Shodan: {str(e)} (IP likely not indexed)"
        return {"verdict": error_msg, "ports": [], "vulns": 0, "os": "Unknown"}
    except Exception as e:
        logger.error(f"Shodan check failed: {str(e)}")
        return {"verdict": f"❌ Error: {str(e)}", "ports": [], "vulns": 0, "os": "Unknown"}


def check_domain_age(domain):
    """
    Check domain age via Whois lookup.

    Args:
        domain: Domain name to check

    Returns:
        dict: {"verdict": str, "age_days": int, "creation_date": str}
    """
    # Check cache
    cache_key = get_cache_key("domain", domain, "whois")
    if Config.CACHE_ENABLED:
        cached = response_cache.get(cache_key)
        if cached:
            logger.debug(f"Cache HIT: {cache_key}")
            return cached

    try:
        w = whois.whois(domain)
        c_date = w.creation_date
        if isinstance(c_date, list):
            c_date = c_date[0]
        if not c_date:
            return {"verdict": "❓ Age Unknown (Whois privacy?)", "age_days": 999, "creation_date": "Unknown"}

        age = datetime.now() - c_date
        days = age.days

        # Use configurable thresholds
        if days < Config.THRESHOLD_DOMAIN_CRITICAL_DAYS:
            verdict = f"🚨 **CRITICAL: Registered YESTERDAY!** ({days} days old)"
        elif days < Config.THRESHOLD_DOMAIN_NEW_DAYS:
            verdict = f"⚠️ **Suspiciously New:** {days} days old"
        else:
            verdict = f"✅ Established: {days} days old (Created: {c_date.date()})"

        result = {
            "verdict": verdict,
            "age_days": days,
            "creation_date": str(c_date.date())
        }

        if Config.CACHE_ENABLED:
            response_cache.set(cache_key, result, Config.CACHE_TTL * 4)  # Cache much longer for Whois

        return result

    except Exception as e:
        logger.warning(f"Whois lookup failed for {domain}: {str(e)}")
        return {"verdict": "❓ Whois lookup failed", "age_days": 999, "creation_date": "Unknown"}


def scan_url_sandbox(target_url):
    """
    Submit URL to URLScan.io sandbox.

    Args:
        target_url: URL to scan

    Returns:
        str: Scan result message
    """
    if not Config.URLSCAN_API_KEY:
        return "❌ No URLScan API Key configured."

    headers = {'API-Key': Config.URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": target_url, "visibility": "public"}

    try:
        resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=Config.API_TIMEOUT)
        if resp.status_code == 200:
            result = resp.json()
            return f"🚀 **Scan Started!** View results here: {result['result']}"
        elif resp.status_code == 429:
            return "❌ Rate Limit Exceeded."
        else:
            return f"❌ URLScan Error: {resp.status_code}"
    except Exception as e:
        logger.error(f"URLScan submission failed: {str(e)}")
        return f"❌ Error: {str(e)}"
