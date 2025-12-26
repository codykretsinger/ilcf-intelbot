"""
IntelBot Utility Functions
Shared helpers for formatting, validation, and common operations
"""
import re
import ipaddress
import requests
import logging
from datetime import datetime

logger = logging.getLogger("IntelBot.Utils")


def defang(text):
    """Safety: Converts http->hxxp and .->[.] to prevent accidental clicks."""
    if not text:
        return ""
    return text.replace("http", "hxxp").replace(".", "[.]")


def get_timestamp():
    """Returns current timestamp in standardized format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_ip(ip_str):
    """
    Validates an IP address and returns the normalized version.

    Args:
        ip_str: String representation of IP address

    Returns:
        str: Normalized IP address, or None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError:
        return None


def detect_hash_type(hash_str):
    """
    Detects hash type based on length and character set.

    Args:
        hash_str: String that might be a hash

    Returns:
        str: "MD5", "SHA-1", "SHA-256", or None
    """
    hash_str = hash_str.strip().lower()

    # Check if it's a valid hex string
    if not re.match(r'^[a-f0-9]+$', hash_str):
        return None

    hash_len = len(hash_str)
    if hash_len == 32:
        return "MD5"
    elif hash_len == 40:
        return "SHA-1"
    elif hash_len == 64:
        return "SHA-256"
    else:
        return None


def expand_url(short_url):
    """
    Follows URL redirects to reveal final destination.

    Args:
        short_url: Potentially shortened URL

    Returns:
        str: Final URL after following redirects
    """
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        return short_url


def extract_domain(url):
    """
    Extracts domain from a full URL.

    Args:
        url: Full URL string

    Returns:
        str: Domain portion of URL
    """
    try:
        # Remove protocol
        domain = url.split("//")[-1]
        # Remove path
        domain = domain.split("/")[0]
        # Remove port
        domain = domain.split(":")[0]
        return domain
    except Exception:
        return url


def calculate_severity_score(abuse_score=0, vt_detections=0, domain_age_days=999, shodan_vulns=0):
    """
    Calculates overall threat severity on 0-100 scale.

    Scoring:
    - AbuseIPDB score: 0-40 points (direct mapping)
    - VT detections: 0-30 points (5 detections = max)
    - Domain age: 0-20 points (< 7 days = max)
    - Shodan CVEs: 0-10 points (5+ CVEs = max)

    Args:
        abuse_score: AbuseIPDB confidence score (0-100)
        vt_detections: Number of VirusTotal engine detections
        domain_age_days: Age of domain in days
        shodan_vulns: Number of known vulnerabilities from Shodan

    Returns:
        tuple: (severity_score, severity_label, severity_emoji)
    """
    score = 0

    # AbuseIPDB contribution (0-40 points, capped at 40)
    score += min(abuse_score * 0.4, 40)

    # VirusTotal contribution (0-30 points, max at 5 detections)
    score += min((vt_detections / 5.0) * 30, 30)

    # Domain age contribution (0-20 points)
    if domain_age_days < 1:
        score += 20
    elif domain_age_days < 7:
        score += 15
    elif domain_age_days < 30:
        score += 10
    elif domain_age_days < 90:
        score += 5

    # Shodan CVE contribution (0-10 points, max at 5 CVEs)
    score += min((shodan_vulns / 5.0) * 10, 10)

    # Determine severity level
    if score >= 75:
        return (score, "CRITICAL", "🚨")
    elif score >= 50:
        return (score, "HIGH", "⚠️")
    elif score >= 25:
        return (score, "MEDIUM", "⚡")
    elif score >= 10:
        return (score, "LOW", "ℹ️")
    else:
        return (score, "MINIMAL", "✅")


def format_severity_verdict(score, label, emoji):
    """
    Formats severity assessment as Slack message.

    Args:
        score: Numerical severity score (0-100)
        label: Severity label (CRITICAL, HIGH, etc.)
        emoji: Emoji for severity level

    Returns:
        str: Formatted message for Slack
    """
    # Color bar visualization
    bar_length = 20
    filled = int((score / 100) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)

    return (
        f"\n*{emoji} THREAT ASSESSMENT: {label}*\n"
        f"> Severity Score: `{score:.1f}/100` {bar}"
    )


def check_user_is_admin(app, user_id, channel_id):
    """
    Check if user has admin/manager privileges in channel.
    Uses Slack API to verify workspace admin or channel creator status.

    Args:
        app: Slack Bolt app instance
        user_id: Slack user ID
        channel_id: Slack channel ID

    Returns:
        bool: True if user is admin/owner/manager, False otherwise
    """
    try:
        # Check if user is workspace admin/owner
        user_info = app.client.users_info(user=user_id)
        if user_info['user'].get('is_admin') or user_info['user'].get('is_owner'):
            logger.info(f"User {user_id} is workspace admin/owner")
            return True

        # Check if user is channel creator
        channel_info = app.client.conversations_info(channel=channel_id)
        if channel_info['channel'].get('creator') == user_id:
            logger.info(f"User {user_id} is channel creator")
            return True

        logger.info(f"User {user_id} does not have admin privileges")
        return False

    except Exception as e:
        logger.error(f"Permission check failed for user {user_id}: {str(e)}")
        # Fail closed - deny access if we can't verify
        return False
