"""
API Rate Limit Tracking
Monitors API usage and warns when approaching limits
"""
import os
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from filelock import FileLock

logger = logging.getLogger("IntelBot.APILimits")

# Rate limit definitions (requests per period)
RATE_LIMITS = {
    "virustotal": {"daily": 500, "minute": 4},
    "abuseipdb": {"daily": 1000},
    "shodan": {"monthly": 100},
    "urlscan": {"daily": 50}
}

# Warning thresholds (percentage of limit)
WARNING_THRESHOLD = 0.80  # Warn at 80%
CRITICAL_THRESHOLD = 0.95  # Critical at 95%


class RateLimitTracker:
    """Track API usage and check against limits."""

    def __init__(self, state_file="api_usage.json"):
        self.state_file = state_file
        self.lock_file = state_file + ".lock"
        self.usage = self._load_state()

    def _load_state(self):
        """Load usage state from file."""
        if not os.path.exists(self.state_file):
            return self._init_state()

        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load API usage state: {e}")
            return self._init_state()

    def _init_state(self):
        """Initialize empty usage state."""
        return {
            "virustotal": {
                "daily": 0,
                "minute": 0,
                "last_reset_daily": str(datetime.now().date()),
                "last_reset_minute": datetime.now().isoformat()
            },
            "abuseipdb": {
                "daily": 0,
                "last_reset_daily": str(datetime.now().date())
            },
            "shodan": {
                "monthly": 0,
                "last_reset_monthly": str(datetime.now().replace(day=1).date())
            },
            "urlscan": {
                "daily": 0,
                "last_reset_daily": str(datetime.now().date())
            }
        }

    def _save_state(self):
        """Save usage state to file with locking."""
        lock = FileLock(self.lock_file, timeout=5)
        try:
            with lock:
                with open(self.state_file, 'w') as f:
                    json.dump(self.usage, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save API usage state: {e}")

    def _reset_if_needed(self, api):
        """Reset counters if time period has elapsed."""
        now = datetime.now()
        api_data = self.usage[api]

        # Daily reset
        if "daily" in api_data:
            last_reset = datetime.fromisoformat(api_data["last_reset_daily"] + "T00:00:00")
            if now.date() > last_reset.date():
                api_data["daily"] = 0
                api_data["last_reset_daily"] = str(now.date())
                logger.info(f"{api} daily counter reset")

        # Minute reset (for VirusTotal)
        if "minute" in api_data:
            last_reset = datetime.fromisoformat(api_data["last_reset_minute"])
            if (now - last_reset).total_seconds() >= 60:
                api_data["minute"] = 0
                api_data["last_reset_minute"] = now.isoformat()

        # Monthly reset (for Shodan)
        if "monthly" in api_data:
            last_reset = datetime.fromisoformat(api_data["last_reset_monthly"] + "T00:00:00")
            if now.month > last_reset.month or now.year > last_reset.year:
                api_data["monthly"] = 0
                api_data["last_reset_monthly"] = str(now.replace(day=1).date())
                logger.info(f"{api} monthly counter reset")

    def record_request(self, api):
        """
        Record an API request and check limits.

        Args:
            api: API name (virustotal, abuseipdb, shodan, urlscan)

        Returns:
            dict: {
                "allowed": bool,
                "warning": str or None,
                "usage": dict with current counts
            }
        """
        self._reset_if_needed(api)

        api_data = self.usage[api]
        limits = RATE_LIMITS[api]
        warnings = []

        # Check each limit type
        for period, limit in limits.items():
            current = api_data[period]
            percentage = (current / limit) if limit > 0 else 0

            # Check if we're at the limit
            if current >= limit:
                return {
                    "allowed": False,
                    "warning": f"🚨 **{api.upper()} RATE LIMIT EXCEEDED**\n> {period.capitalize()}: {current}/{limit} requests used",
                    "usage": {period: {"current": current, "limit": limit, "percentage": percentage}}
                }

            # Check for warnings
            if percentage >= CRITICAL_THRESHOLD:
                warnings.append(
                    f"⚠️ **{api.upper()} CRITICAL**: {int(percentage*100)}% of {period} limit used ({current}/{limit})"
                )
            elif percentage >= WARNING_THRESHOLD:
                warnings.append(
                    f"ℹ️ **{api.upper()} Warning**: {int(percentage*100)}% of {period} limit used ({current}/{limit})"
                )

        # Increment counters
        for period in limits.keys():
            api_data[period] += 1

        self._save_state()

        return {
            "allowed": True,
            "warning": warnings[0] if warnings else None,
            "usage": {period: {"current": api_data[period], "limit": limits[period]} for period in limits.keys()}
        }

    def get_usage_summary(self):
        """Get current usage for all APIs."""
        summary = {}
        for api in RATE_LIMITS.keys():
            self._reset_if_needed(api)
            api_data = self.usage[api]
            limits = RATE_LIMITS[api]

            summary[api] = {}
            for period, limit in limits.items():
                current = api_data[period]
                percentage = int((current / limit) * 100) if limit > 0 else 0
                summary[api][period] = {
                    "current": current,
                    "limit": limit,
                    "percentage": percentage,
                    "remaining": limit - current
                }

        return summary


# Global tracker instance
rate_tracker = RateLimitTracker()
