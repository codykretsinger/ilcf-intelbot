"""
IntelBot Configuration
Centralized configuration with environment variable support
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Centralized configuration from environment variables."""

    # Slack Credentials
    SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
    SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")

    # API Keys
    VT_API_KEY = os.getenv("VT_API_KEY")
    ABUSE_IPDB_KEY = os.getenv("ABUSE_IPDB_KEY")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

    # IOC Management
    IOC_FILE_PATH = os.getenv("IOC_FILE_PATH", "iocs.txt")
    IOC_PUBLIC_URL = os.getenv("IOC_PUBLIC_URL", "http://localhost/iocs.txt")

    # Derived paths - all in same directory (NEW in v2.8)
    IOC_JSON_PATH = IOC_FILE_PATH.rsplit('.', 1)[0] + '.json'  # e.g., iocs.json
    IOC_STIX_PATH = IOC_FILE_PATH.rsplit('.', 1)[0] + '.stix'  # e.g., iocs.stix
    IOC_JSON_URL = IOC_PUBLIC_URL.rsplit('.', 1)[0] + '.json'
    IOC_STIX_URL = IOC_PUBLIC_URL.rsplit('.', 1)[0] + '.stix'

    # Logging
    LOG_DIR = os.getenv("LOG_DIR", "logs")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # Caching
    CACHE_ENABLED = os.getenv("CACHE_ENABLED", "true").lower() == "true"
    CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))  # 5 minutes default
    CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "500"))

    # Threat Detection Thresholds (Configurable)
    THRESHOLD_ABUSE_CRITICAL = int(os.getenv("THRESHOLD_ABUSE_CRITICAL", "80"))
    THRESHOLD_ABUSE_SUSPICIOUS = int(os.getenv("THRESHOLD_ABUSE_SUSPICIOUS", "20"))
    THRESHOLD_DOMAIN_NEW_DAYS = int(os.getenv("THRESHOLD_DOMAIN_NEW_DAYS", "30"))
    THRESHOLD_DOMAIN_CRITICAL_DAYS = int(os.getenv("THRESHOLD_DOMAIN_CRITICAL_DAYS", "2"))

    # API Timeouts
    API_TIMEOUT = int(os.getenv("API_TIMEOUT", "10"))
    URL_EXPAND_TIMEOUT = int(os.getenv("URL_EXPAND_TIMEOUT", "5"))

    @classmethod
    def validate(cls):
        """
        Validates that required configuration is present.

        Raises:
            ValueError: If critical config is missing
        """
        errors = []

        if not cls.SLACK_BOT_TOKEN:
            errors.append("SLACK_BOT_TOKEN is required")
        if not cls.SLACK_APP_TOKEN:
            errors.append("SLACK_APP_TOKEN is required")

        if errors:
            raise ValueError(f"Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))

    @classmethod
    def get_summary(cls):
        """
        Returns configuration summary for logging.

        Returns:
            dict: Configuration status
        """
        return {
            "apis": {
                "VirusTotal": bool(cls.VT_API_KEY),
                "AbuseIPDB": bool(cls.ABUSE_IPDB_KEY),
                "Shodan": bool(cls.SHODAN_API_KEY),
                "URLScan": bool(cls.URLSCAN_API_KEY),
            },
            "cache": {
                "enabled": cls.CACHE_ENABLED,
                "ttl": cls.CACHE_TTL,
                "max_size": cls.CACHE_MAX_SIZE,
            },
            "thresholds": {
                "abuse_critical": cls.THRESHOLD_ABUSE_CRITICAL,
                "abuse_suspicious": cls.THRESHOLD_ABUSE_SUSPICIOUS,
                "domain_new_days": cls.THRESHOLD_DOMAIN_NEW_DAYS,
            },
            "files": {
                "ioc_file": cls.IOC_FILE_PATH,
                "log_dir": cls.LOG_DIR,
            }
        }
