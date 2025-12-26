"""
IntelBot v2.8 - Main Application
ChatOps Threat Intelligence Slack Bot

Modular, production-ready version with:
- Response caching
- Severity scoring
- Search & statistics commands
- Configurable thresholds
- RBAC for IOC deletion (NEW in v2.8)
- API rate limit tracking (NEW in v2.8)
- Multi-format IOC exports (NEW in v2.8)
"""
import os
import re
import logging
from logging.handlers import RotatingFileHandler

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from config import Config
from handlers import (
    handle_intel,
    handle_scan,
    handle_shodan,
    handle_add_ioc,
    handle_remove_ioc,
    handle_list_ioc,
    handle_search_ioc,
    handle_stats,
    handle_api_limits,
    handle_help
)

# --- LOGGING SETUP ---
os.makedirs(Config.LOG_DIR, exist_ok=True)

logger = logging.getLogger("IntelBot")
logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper()))

# Rotating file handler: 10MB max, keep 5 backup files
file_handler = RotatingFileHandler(
    os.path.join(Config.LOG_DIR, "intel_bot.log"),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))
logger.addHandler(file_handler)

# Console handler for real-time monitoring
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
logger.addHandler(console_handler)

# Custom filter to suppress noisy "Unhandled request" warnings
class SlackUnhandledRequestFilter(logging.Filter):
    def filter(self, record):
        # Suppress "Unhandled request" warnings for message events
        if "Unhandled request" in record.getMessage():
            return False
        return True

# Apply filter to Slack loggers
logging.getLogger("slack_bolt").addFilter(SlackUnhandledRequestFilter())
logging.getLogger("slack_sdk").addFilter(SlackUnhandledRequestFilter())

# Validate configuration
try:
    Config.validate()
except ValueError as e:
    logger.critical(str(e))
    exit(1)

# Initialize Slack app
app = App(token=Config.SLACK_BOT_TOKEN)

# --- COMMAND HANDLERS ---

@app.message(re.compile(r"^!intel", re.IGNORECASE))
def intel_command(message, say):
    handle_intel(message, say)


@app.message(re.compile(r"^!scan", re.IGNORECASE))
def scan_command(message, say):
    handle_scan(message, say)


@app.message(re.compile(r"^!shodan", re.IGNORECASE))
def shodan_command(message, say, ack):
    ack()  # Acknowledge immediately to prevent Slack retries
    handle_shodan(message, say)


@app.message(re.compile(r"^!add", re.IGNORECASE))
def add_command(message, say):
    handle_add_ioc(message, say)


@app.message(re.compile(r"^!del|^!remove", re.IGNORECASE))
def remove_command(message, say):
    handle_remove_ioc(message, say, app)  # Pass app instance for RBAC check


@app.message(re.compile(r"^!list", re.IGNORECASE))
def list_command(message, say):
    handle_list_ioc(message, say)


@app.message(re.compile(r"^!search", re.IGNORECASE))
def search_command(message, say):
    handle_search_ioc(message, say)


@app.message(re.compile(r"^!stats", re.IGNORECASE))
def stats_command(message, say):
    handle_stats(message, say)


@app.message(re.compile(r"^!limits", re.IGNORECASE))
def limits_command(message, say):
    handle_api_limits(message, say)


@app.message(re.compile(r"^!help", re.IGNORECASE))
def help_command(message, say):
    handle_help(message, say)


# --- SILENCER (ignore non-command messages) ---
# Note: Removed @app.event("message") handler to prevent duplicate message processing
# The @app.message() regex handlers above already handle all bot commands


# --- MAIN ENTRY POINT ---
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("⚡ IntelBot v2.8 Starting Up...")
    logger.info("=" * 60)

    # Log configuration summary
    config_summary = Config.get_summary()

    logger.info("📡 API Status:")
    for api, enabled in config_summary["apis"].items():
        status = "✅ Enabled" if enabled else "❌ Disabled"
        logger.info(f"  {api}: {status}")

    logger.info(f"\n💾 Cache: {'✅ Enabled' if config_summary['cache']['enabled'] else '❌ Disabled'}")
    if config_summary['cache']['enabled']:
        logger.info(f"  TTL: {config_summary['cache']['ttl']}s")
        logger.info(f"  Max Size: {config_summary['cache']['max_size']} items")

    logger.info(f"\n🎯 Thresholds:")
    logger.info(f"  Abuse Score (Critical): {config_summary['thresholds']['abuse_critical']}%")
    logger.info(f"  Abuse Score (Suspicious): {config_summary['thresholds']['abuse_suspicious']}%")
    logger.info(f"  Domain Age (New): {config_summary['thresholds']['domain_new_days']} days")

    logger.info(f"\n📁 Files:")
    logger.info(f"  IOC File: {config_summary['files']['ioc_file']}")
    logger.info(f"  Log Directory: {config_summary['files']['log_dir']}")

    logger.info("=" * 60)
    logger.info("🚀 Bot is now online and listening for commands!")
    logger.info("=" * 60)

    try:
        SocketModeHandler(app, Config.SLACK_APP_TOKEN).start()
    except KeyboardInterrupt:
        logger.info("Bot shutdown requested by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
