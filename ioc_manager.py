"""
IntelBot IOC Management
Thread-safe IOC file operations with search and statistics
"""
import os
import logging
from filelock import FileLock
from collections import Counter
from datetime import datetime

from config import Config
from utils import get_timestamp, defang
from export_formats import sync_all_formats

logger = logging.getLogger("IntelBot.IOC")

IOC_FILE = Config.IOC_FILE_PATH
IOC_FILE_LOCK = IOC_FILE + ".lock"


def check_internal_list(indicator):
    """
    Checks if the indicator is already in the local IOC file.

    Args:
        indicator: IP, domain, hash, or URL to check

    Returns:
        str: Matching line from IOC file, or None
    """
    if not os.path.exists(IOC_FILE):
        return None

    clean_indicator = indicator.strip()
    try:
        with open(IOC_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                # Check for substring match in the part before the comment #
                if clean_indicator in line.split('#')[0]:
                    return line.strip()
    except Exception as e:
        logger.error(f"Error reading IOC file: {str(e)}")

    return None


def update_ioc_file(action, indicator, user_id="Unknown", reason="No reason provided"):
    """
    Thread-safe IOC file updates with file locking.

    Args:
        action: "add" or "remove"
        indicator: The IOC to add/remove
        user_id: Slack user ID
        reason: Reason for adding the IOC

    Returns:
        str: Status message for Slack
    """
    lock = FileLock(IOC_FILE_LOCK, timeout=10)

    try:
        with lock:
            # Initialize file if it doesn't exist
            if not os.path.exists(IOC_FILE):
                with open(IOC_FILE, 'w', encoding='utf-8') as f:
                    f.write("# IntelBot IOC Blocklist\n")
                    f.write(f"# Created: {get_timestamp()}\n")
                logger.info(f"Created new IOC file: {IOC_FILE}")

            # Read current contents
            with open(IOC_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            clean_indicator = indicator.strip()
            exists = any(clean_indicator in line.split('#')[0] for line in lines)

            if action == "add":
                if exists:
                    logger.warning(f"Attempted to add duplicate IOC: {clean_indicator}")
                    return f"⚠️ `{defang(clean_indicator)}` is already on the list."

                # Append new IOC
                with open(IOC_FILE, 'a', encoding='utf-8') as f:
                    # Format: 1.2.3.4 # Reason | Added: Date by User
                    f.write(f"{clean_indicator} # {reason} | Added: {get_timestamp()} by {user_id}\n")

                logger.info(f"Added IOC: {clean_indicator} | Reason: {reason} | User: {user_id}")

                # Sync all export formats (JSON, STIX)
                logger.info("Syncing export formats...")
                sync_success = sync_all_formats(IOC_FILE)

                if sync_success:
                    logger.info("All IOC formats synchronized")
                    return f"✅ Added `{defang(clean_indicator)}` to IOC list.\n> 📝 *Reason:* {reason}\n> 📤 *Exported to JSON & STIX formats*"
                else:
                    logger.warning("Some export formats failed to sync")
                    return f"✅ Added `{defang(clean_indicator)}` to IOC list.\n> 📝 *Reason:* {reason}\n> ⚠️ *Export sync had errors (check logs)*"

            elif action == "remove":
                if not exists:
                    logger.warning(f"Attempted to remove non-existent IOC: {clean_indicator}")
                    return f"⚠️ `{defang(clean_indicator)}` was not found."

                # Remove matching lines
                new_lines = [line for line in lines if clean_indicator not in line.split('#')[0]]
                with open(IOC_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)

                logger.info(f"Removed IOC: {clean_indicator} | User: {user_id}")

                # Sync all export formats (JSON, STIX)
                logger.info("Syncing export formats after removal...")
                sync_success = sync_all_formats(IOC_FILE)

                if sync_success:
                    logger.info("All IOC formats synchronized after removal")
                    return f"🗑️ Removed `{defang(clean_indicator)}` from the IOC list.\n> 📤 *Export formats updated*"
                else:
                    logger.warning("Some export formats failed to sync after removal")
                    return f"🗑️ Removed `{defang(clean_indicator)}` from the IOC list.\n> ⚠️ *Export sync had errors (check logs)*"

    except Exception as e:
        logger.error(f"IOC file operation failed: {str(e)}")
        return f"❌ File Error: {str(e)}"


def search_ioc_file(query):
    """
    Search IOC file for indicators matching query.

    Args:
        query: Search term (partial match supported)

    Returns:
        list: Matching IOC entries
    """
    if not os.path.exists(IOC_FILE):
        return []

    query = query.strip().lower()
    matches = []

    try:
        with open(IOC_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                # Skip comment lines
                if line.startswith('#'):
                    continue

                # Check if query is in the line (case-insensitive)
                if query in line.lower():
                    matches.append(line.strip())

        logger.info(f"IOC search for '{query}': {len(matches)} results")
        return matches

    except Exception as e:
        logger.error(f"IOC search failed: {str(e)}")
        return []


def get_ioc_stats():
    """
    Calculate statistics about the IOC file.

    Returns:
        dict: Statistics including total count, recent additions, top contributors
    """
    if not os.path.exists(IOC_FILE):
        return {
            "total": 0,
            "today": 0,
            "this_week": 0,
            "top_contributors": [],
            "recent_additions": []
        }

    try:
        with open(IOC_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Parse IOC entries
        iocs = []
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            iocs.append(line.strip())

        # Count contributors
        contributors = []
        for line in iocs:
            if ' by ' in line:
                user = line.split(' by ')[-1].strip()
                contributors.append(user)

        # Count recent additions
        today_count = 0
        week_count = 0
        recent_additions = []

        now = datetime.now()
        for line in iocs:
            # Try to extract date from "Added: YYYY-MM-DD HH:MM:SS"
            if 'Added:' in line:
                try:
                    date_str = line.split('Added:')[1].split('by')[0].strip()
                    # Parse just the date part (YYYY-MM-DD)
                    date_only = date_str.split()[0]
                    ioc_date = datetime.strptime(date_only, "%Y-%m-%d")

                    days_ago = (now - ioc_date).days
                    if days_ago == 0:
                        today_count += 1
                    if days_ago < 7:
                        week_count += 1

                    # Store recent additions (last 5)
                    if days_ago < 7:
                        indicator = line.split('#')[0].strip()
                        recent_additions.append({
                            "indicator": indicator,
                            "days_ago": days_ago,
                            "date": date_only
                        })
                except Exception:
                    pass

        # Get top contributors
        contributor_counts = Counter(contributors)
        top_contributors = contributor_counts.most_common(5)

        # Sort recent additions by date (newest first)
        recent_additions.sort(key=lambda x: x['days_ago'])
        recent_additions = recent_additions[:5]

        return {
            "total": len(iocs),
            "today": today_count,
            "this_week": week_count,
            "top_contributors": top_contributors,
            "recent_additions": recent_additions
        }

    except Exception as e:
        logger.error(f"Failed to calculate IOC stats: {str(e)}")
        return {
            "total": 0,
            "today": 0,
            "this_week": 0,
            "top_contributors": [],
            "recent_additions": []
        }
