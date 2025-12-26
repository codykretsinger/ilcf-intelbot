"""
IOC Export Formats
Generates JSON and STIX formats from TXT IOC file
"""
import json
import logging
import re
from datetime import datetime
import uuid

logger = logging.getLogger("IntelBot.Export")


def parse_ioc_file(file_path):
    """
    Parse IOC file into structured data.

    Returns:
        list: IOC entries with metadata
    """
    iocs = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue

                # Parse: "1.2.3.4 # Reason | Added: 2025-12-26 12:00:00 by U123"
                parts = line.split('#')
                indicator = parts[0].strip()

                metadata = {}
                if len(parts) > 1:
                    comment = parts[1].strip()

                    # Extract reason (before |)
                    if '|' in comment:
                        metadata['reason'] = comment.split('|')[0].strip()

                        # Extract timestamp and user
                        info_part = comment.split('|')[1].strip()
                        if 'Added:' in info_part:
                            date_part = info_part.split('Added:')[1].strip()
                            if ' by ' in date_part:
                                metadata['added_date'] = date_part.split(' by ')[0].strip()
                                metadata['added_by'] = date_part.split(' by ')[1].strip()
                    else:
                        metadata['reason'] = comment

                iocs.append({
                    "indicator": indicator,
                    "type": detect_ioc_type(indicator),
                    **metadata
                })

    except Exception as e:
        logger.error(f"Failed to parse IOC file: {e}")

    return iocs


def detect_ioc_type(indicator):
    """Detect IOC type (ipv4, domain, hash, url)."""

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
        return "ipv4-addr"
    elif re.match(r'^[a-fA-F0-9]{32}$', indicator):
        return "file-md5"
    elif re.match(r'^[a-fA-F0-9]{40}$', indicator):
        return "file-sha1"
    elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
        return "file-sha256"
    elif re.match(r'^https?://', indicator):
        return "url"
    else:
        return "domain-name"


def export_to_json(iocs, output_path):
    """Export IOCs to JSON format."""
    try:
        data = {
            "metadata": {
                "version": "2.8",
                "generated": datetime.now().isoformat(),
                "source": "IntelBot - Community Threat Intelligence",
                "total_indicators": len(iocs)
            },
            "indicators": iocs
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported {len(iocs)} IOCs to JSON: {output_path}")
        return True
    except Exception as e:
        logger.error(f"JSON export failed: {e}")
        return False


def export_to_stix(iocs, output_path):
    """
    Export IOCs to STIX 2.1 format.

    STIX format example:
    {
      "type": "bundle",
      "id": "bundle--...",
      "objects": [
        {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--...",
          "created": "2025-12-26T12:00:00.000Z",
          "modified": "2025-12-26T12:00:00.000Z",
          "pattern": "[ipv4-addr:value = '1.2.3.4']",
          "pattern_type": "stix",
          "valid_from": "2025-12-26T12:00:00.000Z",
          "labels": ["malicious-activity"]
        }
      ]
    }
    """
    try:
        objects = []

        for ioc in iocs:
            # Generate STIX pattern based on type
            indicator_type = ioc['type']
            value = ioc['indicator']

            if indicator_type == "ipv4-addr":
                pattern = f"[ipv4-addr:value = '{value}']"
            elif indicator_type.startswith("file-"):
                hash_type = indicator_type.split('-')[1]  # md5, sha1, sha256
                pattern = f"[file:hashes.{hash_type.upper()} = '{value}']"
            elif indicator_type == "domain-name":
                pattern = f"[domain-name:value = '{value}']"
            elif indicator_type == "url":
                pattern = f"[url:value = '{value}']"
            else:
                pattern = f"[{indicator_type}:value = '{value}']"

            # Parse date or use current
            created_date = ioc.get('added_date', datetime.now().isoformat())
            try:
                created_dt = datetime.strptime(created_date.split()[0], "%Y-%m-%d")
            except:
                created_dt = datetime.now()

            # Format as ISO 8601 with Z suffix
            created_iso = created_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            stix_indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": created_iso,
                "modified": created_iso,
                "name": f"IntelBot IOC: {value}",
                "description": ioc.get('reason', 'Malicious indicator'),
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": created_iso,
                "labels": ["malicious-activity"]
            }

            objects.append(stix_indicator)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"Exported {len(iocs)} IOCs to STIX: {output_path}")
        return True
    except Exception as e:
        logger.error(f"STIX export failed: {e}")
        return False


def sync_all_formats(txt_file_path):
    """
    Read TXT file and generate JSON and STIX versions.

    Args:
        txt_file_path: Path to iocs.txt
    """
    # Determine output paths
    base_path = txt_file_path.rsplit('.', 1)[0]
    json_path = base_path + '.json'
    stix_path = base_path + '.stix'

    # Parse TXT file
    iocs = parse_ioc_file(txt_file_path)

    if not iocs:
        logger.warning("No IOCs found to export")
        return True  # Not an error, just empty

    # Generate exports
    json_success = export_to_json(iocs, json_path)
    stix_success = export_to_stix(iocs, stix_path)

    return json_success and stix_success
