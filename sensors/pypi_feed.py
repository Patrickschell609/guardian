"""
GUARDIAN PyPI Feed Monitor
Monitors PyPI's recent uploads for suspicious ICS/SCADA packages.
Adapted from Lazarus pypi_watcher.py.
"""

import json
import re
import sys
import time
import urllib.request
import urllib.error
import subprocess
import tempfile
import tarfile
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .persistence import scan_package

# Keywords that indicate ICS/SCADA/critical infrastructure packages
ICS_KEYWORDS = [
    "modbus", "s7comm", "s7", "profinet", "profibus", "ethercat",
    "opcua", "opc-ua", "opc_ua", "iec61850", "iec104", "iec-104",
    "iec-61850", "dnp3", "bacnet", "canopen", "canbus", "can-bus",
    "hart", "fieldbus", "zigbee", "zwave", "lorawan",
    "scada", "plc", "hmi", "dcs", "rtu", "ics-", "industrial",
    "siemens", "schneider", "rockwell", "allen-bradley",
    "mitsubishi-plc", "omron-plc", "abb-",
    "power-grid", "smart-grid", "smart-meter", "water-treatment",
    "pipeline", "turbine-control", "hvac-control",
    "mqtt-scada", "coap-industrial", "modbus-tcp", "modbus-rtu",
    "ethernet-ip", "ethernetip",
]


def fetch_pypi_rss() -> list:
    """Fetch PyPI's recent updates RSS feed."""
    url = "https://pypi.org/rss/updates.xml"
    packages = []
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Guardian-Watcher/1.0 (defensive-security-research)"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            tree = ET.parse(resp)
            root = tree.getroot()
            for item in root.findall(".//item"):
                title = item.findtext("title", "")
                link = item.findtext("link", "")
                desc = item.findtext("description", "")
                parts = title.strip().split(" ", 1)
                name = parts[0] if parts else ""
                version = parts[1] if len(parts) > 1 else ""
                packages.append({
                    "name": name.lower(), "version": version,
                    "link": link, "description": desc[:300],
                })
    except Exception as e:
        print(f"  Error fetching RSS: {e}")
    return packages


def fetch_pypi_newest() -> list:
    """Fetch PyPI's newest packages (not just updates)."""
    url = "https://pypi.org/rss/packages.xml"
    packages = []
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Guardian-Watcher/1.0 (defensive-security-research)"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            tree = ET.parse(resp)
            root = tree.getroot()
            for item in root.findall(".//item"):
                title = item.findtext("title", "")
                link = item.findtext("link", "")
                desc = item.findtext("description", "")
                parts = title.strip().split(" ", 1)
                name = parts[0] if parts else ""
                version = parts[1] if len(parts) > 1 else ""
                packages.append({
                    "name": name.lower(), "version": version,
                    "link": link, "description": desc[:300],
                    "is_new": True,
                })
    except Exception as e:
        print(f"  Error fetching newest packages: {e}")
    return packages


def get_package_details(name: str) -> dict:
    """Get full package details from PyPI JSON API."""
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Guardian-Watcher/1.0 (defensive-security-research)"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            info = data.get("info", {})
            releases = data.get("releases", {})

            first_upload = None
            for version, files in releases.items():
                for f in files:
                    ut = f.get("upload_time_iso_8601") or f.get("upload_time")
                    if ut:
                        try:
                            dt = datetime.fromisoformat(ut.replace("Z", "+00:00"))
                            if first_upload is None or dt < first_upload:
                                first_upload = dt
                        except Exception:
                            pass

            return {
                "name": info.get("name", name),
                "version": info.get("version"),
                "summary": (info.get("summary", "") or "")[:300],
                "author": info.get("author", "") or "",
                "author_email": info.get("author_email", "") or "",
                "total_releases": len(releases),
                "first_upload": first_upload.isoformat() if first_upload else None,
                "age_days": (datetime.now(timezone.utc) - first_upload).days if first_upload else None,
            }
    except Exception as e:
        return {"name": name, "error": str(e)[:100]}


def matches_ics_keywords(name: str, description: str = "") -> list:
    """Check if package name or description matches ICS/SCADA keywords."""
    text = f"{name} {description}".lower()
    return [kw for kw in ICS_KEYWORDS if kw in text]


def scan_package_persistence(package_name: str) -> dict:
    """Download and scan a PyPI package for persistence mechanisms."""
    scan_dir = Path(tempfile.mkdtemp(prefix=f"guardian_{package_name}_"))
    try:
        result = subprocess.run(
            ["pip", "download", "--no-deps", "-d", str(scan_dir), package_name],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return {"error": f"Download failed: {result.stderr[:200]}"}

        extract_dir = scan_dir / "extracted"
        extract_dir.mkdir()

        for archive in scan_dir.iterdir():
            if archive.is_dir():
                continue
            if archive.name.endswith((".tar.gz", ".tgz")):
                try:
                    with tarfile.open(archive) as tar:
                        tar.extractall(path=extract_dir, filter="data")
                except Exception:
                    pass
            elif archive.suffix in (".whl", ".zip"):
                try:
                    with zipfile.ZipFile(archive) as zf:
                        zf.extractall(path=extract_dir)
                except Exception:
                    pass

        scan_result = scan_package(str(extract_dir))
        return {
            "scanned": True,
            "total_findings": scan_result.total_findings,
            "findings": [{"file": f.file, "line": f.line, "category": f.category,
                          "severity": f.severity, "context": f.context}
                         for f in scan_result.findings],
            "critical_count": sum(1 for f in scan_result.findings if f.severity == "CRITICAL"),
            "high_count": sum(1 for f in scan_result.findings if f.severity == "HIGH"),
        }
    except Exception as e:
        return {"error": str(e)[:200]}


def run_watcher(scan: bool = True) -> list:
    """Check PyPI recent uploads for ICS/SCADA-related packages."""
    updates = fetch_pypi_rss()
    newest = fetch_pypi_newest()
    all_packages = updates + newest

    # Deduplicate
    unique = {}
    for p in all_packages:
        if p["name"] not in unique:
            unique[p["name"]] = p
    all_packages = list(unique.values())

    # Filter for ICS/SCADA matches
    alerts = []
    for pkg in all_packages:
        kw_matches = matches_ics_keywords(pkg["name"], pkg.get("description", ""))
        if not kw_matches:
            continue

        details = get_package_details(pkg["name"])
        age = details.get("age_days")
        author = details.get("author", "?")

        is_very_new = age is not None and age <= 14
        is_first_release = details.get("total_releases", 0) <= 2

        risk = "LOW"
        if is_very_new and is_first_release:
            risk = "HIGH"
        elif is_very_new:
            risk = "MEDIUM"

        scan_results = {}
        if scan and risk in ("HIGH", "MEDIUM"):
            scan_results = scan_package_persistence(pkg["name"])
            if scan_results.get("critical_count", 0) > 0:
                risk = "CRITICAL"

        alerts.append({
            "package": pkg["name"],
            "version": pkg.get("version", ""),
            "keywords": kw_matches,
            "risk": risk,
            "age_days": age,
            "author": author,
            "description": details.get("summary", ""),
            "is_new": pkg.get("is_new", False),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "scan_results": scan_results,
        })
        time.sleep(0.3)

    return alerts
