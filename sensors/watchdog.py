"""
GUARDIAN Watchdog
Monitors claimable ICS/SCADA package names for new registrations.
Adapted from Lazarus watchdog.py.
"""

import json
import time
import sys
import urllib.request
import urllib.error
import subprocess
import tarfile
import zipfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict

from .persistence import scan_package

# ICS protocols that are highest-value targets
ICS_TAGS = {
    "modbus", "s7comm", "plc", "scada", "iec104", "iec61850",
    "ethercat", "opcua", "profibus", "canbus", "canopen",
    "dnp3", "bacnet", "mqtt",
}

# High-value package names
PRIORITY_WATCH = [
    "s7comm", "modbus-arduino", "modbus_arduino", "freemodbus",
    "scadapass", "qsimplescada", "libnodave", "nodave",
    "pymodbus-serial", "modbus4android", "ethercat-master",
    "iec61850", "iec104", "opcua-server", "plc-controller",
    "canopen-master", "profibus", "bacnet-stack",
]


@dataclass
class WatchAlert:
    package_name: str
    registry: str
    protocol_tag: str
    status: str
    detected_at: str
    package_age_days: int
    persistence_findings: int
    critical_findings: int
    scan_details: dict


def check_pypi(package: str) -> dict:
    """Check if a package exists on PyPI now."""
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Watchdog/1.0 (defensive-security-research)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            info = data.get("info", {})
            releases = data.get("releases", {})

            first_upload = None
            for version, files in releases.items():
                for f in files:
                    upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                    if upload_time:
                        try:
                            dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                            if first_upload is None or dt < first_upload:
                                first_upload = dt
                        except Exception:
                            pass

            age_days = None
            if first_upload:
                age_days = (datetime.now(timezone.utc) - first_upload).days

            return {
                "exists": True,
                "name": info.get("name", package),
                "version": info.get("version"),
                "author": info.get("author", "") or "",
                "summary": (info.get("summary", "") or "")[:300],
                "age_days": age_days,
                "total_releases": len(releases),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "name": package}
        return {"exists": None, "name": package, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"exists": None, "name": package, "error": str(e)[:100]}


def check_npm(package: str) -> dict:
    """Check if a package exists on npm now."""
    url = f"https://registry.npmjs.org/{package}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Watchdog/1.0 (defensive-security-research)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            time_info = data.get("time", {})
            created = time_info.get("created")

            age_days = None
            if created:
                try:
                    dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - dt).days
                except Exception:
                    pass

            return {
                "exists": True,
                "name": data.get("name", package),
                "version": data.get("dist-tags", {}).get("latest", ""),
                "age_days": age_days,
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "name": package}
        return {"exists": None, "name": package, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"exists": None, "name": package, "error": str(e)[:100]}


def scan_pypi_package(package_name: str) -> dict:
    """Download a PyPI package (NO install) and run persistence detector."""
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
                          "severity": f.severity} for f in scan_result.findings],
            "critical_count": sum(1 for f in scan_result.findings if f.severity == "CRITICAL"),
            "high_count": sum(1 for f in scan_result.findings if f.severity == "HIGH"),
        }
    except Exception as e:
        return {"error": str(e)[:200]}


def run_watchdog(watch_names: list = None, quick: bool = False, scan_new: bool = True) -> list:
    """
    Check package names for new registrations.

    Args:
        watch_names: List of dicts with 'package', 'registry', 'tag' keys.
                     If None, uses PRIORITY_WATCH on PyPI.
        quick: Only check ICS-critical names.
        scan_new: Auto-scan newly registered packages.
    """
    if watch_names is None:
        watch_names = [{"package": p, "registry": "pypi", "tag": "ics"} for p in PRIORITY_WATCH]

    alerts = []
    now = datetime.now(timezone.utc).isoformat()

    for item in watch_names:
        pkg = item["package"]
        reg = item.get("registry", "pypi")
        tag = item.get("tag", "unknown")

        if reg == "pypi":
            result = check_pypi(pkg)
        elif reg == "npm":
            result = check_npm(pkg)
        else:
            continue

        if result.get("exists") is None or not result["exists"]:
            time.sleep(0.15)
            continue

        age_days = result.get("age_days")
        is_very_new = age_days is not None and age_days <= 14

        if is_very_new:
            scan_details = {}
            persistence_findings = 0
            critical_findings = 0

            if scan_new and reg == "pypi":
                scan_details = scan_pypi_package(pkg)
                persistence_findings = scan_details.get("total_findings", 0)
                critical_findings = scan_details.get("critical_count", 0)

            alert = WatchAlert(
                package_name=pkg, registry=reg, protocol_tag=tag,
                status="NEWLY_REGISTERED", detected_at=now,
                package_age_days=age_days or -1,
                persistence_findings=persistence_findings,
                critical_findings=critical_findings,
                scan_details=scan_details,
            )
            alerts.append(asdict(alert))

        time.sleep(0.15)

    return alerts
