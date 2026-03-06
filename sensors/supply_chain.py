"""
GUARDIAN Supply Chain Scanner
Cross-references repo names against PyPI/npm for claimable package names.
Adapted from Lazarus crossref_scanner.py.
"""

import json
import time
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


def normalize_package_name(repo_name: str) -> list:
    """Generate likely PyPI/npm package names from a repo name."""
    names = set()
    name = repo_name.strip()
    names.add(name.lower())
    names.add(name.lower().replace("_", "-"))
    names.add(name.lower().replace("-", "_"))

    for suffix in ["-python", "-py", ".py", "-js", "-node", "-lib", "-library",
                   "-master", "-demo", "-example", "-rtt-stm32", "-client", "-server"]:
        if name.lower().endswith(suffix):
            base = name[:len(name)-len(suffix)].lower()
            if len(base) > 1:
                names.add(base)
                names.add(base.replace("_", "-"))
                names.add(base.replace("-", "_"))

    for prefix in ["py-", "python-", "node-", "lib", "go-"]:
        if name.lower().startswith(prefix):
            base = name[len(prefix):].lower()
            if len(base) > 1:
                names.add(base)

    names = {n for n in names if len(n) > 1 and re.match(r'^[a-z0-9][a-z0-9._-]*$', n)}
    return sorted(names)


def check_pypi(package: str) -> dict:
    """Check PyPI for a package. Returns status info."""
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            info = data.get("info", {})
            releases = data.get("releases", {})

            latest_date = None
            total_files = 0
            for version, files in releases.items():
                total_files += len(files)
                for f in files:
                    upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                    if upload_time:
                        try:
                            dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                            if latest_date is None or dt > latest_date:
                                latest_date = dt
                        except Exception:
                            pass

            days_since = None
            if latest_date:
                days_since = (datetime.now(timezone.utc) - latest_date).days

            return {
                "status": "EXISTS",
                "name": info.get("name", package),
                "version": info.get("version"),
                "summary": (info.get("summary", "") or "")[:200],
                "author": info.get("author", "") or "",
                "last_updated": latest_date.isoformat() if latest_date else None,
                "days_since_update": days_since,
                "total_releases": len(releases),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "NOT_FOUND", "name": package}
        return {"status": f"HTTP_{e.code}", "name": package}
    except Exception as e:
        return {"status": "ERROR", "name": package, "error": str(e)[:100]}


def check_npm(package: str) -> dict:
    """Check npm for a package."""
    url = f"https://registry.npmjs.org/{package}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            time_info = data.get("time", {})
            modified = time_info.get("modified")

            days_since = None
            if modified:
                try:
                    dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                    days_since = (datetime.now(timezone.utc) - dt).days
                except Exception:
                    pass

            return {
                "status": "EXISTS",
                "name": data.get("name", package),
                "version": data.get("dist-tags", {}).get("latest", ""),
                "days_since_update": days_since,
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "NOT_FOUND", "name": package}
        return {"status": f"HTTP_{e.code}", "name": package}
    except Exception as e:
        return {"status": "ERROR", "name": package, "error": str(e)[:100]}


def classify_finding(pypi_results: list, npm_results: list) -> dict:
    """Classify the overall risk for package names."""
    findings = []
    worst_risk = "LOW"
    risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    for result in pypi_results:
        risk = "LOW"
        reason = ""

        if result["status"] == "NOT_FOUND":
            risk = "CRITICAL"
            reason = f"PyPI name '{result['name']}' is AVAILABLE. Anyone can register it."
        elif result["status"] == "EXISTS":
            days = result.get("days_since_update")
            if days and days > 1825:
                risk = "HIGH"
                reason = f"PyPI '{result['name']}' exists but last updated {days//365}y ago."
            elif days and days > 730:
                risk = "MEDIUM"
                reason = f"PyPI '{result['name']}' last updated {days//365}y ago."
            else:
                reason = f"PyPI '{result['name']}' v{result.get('version','')} appears maintained."

        findings.append({"registry": "pypi", "package": result["name"], "risk": risk, "reason": reason})
        if risk_order.get(risk, 0) > risk_order.get(worst_risk, 0):
            worst_risk = risk

    for result in npm_results:
        risk = "LOW"
        reason = ""
        if result["status"] == "NOT_FOUND":
            risk = "CRITICAL"
            reason = f"npm name '{result['name']}' is AVAILABLE."
        elif result["status"] == "EXISTS":
            days = result.get("days_since_update")
            if days and days > 1825:
                risk = "HIGH"
                reason = f"npm '{result['name']}' last updated {days//365}y ago."
            else:
                reason = f"npm '{result['name']}' appears maintained."

        findings.append({"registry": "npm", "package": result["name"], "risk": risk, "reason": reason})
        if risk_order.get(risk, 0) > risk_order.get(worst_risk, 0):
            worst_risk = risk

    return {"worst_risk": worst_risk, "findings": findings}


def scan_repo_names(repo_names: list) -> list:
    """Scan a list of repo names for claimable package names."""
    results = []
    for repo_name in repo_names:
        pkg_names = normalize_package_name(repo_name)
        pypi_results = []
        npm_results = []

        for pkg in pkg_names:
            pypi_results.append(check_pypi(pkg))
            time.sleep(0.15)
            npm_results.append(check_npm(pkg))
            time.sleep(0.1)

        classification = classify_finding(pypi_results, npm_results)
        results.append({
            "repo_name": repo_name,
            "checked_names": pkg_names,
            "classification": classification,
        })
    return results
