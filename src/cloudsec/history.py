import json
from datetime import datetime, timezone
from pathlib import Path


HISTORY_DIR = Path("reports/history")


def save_scan(report):
    """
    Save a completed CloudSec scan as an immutable historical snapshot.
    """

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    filename = f"scan-{timestamp.strftime('%Y%m%d-%H%M%S-%f')}.json"

    scan_path = HISTORY_DIR / filename

    with open(scan_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return str(scan_path)


def load_previous_scan():
    """
    Load the most recent historical scan.

    Returns None if no previous scan exists.
    """

    if not HISTORY_DIR.exists():
        return None

    scan_files = sorted(
        HISTORY_DIR.glob("scan-*.json"),
        reverse=True
    )

    if not scan_files:
        return None

    with open(scan_files[0], "r", encoding="utf-8") as file:
        return json.load(file)


def get_finding_key(finding):
    """
    Generate a stable identity for a security finding.

    A finding is uniquely identified by its rule and resource.
    """

    return (
        finding["rule_id"],
        finding["resource"],
    )


def compare_scans(previous_scan, current_scan):
    """
    Compare two CloudSec scans.

    Only actionable findings are compared.
    PASS and INFO results are excluded.

    Returns:
        new findings
        resolved findings
        persistent findings
    """

    if previous_scan is None:
        return {
            "new": current_scan.get("findings", []),
            "resolved": [],
            "persistent": [],
        }

    previous_findings = [
        finding
        for finding in previous_scan.get("findings", [])
        if finding.get("severity", "").upper() not in ("PASS", "INFO")
    ]

    current_findings = [
        finding
        for finding in current_scan.get("findings", [])
        if finding.get("severity", "").upper() not in ("PASS", "INFO")
    ]

    previous_map = {
        get_finding_key(finding): finding
        for finding in previous_findings
    }

    current_map = {
        get_finding_key(finding): finding
        for finding in current_findings
    }

    new_findings = [
        finding
        for key, finding in current_map.items()
        if key not in previous_map
    ]

    resolved_findings = [
        finding
        for key, finding in previous_map.items()
        if key not in current_map
    ]

    persistent_findings = [
        finding
        for key, finding in current_map.items()
        if key in previous_map
    ]

    return {
        "new": new_findings,
        "resolved": resolved_findings,
        "persistent": persistent_findings,
    }


def calculate_risk_change(previous_scan, current_scan):
    """
    Calculate the change in risk score between scans.
    """

    current_score = current_scan.get(
        "risk", {}
    ).get(
        "score", 0
    )

    if previous_scan is None:
        current_findings = [
            finding
            for finding in current_scan.get("findings", [])
            if finding.get("severity", "").upper() not in ("PASS", "INFO")
        ]

        return {
            "new": current_findings,
            "resolved": [],
            "persistent": [],
        }

    previous_score = previous_scan.get(
        "risk", {}
    ).get(
        "score", 0
    )

    return current_score - previous_score
