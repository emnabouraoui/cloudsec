import json
from datetime import datetime, timezone
from pathlib import Path


def save_json_report(
    findings,
    resources_scanned,
    checks_performed,
    passed,
    failed,
    informational,
    subscription_id=None,
    risk_score=0,
    risk_level="SECURE",
    risk_high=0,
    risk_medium=0,
    risk_low=0
):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / "cloudsec-report.json"

    if failed > 0:
        status = "ATTENTION REQUIRED"
    else:
        status = "SECURE"

    report = {
        "tool": {
            "name": "CloudSec",
            "description": "Cloud Security Posture Management"
        },
        "scan": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "subscription_id": subscription_id
        },
        "summary": {
            "resources_scanned": resources_scanned,
            "checks_performed": checks_performed,
            "passed": passed,
            "failed": failed,
            "informational": informational,
            "status": status
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "high": risk_high,
            "medium": risk_medium,
            "low": risk_low,
            "informational": informational,
            "passed": passed
        },
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "resource": finding.resource,
                "title": finding.title,
                "description": finding.description,
                "recommendation": finding.recommendation
            }
            for finding in findings
        ]
    }

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4
        )

    return str(report_path)