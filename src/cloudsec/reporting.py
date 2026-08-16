import json
from datetime import datetime


def save_json_report(
    findings,
    resources_scanned,
    checks_performed,
    passed,
    failed,
    informational
):
    report = {
        "generated_at": datetime.utcnow().isoformat(),

        "summary": {
            "resources_scanned": resources_scanned,
            "checks_performed": checks_performed,
            "passed": passed,
            "failed": failed,
            "informational": informational,
            "status": (
                "SECURE"
                if failed == 0
                else "ATTENTION REQUIRED"
            )
        },

        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    with open(
        "reports/cloudsec-report.json",
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(report, f, indent=4)