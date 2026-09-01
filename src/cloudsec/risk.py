
SEVERITY_SCORES = {
    "PASS": 0,
    "INFO": 0,
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 10,
}


def calculate_finding_risk(finding):
    """
    Calculate the risk score for a single security finding.

    PASS and INFO findings have no security risk score.
    LOW, MEDIUM and HIGH findings receive increasing scores.
    """

    return SEVERITY_SCORES.get(finding.severity.upper(), 0)


def calculate_total_risk(findings):
    """
    Calculate the total risk score for all security findings.
    """

    return sum(
        calculate_finding_risk(finding)
        for finding in findings
    )


def calculate_risk_level(total_score):
    """
    Convert the total risk score into an overall risk level.
    """

    if total_score == 0:
        return "SECURE"

    if total_score <= 10:
        return "LOW"

    if total_score <= 25:
        return "MEDIUM"

    return "HIGH"


def prioritize_findings(findings):
    """
    Return security findings ordered by risk priority.

    PASS and INFO findings are excluded because they do not
    represent actionable security risks.
    """

    actionable_findings = [
        finding
        for finding in findings
        if finding.severity.upper() not in ("PASS", "INFO")
    ]

    return sorted(
        actionable_findings,
        key=calculate_finding_risk,
        reverse=True
    )
