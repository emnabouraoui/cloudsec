from dataclasses import dataclass


@dataclass
class SecurityFinding:
    rule_id: str
    severity: str
    resource: str
    title: str
    description: str
    recommendation: str