from dataclasses import dataclass


@dataclass
class SecurityFinding:
    rule_id: str
    severity: str
    resource: str
    title: str
    description: str
    recommendation: str

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource": self.resource,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation
        }