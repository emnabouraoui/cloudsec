from ..models import SecurityFinding


PRIVILEGED_ROLES = {
    "Owner": {
        "rule_id": "IAM-001",
        "severity": "HIGH",
        "description": (
            "Owner provides full management access to Azure resources "
            "and can assign Azure RBAC roles."
        ),
        "recommendation": (
            "Review whether Owner access is required. Apply least "
            "privilege and use a more specific role whenever possible."
        ),
    },
    "Contributor": {
        "rule_id": "IAM-002",
        "severity": "MEDIUM",
        "description": (
            "Contributor provides broad management access to Azure "
            "resources but does not allow assigning Azure RBAC roles."
        ),
        "recommendation": (
            "Review whether subscription-level Contributor access is "
            "required. Prefer resource-group or resource-level access "
            "whenever possible."
        ),
    },
    "User Access Administrator": {
        "rule_id": "IAM-003",
        "severity": "HIGH",
        "description": (
            "User Access Administrator can manage access to Azure "
            "resources by assigning and removing Azure RBAC roles."
        ),
        "recommendation": (
            "Review whether this level of access is required. Restrict "
            "User Access Administrator assignments to trusted "
            "administrators and apply least privilege."
        ),
    },
    "Role Based Access Control Administrator": {
        "rule_id": "IAM-004",
        "severity": "HIGH",
        "description": (
            "Role Based Access Control Administrator can manage Azure "
            "resource access by assigning Azure RBAC roles."
        ),
        "recommendation": (
            "Review whether this role is required. Restrict RBAC "
            "administration to trusted administrators and use the "
            "least privileged role possible."
        ),
    },
}


def check_subscription_privileged_assignments(
    authorization_client,
    subscription_id,
):
    findings = []

    scope = f"/subscriptions/{subscription_id}"

    role_definitions = list(
        authorization_client.role_definitions.list(
            scope=scope
        )
    )

    role_map = {}

    for role in role_definitions:
        if role.role_name in PRIVILEGED_ROLES:
            role_map[role.role_name] = role.id

    assignments = authorization_client.role_assignments.list_for_scope(
        scope
    )

    detected_roles = set()

    for assignment in assignments:
        assignment_role_id = assignment.role_definition_id

        if not assignment_role_id:
            continue

        assignment_role_id = assignment_role_id.lower()

        matched_role = None

        for role_name, role_id in role_map.items():
            if assignment_role_id == role_id.lower():
                matched_role = role_name
                break

        if not matched_role:
            continue

        detected_roles.add(matched_role)

        rule = PRIVILEGED_ROLES[matched_role]
        principal_id = assignment.principal_id

        findings.append(
            SecurityFinding(
                rule_id=rule["rule_id"],
                severity=rule["severity"],
                resource=principal_id,
                title=f"Subscription {matched_role} role detected",
                description=(
                    f"Principal {principal_id} has the "
                    f"{matched_role} role at subscription scope. "
                    f"{rule['description']}"
                ),
                recommendation=rule["recommendation"],
            )
        )

    for role_name, rule in PRIVILEGED_ROLES.items():
        if role_name in detected_roles:
            continue

        findings.append(
            SecurityFinding(
                rule_id=rule["rule_id"],
                severity="PASS",
                resource=subscription_id,
                title=(
                    f"No subscription {role_name} assignments detected"
                ),
                description=(
                    f"No {role_name} role assignment was detected "
                    "at subscription scope."
                ),
                recommendation="No action required.",
            )
        )

    return findings

def check_subscription_privileged_service_principals(
    authorization_client,
    subscription_id,
):
    findings = []

    scope = f"/subscriptions/{subscription_id}"

    privileged_role_names = set(PRIVILEGED_ROLES.keys())

    role_definitions = list(
        authorization_client.role_definitions.list(
            scope=scope
        )
    )

    role_map = {}

    for role in role_definitions:
        if role.role_name in privileged_role_names:
            role_map[role.id.lower()] = role.role_name

    assignments = authorization_client.role_assignments.list_for_scope(
        scope
    )

    privileged_service_principals = []

    for assignment in assignments:
        if not assignment.role_definition_id:
            continue

        role_name = role_map.get(
            assignment.role_definition_id.lower()
        )

        if not role_name:
            continue

        principal_type = getattr(
            assignment,
            "principal_type",
            None
        )

        if principal_type in [
            "ServicePrincipal",
            "ManagedIdentity",
        ]:
            privileged_service_principals.append(
                (assignment, role_name, principal_type)
            )

    if not privileged_service_principals:
        findings.append(
            SecurityFinding(
                rule_id="IAM-005",
                severity="PASS",
                resource=subscription_id,
                title=(
                    "No privileged service principal or "
                    "managed identity assignments detected"
                ),
                description=(
                    "No subscription-level privileged role assignment "
                    "was detected for a service principal or managed identity."
                ),
                recommendation="No action required.",
            )
        )
        

        return findings
    

    for assignment, role_name, principal_type in (
        privileged_service_principals
    ):
        findings.append(
            SecurityFinding(
                rule_id="IAM-005",
                severity="HIGH",
                resource=assignment.principal_id,
                title=(
                    "Privileged role assigned to "
                    f"{principal_type}"
                ),
                description=(
                    f"Principal {assignment.principal_id} is a "
                    f"{principal_type} with the {role_name} role "
                    "at subscription scope. Privileged non-human "
                    "identities can create significant security risk "
                    "if their credentials or tokens are compromised."
                ),
                recommendation=(
                    "Review whether this privileged assignment is "
                    "required. Restrict privileged permissions, use "
                    "least privilege, and avoid unnecessary "
                    "subscription-level access for workloads."
                ),
            )
        )

    return findings
def check_direct_subscription_privileged_users(
    authorization_client,
    subscription_id,
):
    findings = []

    scope = f"/subscriptions/{subscription_id}"

    privileged_role_names = set(PRIVILEGED_ROLES.keys())

    role_definitions = list(
        authorization_client.role_definitions.list(
            scope=scope
        )
    )

    role_map = {}

    for role in role_definitions:
        if role.role_name in privileged_role_names:
            role_map[role.id.lower()] = role.role_name

    assignments = authorization_client.role_assignments.list_for_scope(
        scope
    )

    detected_users = []

    for assignment in assignments:
        if not assignment.role_definition_id:
            continue

        role_name = role_map.get(
            assignment.role_definition_id.lower()
        )

        if not role_name:
            continue

        principal_type = getattr(
            assignment,
            "principal_type",
            None
        )

        if principal_type == "User":
            detected_users.append(
                (assignment, role_name)
            )

    if not detected_users:
        findings.append(
            SecurityFinding(
                rule_id="IAM-006",
                severity="PASS",
                resource=subscription_id,
                title="No direct privileged user assignments detected",
                description=(
                    "No direct subscription-level privileged role "
                    "assignment was detected for an individual user."
                ),
                recommendation="No action required.",
            )
        )

        return findings

    for assignment, role_name in detected_users:
        findings.append(
            SecurityFinding(
                rule_id="IAM-006",
                severity="HIGH",
                resource=assignment.principal_id,
                title="Direct privileged user assignment detected",
                description=(
                    f"User {assignment.principal_id} has the "
                    f"{role_name} role directly assigned at "
                    "subscription scope. Direct privileged access "
                    "increases the risk of excessive permissions "
                    "and makes access governance more difficult."
                ),
                recommendation=(
                    "Review whether direct subscription-level access "
                    "is required. Prefer group-based access, "
                    "least-privilege roles, and narrower scopes "
                    "whenever possible."
                ),
            )
        )

    return findings
 