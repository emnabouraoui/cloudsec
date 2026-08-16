from ..models import SecurityFinding


def check_storage_public_access(
    storage_client,
    resource_group,
    account_name
):
    account = storage_client.storage_accounts.get_properties(
        resource_group,
        account_name
    )

    public_access = account.allow_blob_public_access

    if public_access:
        return SecurityFinding(
            rule_id="STORAGE-001",
            severity="HIGH",
            resource=account_name,
            title="Public blob access is enabled",
            description="Anonymous public access to blob data is allowed.",
            recommendation=(
                "Disable public blob access unless it is explicitly required."
            )
        )

    return SecurityFinding(
        rule_id="STORAGE-001",
        severity="PASS",
        resource=account_name,
        title="Public blob access is disabled",
        description="Anonymous public access to blob data is not allowed.",
        recommendation="No action required."
    )


def check_secure_transfer(
    storage_client,
    resource_group,
    account_name
):
    account = storage_client.storage_accounts.get_properties(
        resource_group,
        account_name
    )

    secure_transfer = account.enable_https_traffic_only

    if secure_transfer:
        return SecurityFinding(
            rule_id="STORAGE-002",
            severity="PASS",
            resource=account_name,
            title="Secure transfer is required",
            description="The storage account requires HTTPS traffic.",
            recommendation="No action required."
        )

    return SecurityFinding(
        rule_id="STORAGE-002",
        severity="HIGH",
        resource=account_name,
        title="Secure transfer is disabled",
        description="The storage account does not require HTTPS traffic.",
        recommendation="Enable secure transfer for the storage account."
    )