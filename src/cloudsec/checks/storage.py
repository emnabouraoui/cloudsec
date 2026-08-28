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


def check_storage_tls_version(
    storage_client,
    resource_group,
    account_name
):
    account = storage_client.storage_accounts.get_properties(
        resource_group,
        account_name
    )

    tls_version = account.minimum_tls_version

    if tls_version in ["TLS1_2", "TLS1_3"]:
        return SecurityFinding(
            rule_id="STORAGE-003",
            severity="PASS",
            resource=account_name,
            title="Minimum TLS version is secure",
            description=(
                f"The storage account requires {tls_version} "
                "or a newer TLS version."
            ),
            recommendation="No action required."
        )

    return SecurityFinding(
        rule_id="STORAGE-003",
        severity="HIGH",
        resource=account_name,
        title="Minimum TLS version is too low",
        description=(
            f"The storage account uses {tls_version}, "
            "which is below the recommended TLS 1.2."
        ),
        recommendation="Set the minimum TLS version to TLS 1.2."
    )


def check_storage_public_network_access(
    storage_client,
    resource_group,
    account_name
):
    account = storage_client.storage_accounts.get_properties(
        resource_group,
        account_name
    )

    public_network_access = account.public_network_access

    if public_network_access is None:
        return SecurityFinding(
            rule_id="STORAGE-004",
            severity="INFO",
            resource=account_name,
            title="Public network access configuration is unavailable",
            description=(
                "Azure did not return a public network access "
                "configuration for this storage account."
            ),
            recommendation=(
                "Review the storage account network configuration "
                "and explicitly configure public network access."
            )
        )

    public_network_access = str(public_network_access).lower()

    if "disabled" in public_network_access:
        return SecurityFinding(
            rule_id="STORAGE-004",
            severity="PASS",
            resource=account_name,
            title="Public network access is disabled",
            description=(
                "The storage account is not accessible through "
                "the public network."
            ),
            recommendation="No action required."
        )

    if "enabled" in public_network_access:
        return SecurityFinding(
            rule_id="STORAGE-004",
            severity="MEDIUM",
            resource=account_name,
            title="Public network access is enabled",
            description=(
                "The storage account accepts connections through "
                "the public network."
            ),
            recommendation=(
                "Disable public network access or restrict access "
                "using appropriate network controls."
            )
        )

    return SecurityFinding(
        rule_id="STORAGE-004",
        severity="INFO",
        resource=account_name,
        title="Unknown public network access configuration",
        description=(
            f"Azure returned an unrecognized public network access "
            f"value: {public_network_access}"
        ),
        recommendation=(
            "Review the storage account network configuration "
            "and verify that public network access is explicitly "
            "configured."
        )
    )
