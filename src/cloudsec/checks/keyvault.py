from ..models import SecurityFinding


def check_keyvault_soft_delete(
    keyvault_client,
    resource_group_name,
    vault_name
):
    vault = keyvault_client.vaults.get(
        resource_group_name,
        vault_name
    )

    soft_delete_enabled = vault.properties.enable_soft_delete

    if soft_delete_enabled:
        return SecurityFinding(
            rule_id="KEYVAULT-001",
            severity="PASS",
            resource=vault_name,
            title="Soft delete is enabled",
            description=(
                "Deleted Key Vault objects can be recovered "
                "during the retention period."
            ),
            recommendation="No action required."
        )

    return SecurityFinding(
        rule_id="KEYVAULT-001",
        severity="HIGH",
        resource=vault_name,
        title="Soft delete is disabled",
        description=(
            "Deleted Key Vault objects cannot be recovered."
        ),
        recommendation="Enable soft delete."
    )


def check_keyvault_public_network_access(
    keyvault_client,
    resource_group_name,
    vault_name
):
    vault = keyvault_client.vaults.get(
        resource_group_name,
        vault_name
    )

    public_network_access = vault.properties.public_network_access

    if public_network_access == "Disabled":
        return SecurityFinding(
            rule_id="KEYVAULT-002",
            severity="PASS",
            resource=vault_name,
            title="Public network access is disabled",
            description=(
                "The Key Vault cannot be accessed through the "
                "public network."
            ),
            recommendation="No action required."
        )

    if public_network_access == "Enabled":
        return SecurityFinding(
            rule_id="KEYVAULT-002",
            severity="MEDIUM",
            resource=vault_name,
            title="Public network access is enabled",
            description=(
                "The Key Vault accepts connections through the "
                "public network."
            ),
            recommendation=(
                "Disable public network access or restrict access "
                "using appropriate network controls."
            )
        )

    return SecurityFinding(
        rule_id="KEYVAULT-002",
        severity="INFO",
        resource=vault_name,
        title="Public network access configuration is unavailable",
        description=(
            "Azure did not return an explicit public network access "
            "configuration for this Key Vault."
        ),
        recommendation=(
            "Review the Key Vault network configuration and explicitly "
            "configure public network access according to security "
            "requirements."
        )
    )


def check_keyvault_purge_protection(
    keyvault_client,
    resource_group_name,
    vault_name
):
    vault = keyvault_client.vaults.get(
        resource_group_name,
        vault_name
    )

    purge_protection_enabled = vault.properties.enable_purge_protection

    if purge_protection_enabled:
        return SecurityFinding(
            rule_id="KEYVAULT-003",
            severity="PASS",
            resource=vault_name,
            title="Purge protection is enabled",
            description=(
                "Key Vault resources are protected against permanent "
                "deletion during the retention period."
            ),
            recommendation="No action required."
        )

    return SecurityFinding(
        rule_id="KEYVAULT-003",
        severity="HIGH",
        resource=vault_name,
        title="Purge protection is disabled",
        description=(
            "Key Vault resources can potentially be permanently "
            "deleted after soft deletion."
        ),
        recommendation=(
            "Enable purge protection to help prevent permanent "
            "deletion of Key Vault resources."
        )
    )
