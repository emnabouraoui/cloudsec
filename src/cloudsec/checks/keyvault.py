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