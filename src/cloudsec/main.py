import json
import shutil
import subprocess

from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient

from .checks.storage import (
    check_storage_public_access,
    check_secure_transfer,
    check_storage_tls_version,
    check_storage_public_network_access,
)

from .checks.keyvault import (
    check_keyvault_soft_delete,

)

from .reporting import save_json_report


def get_subscription_id():
    az_command = shutil.which("az.cmd") or shutil.which("az")

    if not az_command:
        raise RuntimeError(
            "Azure CLI was not found. Make sure Azure CLI is installed "
            "and available in PATH."
        )

    result = subprocess.run(
        [
            az_command,
            "account",
            "show",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    account = json.loads(result.stdout)

    return account["id"]


def print_finding(finding):
    print(f"\n[{finding.severity}] {finding.rule_id}")
    print(f"Resource: {finding.resource}")
    print(f"Title: {finding.title}")
    print(f"Description: {finding.description}")
    print(f"Recommendation: {finding.recommendation}")


def main():
    print("CloudSec")
    print("Cloud Security Posture Management")
    print("-------------------------------")

    credential = AzureCliCredential()
    subscription_id = get_subscription_id()

    resource_client = ResourceManagementClient(
        credential,
        subscription_id,
    )

    storage_client = StorageManagementClient(
        credential,
        subscription_id,
    )

    keyvault_client = KeyVaultManagementClient(
        credential,
        subscription_id,
    )

    # ==========================================================
    # RESOURCE GROUPS
    # ==========================================================

    print("\nAzure Resource Groups:")
    print("-------------------------------")

    resource_groups = list(
        resource_client.resource_groups.list()
    )

    for resource_group in resource_groups:
        print(f"- {resource_group.name}")

    print(
        f"\nTotal resource groups: {len(resource_groups)}"
    )

    all_findings = []
    resources_scanned = 0

    # ==========================================================
    # STORAGE SECURITY SCAN
    # ==========================================================

    print("\nStorage Security Scan")
    print("===============================")

    for resource_group in resource_groups:

        storage_accounts = list(
            storage_client.storage_accounts.list_by_resource_group(
                resource_group.name
            )
        )

        for storage_account in storage_accounts:

            resources_scanned += 1

            finding = check_storage_public_access(
                storage_client,
                resource_group.name,
                storage_account.name,
            )

            all_findings.append(finding)
            print_finding(finding)

            finding = check_secure_transfer(
                storage_client,
                resource_group.name,
                storage_account.name,
            )

            all_findings.append(finding)
            print_finding(finding)

            finding = check_storage_tls_version(
                storage_client,
                resource_group.name,
                storage_account.name,
            )

            all_findings.append(finding)
            print_finding(finding)

            finding = check_storage_public_network_access(
                storage_client,
                resource_group.name,
                storage_account.name,
            )

            all_findings.append(finding)
            print_finding(finding)

    # ==========================================================
    # KEY VAULT SECURITY SCAN
    # ==========================================================

    print("\nKey Vault Security Scan")
    print("===============================")

    for resource_group in resource_groups:

        key_vaults = list(
            keyvault_client.vaults.list_by_resource_group(
                resource_group.name
            )
        )

        for vault in key_vaults:

            resources_scanned += 1

            finding = check_keyvault_soft_delete(
                keyvault_client,
                resource_group.name,
                vault.name,
            )

            all_findings.append(finding)
            print_finding(finding)

    # ==========================================================
    # SUMMARY
    # ==========================================================

    passed = sum(
        1
        for finding in all_findings
        if finding.severity == "PASS"
    )

    informational = sum(
        1
        for finding in all_findings
        if finding.severity == "INFO"
    )

    failed = sum(
        1
        for finding in all_findings
        if finding.severity not in ("PASS", "INFO")
    )

    checks_performed = len(all_findings)

    if failed == 0:
        overall_status = "SECURE"
    else:
        overall_status = "ATTENTION REQUIRED"

    print("\nCloudSec Scan Summary")
    print("===============================")
    print(f"Resources scanned: {resources_scanned}")
    print(f"Checks performed:  {checks_performed}")
    print(f"Passed:            {passed}")
    print(f"Failed:            {failed}")
    print(f"Informational:     {informational}")

    print(f"\nOverall status: {overall_status}")

    # ==========================================================
    # JSON REPORT
    # ==========================================================

    report_path = save_json_report(
    all_findings,
    resources_scanned,
    checks_performed,
    passed,
    failed,
    informational,
    )

    print("\nJSON report generated:")
    print(report_path)

    print("\nCloudSec scan completed.")


if __name__ == "__main__":
    main()