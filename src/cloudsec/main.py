from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from .checks.iam import (
    check_subscription_privileged_assignments,
    check_subscription_privileged_service_principals,
    check_direct_subscription_privileged_users,
)

from .checks.compute import check_vm_public_ip
from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from .checks.network import (
    check_nsg_remote_access,
    check_nsg_dangerous_rules,
)

from .checks.storage import (
    check_storage_public_access,
    check_secure_transfer,
    check_storage_tls_version,
    check_storage_public_network_access,
)
from .checks.storage import (
    check_storage_public_access,
    check_secure_transfer,
    check_storage_tls_version,
    check_storage_public_network_access,
)

from .checks.keyvault import (
    check_keyvault_soft_delete,
    check_keyvault_public_network_access,
    check_keyvault_purge_protection,
)
from .checks.compute import check_vm_public_ip

from .reporting import save_json_report

import subprocess
import json


def print_finding(finding):
    """Print a security finding."""

    print(f"\n[{finding.severity}] {finding.rule_id}")
    print(f"Resource: {finding.resource}")
    print(f"Title: {finding.title}")
    print(f"Description: {finding.description}")
    print(f"Recommendation: {finding.recommendation}")


def main():

    # ==========================================================
    # CLOUDSEC HEADER
    # ==========================================================

    print("CloudSec")
    print("Cloud Security Posture Management")
    print("-------------------------------")

    # ==========================================================
    # AZURE AUTHENTICATION
    # ==========================================================

    credential = AzureCliCredential(process_timeout=60)

    account_result = subprocess.run(
        [
            "az.cmd",
            "account",
            "show",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    account = json.loads(account_result.stdout)
    subscription_id = account["id"]

    # ==========================================================
    # AZURE CLIENTS
    # ==========================================================

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

    compute_client = ComputeManagementClient(
        credential,
        subscription_id,
    )

    network_client = NetworkManagementClient(
        credential,
        subscription_id,
    )
    authorization_client = AuthorizationManagementClient(
    credential,
    subscription_id
)

    # ==========================================================
    # RESOURCE GROUPS
    # ==========================================================

    resource_groups = list(
        resource_client.resource_groups.list()
    )

    print("\nAzure Resource Groups:")
    print("-------------------------------")

    for resource_group in resource_groups:
        print(f"- {resource_group.name}")

    print(
        f"\nTotal resource groups: "
        f"{len(resource_groups)}"
    )

    # ==========================================================
    # ALL FINDINGS
    # ==========================================================

    all_findings = []

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

            account_name = storage_account.name
            resource_group_name = resource_group.name

            # --------------------------------------------------
            # STORAGE-001
            # --------------------------------------------------

            finding = check_storage_public_access(
                storage_client,
                resource_group_name,
                account_name,
            )

            all_findings.append(finding)
            print_finding(finding)

            # --------------------------------------------------
            # STORAGE-002
            # --------------------------------------------------

            finding = check_secure_transfer(
                storage_client,
                resource_group_name,
                account_name,
            )

            all_findings.append(finding)
            print_finding(finding)

            # --------------------------------------------------
            # STORAGE-003
            # --------------------------------------------------

            finding = check_storage_tls_version(
                storage_client,
                resource_group_name,
                account_name,
            )

            all_findings.append(finding)
            print_finding(finding)

            # --------------------------------------------------
            # STORAGE-004
            # --------------------------------------------------

            finding = check_storage_public_network_access(
                storage_client,
                resource_group_name,
                account_name,
            )

            all_findings.append(finding)
            print_finding(finding)

        # ==========================================================
    # KEY VAULT SECURITY SCAN
    # ==========================================================

    print("\nKey Vault Security Scan")
    print("===============================")

    for resource_group in resource_groups:

        vaults = list(
            keyvault_client.vaults.list_by_resource_group(
                resource_group.name
            )
        )

        for vault in vaults:

            # --------------------------------------------------
            # KEYVAULT-001
            # --------------------------------------------------

            finding = check_keyvault_soft_delete(
                keyvault_client,
                resource_group.name,
                vault.name,
            )

            all_findings.append(finding)
            print_finding(finding)

            # --------------------------------------------------
            # KEYVAULT-002
            # --------------------------------------------------

            finding = check_keyvault_public_network_access(
                keyvault_client,
                resource_group.name,
                vault.name,
            )

            all_findings.append(finding)
            print_finding(finding)

            # --------------------------------------------------
            # KEYVAULT-003
            # --------------------------------------------------

            finding = check_keyvault_purge_protection(
                keyvault_client,
                resource_group.name,
                vault.name,
            )

            all_findings.append(finding)
            print_finding(finding)


    

    # ==========================================================
    # COMPUTE SECURITY SCAN
    # ==========================================================

    print("\nCompute Security Scan")
    print("===============================")

    compute_findings = []

    for resource_group in resource_groups:
        rg_findings = check_vm_public_ip(
            compute_client,
            network_client,
            resource_group.name
        )

        compute_findings.extend(rg_findings)

        for finding in rg_findings:
            print_finding(finding)

    all_findings.extend(compute_findings)
        # ==========================================================
    # NETWORK SECURITY SCAN
    # ==========================================================

    print("\nNetwork Security Scan")
    print("===============================")

    network_findings = []

    for resource_group in resource_groups:
        rg_findings = check_nsg_remote_access(
            network_client,
            resource_group.name
        )

        network_findings.extend(rg_findings)

        for finding in rg_findings:
            print(f"\n[{finding.severity}] {finding.rule_id}")
            print(f"Resource: {finding.resource}")
            print(f"Title: {finding.title}")
            print(f"Description: {finding.description}")
            print(f"Recommendation: {finding.recommendation}")
    all_findings.extend(network_findings)

    # ==========================================================
    # VM-003 - DANGEROUS NSG RULES
    # ==========================================================

    for resource_group in resource_groups:
        rg_findings = check_nsg_dangerous_rules(
            network_client,
            resource_group.name,
        )

        network_findings.extend(rg_findings)

        for finding in rg_findings:
            print(f"\n[{finding.severity}] {finding.rule_id}")
            print(f"Resource: {finding.resource}")
            print(f"Title: {finding.title}")
            print(f"Description: {finding.description}")
            print(f"Recommendation: {finding.recommendation}")

    all_findings.extend(network_findings)

        # ==========================================================
    # IAM / RBAC SECURITY SCAN
    # ==========================================================

    print("\nIAM / RBAC Security Scan")
    print("===============================")

    iam_findings = check_subscription_privileged_assignments(
        authorization_client,
        subscription_id,
    )

    for finding in iam_findings:
        print_finding(finding)

    all_findings.extend(iam_findings)

    iam_service_principal_findings = (
        check_subscription_privileged_service_principals(
            authorization_client,
            subscription_id,
        )
    )

    for finding in iam_service_principal_findings:
        print_finding(finding)

    all_findings.extend(iam_service_principal_findings)

    iam_user_findings = check_direct_subscription_privileged_users(
        authorization_client,
        subscription_id,
    )

    for finding in iam_user_findings:
        print_finding(finding)

    all_findings.extend(iam_user_findings)
    # ==========================================================
    # FINAL SUMMARY
    # ==========================================================

    resources_scanned = len(set(
        finding.resource
        for finding in all_findings
    ))

    checks_performed = len(all_findings)

    passed = sum(
        1
        for finding in all_findings
        if finding.severity == "PASS"
    )

    failed = sum(
        1
        for finding in all_findings
        if finding.severity in ["HIGH", "MEDIUM"]
    )

    informational = sum(
        1
        for finding in all_findings
        if finding.severity == "INFO"
    )

    print("\nCloudSec Scan Summary")
    print("===============================")
    print(f"Resources scanned: {resources_scanned}")
    print(f"Checks performed:  {checks_performed}")
    print(f"Passed:            {passed}")
    print(f"Failed:            {failed}")
    print(f"Informational:     {informational}")

    if failed > 0:
        overall_status = "AT RISK"
    else:
        overall_status = "SECURE"

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