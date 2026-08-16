from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

from .checks.storage import (
    check_storage_public_access,
    check_secure_transfer,
    check_storage_tls_version,
    check_storage_public_network_access
)

from .reporting import save_json_report

import json
import subprocess


def get_subscription_id():
    result = subprocess.run(
        ["az.cmd", "account", "show", "--output", "json"],
        capture_output=True,
        text=True,
        check=True
    )

    account = json.loads(result.stdout)

    return account["id"]


def main():
    print("CloudSec")
    print("Cloud Security Posture Management")
    print("-------------------------------")

    credential = AzureCliCredential()

    subscription_id = get_subscription_id()

    resource_client = ResourceManagementClient(
        credential,
        subscription_id
    )

    storage_client = StorageManagementClient(
        credential,
        subscription_id
    )

    print("\nAzure Resource Groups:")
    print("-------------------------------")

    resource_groups = list(
        resource_client.resource_groups.list()
    )

    for resource_group in resource_groups:
        print(f"- {resource_group.name}")

    print(f"\nTotal resource groups: {len(resource_groups)}")

    print("\nStorage Security Scan")
    print("===============================")

    total_resources = 0
    total_checks = 0
    passed_checks = 0
    failed_checks = 0
    info_checks = 0

    all_findings = []

    for resource_group in resource_groups:

        storage_accounts = list(
            storage_client.storage_accounts.list_by_resource_group(
                resource_group.name
            )
        )

        for account in storage_accounts:

            total_resources += 1

            findings = [
                check_storage_public_access(
                    storage_client,
                    resource_group.name,
                    account.name
                ),
                check_secure_transfer(
                    storage_client,
                    resource_group.name,
                    account.name
                ),
                check_storage_tls_version(
                    storage_client,
                    resource_group.name,
                    account.name
                ),
                check_storage_public_network_access(
                    storage_client,
                    resource_group.name,
                    account.name
                )
            ]

            for finding in findings:

                all_findings.append(finding)

                total_checks += 1

                if finding.severity == "PASS":
                    passed_checks += 1

                elif finding.severity == "INFO":
                    info_checks += 1

                else:
                    failed_checks += 1

                print(f"\n[{finding.severity}] {finding.rule_id}")
                print(f"Resource: {finding.resource}")
                print(f"Title: {finding.title}")
                print(f"Description: {finding.description}")
                print(f"Recommendation: {finding.recommendation}")

    print("\nCloudSec Scan Summary")
    print("===============================")
    print(f"Resources scanned: {total_resources}")
    print(f"Checks performed:  {total_checks}")
    print(f"Passed:            {passed_checks}")
    print(f"Failed:            {failed_checks}")
    print(f"Informational:     {info_checks}")

    if failed_checks == 0:
        print("\nOverall status: SECURE")
    else:
        print("\nOverall status: ATTENTION REQUIRED")

    save_json_report(
        all_findings,
        total_resources,
        total_checks,
        passed_checks,
        failed_checks,
        info_checks
    )

    print("\nJSON report generated:")
    print("reports/cloudsec-report.json")

    print("\nCloudSec scan completed.")


if __name__ == "__main__":
    main()