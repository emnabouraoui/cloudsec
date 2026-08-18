from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

from ..models import SecurityFinding


def check_vm_public_ip(
    compute_client: ComputeManagementClient,
    network_client: NetworkManagementClient,
    resource_group_name: str,
):
    findings = []

    for vm in compute_client.virtual_machines.list(
        resource_group_name
    ):

        vm_name = vm.name

        if (
            not vm.network_profile
            or not vm.network_profile.network_interfaces
        ):
            findings.append(
                SecurityFinding(
                    rule_id="COMPUTE-001",
                    severity="INFO",
                    resource=vm_name,
                    title="VM has no network interface information",
                    description=(
                        "Azure did not return network interface "
                        "information for this virtual machine."
                    ),
                    recommendation=(
                        "Review the VM network configuration."
                    ),
                )
            )

            continue

        has_public_ip = False

        for nic_ref in vm.network_profile.network_interfaces:

            nic_id = nic_ref.id

            if not nic_id:
                continue

            nic_name = nic_id.split("/")[-1]

            nic = network_client.network_interfaces.get(
                resource_group_name,
                nic_name,
            )

            for ip_config in nic.ip_configurations or []:

                if not ip_config.public_ip_address:
                    continue

                public_ip_id = (
                    ip_config.public_ip_address.id
                )

                if public_ip_id:
                    has_public_ip = True
                    break

            if has_public_ip:
                break

        if has_public_ip:

            findings.append(
                SecurityFinding(
                    rule_id="COMPUTE-001",
                    severity="HIGH",
                    resource=vm_name,
                    title="VM has a public IP address",
                    description=(
                        "The virtual machine is directly exposed "
                        "through a public IP address."
                    ),
                    recommendation=(
                        "Remove the public IP address if direct "
                        "internet exposure is not required."
                    ),
                )
            )

        else:

            findings.append(
                SecurityFinding(
                    rule_id="COMPUTE-001",
                    severity="PASS",
                    resource=vm_name,
                    title="VM has no public IP address",
                    description=(
                        "The virtual machine is not directly "
                        "exposed through a public IP address."
                    ),
                    recommendation="No action required.",
                )
            )

    return findings