from ..models import SecurityFinding


def check_vm_public_ip(
    compute_client,
    network_client,
    resource_group_name
):
    findings = []
    virtual_machines = list(
        compute_client.virtual_machines.list(
            resource_group_name
        )
    )

    if not virtual_machines:
        findings.append(
            SecurityFinding(
                rule_id="VM-001",
                severity="INFO",
                resource=resource_group_name,
                title="No virtual machines found",
                description=(
                    "No virtual machines were found in this "
                    "resource group, so VM public IP exposure "
                    "could not be assessed."
                ),
                recommendation="No action required."
            )
        )

        return findings

        virtual_machines = list(
        compute_client.virtual_machines.list(
            resource_group_name
        )
    )

    if not virtual_machines:
        findings.append(
            SecurityFinding(
                rule_id="VM-001",
                severity="INFO",
                resource=resource_group_name,
                title="No virtual machines found",
                description=(
                    "No virtual machines were found in this "
                    "resource group, so VM public IP exposure "
                    "could not be assessed."
                ),
                recommendation="No action required."
            )
        )

        return findings

    for vm in virtual_machines:
        vm_name = vm.name

        if not vm.network_profile or not vm.network_profile.network_interfaces:
            findings.append(
                SecurityFinding(
                    rule_id="VM-001",
                    severity="INFO",
                    resource=vm_name,
                    title="VM has no network interface configuration",
                    description=(
                        "The virtual machine does not expose a network "
                        "interface configuration through its VM definition."
                    ),
                    recommendation=(
                        "Review the VM network configuration."
                    )
                )
            )
            continue

        has_public_ip = False

        for nic_ref in vm.network_profile.network_interfaces:
            nic_id = nic_ref.id

            nic_name = nic_id.split("/")[-1]

            nic = network_client.network_interfaces.get(
                resource_group_name,
                nic_name
            )

            if not nic.ip_configurations:
                continue

            for ip_config in nic.ip_configurations:
                if ip_config.public_ip_address:
                    has_public_ip = True
                    break

            if has_public_ip:
                break

        if has_public_ip:
            findings.append(
                SecurityFinding(
                    rule_id="VM-001",
                    severity="HIGH",
                    resource=vm_name,
                    title="Virtual machine has a public IP address",
                    description=(
                        "The virtual machine is associated with a public "
                        "IP address and may be directly reachable from "
                        "the Internet."
                    ),
                    recommendation=(
                        "Remove the public IP if it is not required. "
                        "Prefer private networking, VPN, Bastion, or "
                        "other controlled access mechanisms."
                    )
                )
            )
        else:
            findings.append(
                SecurityFinding(
                    rule_id="VM-001",
                    severity="PASS",
                    resource=vm_name,
                    title="Virtual machine has no public IP address",
                    description=(
                        "The virtual machine is not directly associated "
                        "with a public IP address."
                    ),
                    recommendation="No action required."
                )
            )

    return findings