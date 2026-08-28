from ..models import SecurityFinding


def check_nsg_remote_access(network_client, resource_group_name):
    findings = []

    nsgs = network_client.network_security_groups.list(resource_group_name)

    for nsg in nsgs:
        nsg_name = nsg.name

        for rule in nsg.security_rules:
            if rule.access != "Allow":
                continue

            if rule.direction != "Inbound":
                continue

            if rule.protocol not in ("Tcp", "*"):
                continue

            source = rule.source_address_prefix
            destination_port = str(rule.destination_port_range)

            if source in ("*", "0.0.0.0/0", "Internet"):

                if destination_port == "22":
                    findings.append(
                        SecurityFinding(
                            rule_id="VM-002",
                            severity="HIGH",
                            resource=nsg_name,
                            title="SSH is exposed to the Internet",
                            description=(
                                "Inbound TCP port 22 is accessible "
                                "from any IPv4 address."
                            ),
                            recommendation=(
                                "Restrict SSH access to trusted IP ranges "
                                "or use a secure remote-access solution."
                            )
                        )
                    )

                elif destination_port == "3389":
                    findings.append(
                        SecurityFinding(
                            rule_id="VM-002",
                            severity="HIGH",
                            resource=nsg_name,
                            title="RDP is exposed to the Internet",
                            description=(
                                "Inbound TCP port 3389 is accessible "
                                "from any IPv4 address."
                            ),
                            recommendation=(
                                "Restrict RDP access to trusted IP ranges "
                                "or use a secure remote-access solution."
                            )
                        )
                    )

    if not findings:
        findings.append(
            SecurityFinding(
                rule_id="VM-002",
                severity="PASS",
                resource=resource_group_name,
                title="No SSH or RDP exposure detected",
                description=(
                    "No inbound NSG rule was found exposing SSH "
                    "or RDP directly to the Internet."
                ),
                recommendation="No action required."
            )
        )

    return findings


def check_nsg_dangerous_rules(network_client, resource_group_name):
    findings = []

    nsgs = network_client.network_security_groups.list(resource_group_name)

    dangerous_ports = {
        "22": (
            "SSH",
            "HIGH",
            "Restrict SSH access to trusted IP ranges."
        ),
        "3389": (
            "RDP",
            "HIGH",
            "Restrict RDP access to trusted IP ranges."
        ),
        "23": (
            "Telnet",
            "HIGH",
            "Disable Telnet and use SSH instead."
        ),
        "445": (
            "SMB",
            "HIGH",
            "Restrict SMB access to trusted networks."
        ),
        "1433": (
            "SQL Server",
            "HIGH",
            "Restrict SQL Server access to trusted networks."
        ),
        "3306": (
            "MySQL",
            "HIGH",
            "Restrict MySQL access to trusted networks."
        ),
        "5432": (
            "PostgreSQL",
            "HIGH",
            "Restrict PostgreSQL access to trusted networks."
        ),
    }

    for nsg in nsgs:
        nsg_name = nsg.name

        for rule in nsg.security_rules:
            if rule.access != "Allow":
                continue

            if rule.direction != "Inbound":
                continue

            source = rule.source_address_prefix

            if source not in ("*", "0.0.0.0/0", "Internet"):
                continue

            destination_port = str(rule.destination_port_range)

            if destination_port in dangerous_ports:
                service, severity, recommendation = dangerous_ports[
                    destination_port
                ]

                findings.append(
                    SecurityFinding(
                        rule_id="VM-003",
                        severity=severity,
                        resource=nsg_name,
                        title=f"{service} is exposed to the Internet",
                        description=(
                            f"Inbound traffic to {service} "
                            f"(port {destination_port}) is allowed "
                            "from any IPv4 address."
                        ),
                        recommendation=recommendation
                    )
                )

    if not findings:
        findings.append(
            SecurityFinding(
                rule_id="VM-003",
                severity="PASS",
                resource=resource_group_name,
                title="No dangerous inbound NSG rules detected",
                description=(
                    "No inbound NSG rule was found exposing "
                    "high-risk services to the Internet."
                ),
                recommendation="No action required."
            )
        )

    return findings