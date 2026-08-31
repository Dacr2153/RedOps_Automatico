"""Network-related validation and formatting helpers.

These pure functions are used across modules to validate IP addresses,
CIDR ranges and build Nmap argument strings safely.
"""

from __future__ import annotations

import ipaddress


def is_valid_ip(address: str) -> bool:
    """Return True if *address* is a valid IPv4 address.

    Args:
        address: String to validate.

    Returns:
        ``True`` for valid IPv4, ``False`` otherwise.
    """
    try:
        ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def is_valid_cidr(network: str) -> bool:
    """Return True if *network* is a valid IPv4 CIDR notation.

    Args:
        network: CIDR string to validate (e.g. ``192.168.56.0/24``).

    Returns:
        ``True`` for valid CIDR, ``False`` otherwise.
    """
    try:
        ipaddress.IPv4Network(network, strict=False)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def hosts_in_cidr(network: str) -> list[str]:
    """Enumerate all host IPs in a CIDR range (excludes network and broadcast).

    Args:
        network: CIDR notation string.

    Returns:
        List of IPv4 host addresses as strings.

    Raises:
        ValueError: If *network* is not a valid CIDR.
    """
    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"Invalid CIDR: {network}") from exc
    return [str(host) for host in net.hosts()]


def sanitize_ip_for_log(ip: str) -> str:
    """Partially redact an IP address for safe logging at INFO+ levels.

    The last octet is replaced with ``xxx`` so that exact targets are not
    leaked into aggregated log stores.

    Args:
        ip: An IPv4 address string.

    Returns:
        Redacted IP (e.g. ``192.168.56.xxx``).
    """
    parts = ip.split(".")
    if len(parts) == 4:  # noqa: PLR2004
        parts[3] = "xxx"
    return ".".join(parts)
