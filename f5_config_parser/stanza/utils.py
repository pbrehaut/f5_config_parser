import re
from typing import List


def _parse_monitor_expression(monitor_expr: str) -> List[str]:
    """
    Parse monitor expressions that can contain 'and' or 'or' operators.

    Examples:
    - "mon-http" → ["mon-http"]
    - "mon-https and mon-tcp" → ["mon-https", "mon-tcp"]
    - "mon-a or mon-b" → ["mon-a", "mon-b"]
    """
    # Split on 'and' and 'or' operators
    # Split on 'and' or 'or' (case insensitive, with word boundaries)
    monitors = re.split(r'\s+(?:and|or)\s+', monitor_expr, flags=re.IGNORECASE)
    # Strip whitespace from each monitor name
    return [monitor.strip() for monitor in monitors if monitor.strip()]


def _is_ip_address(value: str) -> bool:
    """Check if value is an IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_rd_from_ip(ip_address: str) -> str:
    """
    Get the route domain from an IP address.
    Args:
        ip_address: IP address as a string
    Returns:
        Route domain as a string
    """
    rd = re.search(r'%(\d+)', ip_address)
    if rd:
        return rd.group(1)
    return ""
