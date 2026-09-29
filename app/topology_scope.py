import ipaddress
import os

def include_ipv6():
    return os.getenv("TOPOLOGY_INCLUDE_IPV6", "false").strip().lower() in {"1","true","yes","on"}

def classify_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link_local"
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_private:
        return "internal"
    return "external"

def reportable_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.version == 6 and not include_ipv6())

def ip_sort_key(value):
    try:
        addr = ipaddress.ip_address(value)
        return (addr.version, int(addr))
    except ValueError:
        return (99, str(value))
