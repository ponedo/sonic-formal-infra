"""Deterministic prefix/address mapping utilities.

Mirrors the sonic-formal-infra convention: models reason over opaque integer
IDs (prefix_t / addr_t), and harnesses map those IDs to concrete strings when
driving real software like FRR bgpd.
"""
import hashlib
import ipaddress

from .types import addr_t, prefix_t


IPV4_ROOT_PREFIX = prefix_t(0)
IPV4_UNSPECIFIED = addr_t(0)


def to_ipv4_prefix(p: prefix_t) -> str:
    """Deterministic IPv4 route prefix for a prefix_t identifier.

    Returns a network address under RFC 5737's documentation ranges
    (192.0.2.0/23 or 198.51.100.0/23) with the /24 mask applied.
    The host byte is always 0 to match FRR's route_node_get() behavior
    which masks prefixes to their network address.
    IPV4_ROOT_PREFIX (id 0) maps to 0.0.0.0/0, the IPv4 default route.

    The third octet is derived from the identifier so that distinct
    prefix_t values map to distinct prefix strings (near-injective,
    mirroring to_ipv6_prefix).  This avoids accidental string collisions
    between independently-generated prefixes (e.g. an NLRI prefix vs a
    RIB prefix) that would otherwise alias to the same radix-tree node
    in FRR while remaining distinct keys in the integer-keyed model.
    """
    if p == IPV4_ROOT_PREFIX:
        return "0.0.0.0/0"
    h = hashlib.blake2b(str(int(p)).encode(), digest_size=4).hexdigest()
    # Use two documentation blocks based on the high nibble for variety.
    # The low byte varies the third octet (host byte stays 0 = network
    # address) to match FRR's prefix masking while keeping prefixes distinct.
    low = int(h[2:4], 16)
    if int(h[0], 16) & 1:
        return f"192.0.{low}.0/24"
    return f"198.51.{low}.0/24"


def to_ipv6_prefix(p: prefix_t) -> str:
    """Deterministic IPv6 route prefix for a prefix_t identifier.

    Returns an address under RFC 3849's documentation range 2001:db8::/32,
    with /128 host length. Uses ipaddress module for proper compressed format
    to match FRR's inet_ntop() output.
    prefix_t(0) maps to ::/0, the IPv6 default route.
    """
    if p == prefix_t(0):
        return "::/0"
    h = hashlib.blake2b(str(int(p)).encode(), digest_size=6).hexdigest()
    # Build full 128-bit address and use ipaddress for standard compression
    addr_int = (int(h[0:4], 16) << 96) | (int(h[4:8], 16) << 64) | int(h[8:12], 16)
    addr = ipaddress.IPv6Address((0x20010DB8 << 96) | addr_int)
    return f"{addr}/128"


def to_ipv4_address(a: addr_t) -> str:
    """Deterministic IPv4 host address for an addr_t identifier."""
    if a == IPV4_UNSPECIFIED:
        return "0.0.0.0"
    h = hashlib.blake2b(str(int(a)).encode(), digest_size=4).hexdigest()
    if int(h[0], 16) & 1:
        return f"192.0.2.{int(h[2:4], 16) % 256}"
    return f"198.51.100.{int(h[2:4], 16) % 256}"


def to_ipv6_address(a: addr_t) -> str:
    """Deterministic IPv6 host address for an addr_t identifier."""
    if a == addr_t(0):
        return "::"
    h = hashlib.blake2b(str(int(a)).encode(), digest_size=6).hexdigest()
    return f"2001:db8:{h[0:4]}:{h[4:8]}::{h[8:12]}"


def prefix_to_str(p: prefix_t, ipv6: bool = False) -> str:
    """Map a prefix_t to a concrete string based on the address family."""
    if ipv6:
        return to_ipv6_prefix(p)
    return to_ipv4_prefix(p)
