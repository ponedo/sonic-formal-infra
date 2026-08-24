from bgp_ls.linkstate_mgmt.igp_primitives import sys_id_t, to_sys_id
from dataclasses import dataclass
from enum import IntEnum
from modeling_primitives import (
    clamp_u32,
    opaque_addr_t,
    opaque_prefix_t,
    to_ipv6_opaque_address,
    to_ipv6_opaque_prefix,
    uint8_t,
    uint32_t,
)

# ── Domain types ──────────────────────────────────────────────────────────────
# Abstract types that capture key fields relevant to bgpd's handling of link
# state edge updates.


# ── BGP-LS data structures ────────────────────────────────────────────────────
# BGP-LS-specific types; adheres to RFC and implemented similarly within FRR.


class BgpRouteType(IntEnum):
    LOCAL = 1
    ATTACHED = 2
    EXTERNAL_BGP = 3
    INTERNAL_BGP = 4
    REDISTRIBUTED = 5


@dataclass
class BgpLsNode:
    """Node descriptor: identifies a node in the topology by a router ID.

    All types of NLRI (node, link, and prefix) are required to contain at least
    one node descriptor."""

    asn: uint32_t
    igp_router_id: sys_id_t

    def to_dict(self) -> dict:
        return {
            "asn": clamp_u32(self.asn),
            "igp_router_id": to_sys_id(self.igp_router_id),
        }


@dataclass
class BgpLsLink:
    """Link descriptor: identifies a link between two nodes in the topology by
    their router IDs and IP addresses.

    A link between two nodes is not considered complete unless two NLRIs exist
    for this link: one in the forward direction, and one in the reverse
    direction."""

    interface: opaque_addr_t  # IPv6 address
    neighbor: opaque_addr_t  # IPv6 address
    remote_asn: uint32_t

    def to_dict(self) -> dict:
        return {
            "interface": to_ipv6_opaque_address(self.interface),
            "neighbor": to_ipv6_opaque_address(self.neighbor),
            "remote_asn": clamp_u32(self.remote_asn),
        }


@dataclass
class BgpLsPrefix:
    """Prefix descriptor: identifies a prefix advertised by a node in the
    topology.

    IP reachability information to each of its BGP next hops should be
    advertised by the advertising node."""

    bgp_route_type: BgpRouteType
    prefix: opaque_prefix_t

    def to_dict(self) -> dict:
        return {
            "bgp_route_type": self.bgp_route_type,
            "prefix": to_ipv6_opaque_prefix(self.prefix),
        }


@dataclass
class BgpLsLinkNlri:
    """Link NLRI: encapsulates a source node descriptor, destination node
    descriptor, and link descriptor to propagate as link-state information.

    All fields are required by RFC 9552. Note that, as stated before by the link
    descriptor, this NLRI only describes a one-way path between two nodes. The
    corresponding reverse link must exist to fully describe a connection between
    the two nodes according to BGP-LS."""

    source: BgpLsNode
    destination: BgpLsNode
    link: BgpLsLink

    def to_dict(self) -> dict:
        return {
            "type": "link_nlri",
            "source": self.source.to_dict(),
            "destination": self.destination.to_dict(),
            "link": self.link.to_dict(),
        }


@dataclass
class BgpLsPrefixNlri:
    """Prefix NLRI: encapsulates a local node descriptor and prefix descriptor
    to propagate as link-state information.

    All fields are required by RFC 9552. Note that the RFC also describes the
    layout for Multi-Topology identifiers and OSPF route types. This is outside
    of the model's scope. The current model only supports IPv6 prefixes."""

    local_node: BgpLsNode
    prefix: BgpLsPrefix

    def to_dict(self) -> dict:
        return {
            "type": "prefix_nlri",
            "local_node": self.local_node.to_dict(),
            "prefix": self.prefix.to_dict(),
        }


# ── Link-state data structures ────────────────────────────────────────────────
# FRR-specific Link-State implementation types. SONiC, running FRR as its
# network stack, relies on these data types to generalize information from both
# IS-IS and OSPF.


class AddressFamily(IntEnum):
    AF_INET = 2
    AF_INET6 = 10


@dataclass(frozen=True)
class LinkStateNodeId:
    """Link-state node identifier: identifies a node within FRR.

    This class is currently implemented only for IS-IS identifiers. OSPF and
    other methods for identification are outside of the model's scope.
    """

    iso_sys_id: sys_id_t
    level: uint8_t

    def to_dict(self) -> dict:
        return {"iso_sys_id": to_sys_id(self.iso_sys_id), "level": self.level}


@dataclass
class LinkStateEdge:
    """Link-state edge: represents a unidirectional link between two nodes
    within FRR.

    FRR uses a graph model to hold link-state information. Edges within this
    model correspond to links between nodes in compliance with the BGP-LS
    protocol."""

    asn: uint32_t
    source: opaque_addr_t
    destination: opaque_addr_t
    source_node: LinkStateNodeId
    destination_node: LinkStateNodeId

    def to_dict(self) -> dict:
        return {
            "type": "edge",
            "asn": clamp_u32(self.asn),
            "source": to_ipv6_opaque_address(self.source),
            "destination": to_ipv6_opaque_address(self.destination),
            "source_node": self.source_node.to_dict(),
            "destination_node": self.destination_node.to_dict(),
        }


@dataclass
class LinkStateAttributes:
    """Link-state attributes: represents an IGP-agnostic description of
    properties along a link within FRR.

    BGP-LS describes an opaque link-state propagation protocol; information
    outside of topology is often ignored by BGP-LS propagators themselves.
    Instead, IGPs are expected to properly produce link-state information for
    BGP-LS propagators to pass on.
    """

    local: opaque_addr_t  # local IPv6 address
    remote: opaque_addr_t  # remote IPv6 address
    adv_node: LinkStateNodeId  # advertising router
    remote_node: LinkStateNodeId  # remote router

    def to_dict(self) -> dict:
        return {
            "type": "attributes",
            "local": to_ipv6_opaque_address(self.local),
            "remote": to_ipv6_opaque_address(self.remote),
            "adv_node": self.adv_node.to_dict(),
            "remote_node": self.remote_node.to_dict(),
        }


@dataclass
class LinkStateSubnet:
    """Link-state subnet: represents an IP prefix within FRR.

    FRR uses a graph model to hold link-state information. Subnets within this
    model correspond to prefixes advertised by nodes in compliance with the BGP-
    LS protocol."""

    prefix: opaque_prefix_t

    def to_dict(self) -> dict:
        return {
            "type": "subnet",
            "prefix": to_ipv6_opaque_prefix(self.prefix),
        }


@dataclass
class LinkStatePrefix:
    """Link-state prefix: represents an IGP-agnostic description of a prefx
    within FRR.

    BGP-LS describes an opaque link-state propagation protocol; information
    outside of topology is often ignored by BGP-LS propagators themselves.
    Instead, IGPs are expected to properly produce link-state information for
    BGP-LS propagators to pass on.
    """

    adv: LinkStateNodeId
    prefix: opaque_prefix_t

    def to_dict(self) -> dict:
        return {
            "type": "prefix",
            "adv": self.adv.to_dict(),
            "prefix": to_ipv6_opaque_prefix(self.prefix),
        }


# ── API surface ───────────────────────────────────────────────────────────────
# The action under test takes a BApiLinkStateUpdate (what zebra sends) and
# returns 0 after successfully originating the link; -1 otherwise.


# ── Zebra types ───────────────────────────────────────────────────────────────
# Types used in the Zebra API, such as Opaque messages.


class LinkStateEvent(IntEnum):
    UNDEF = 0
    SYNC = 1
    ADD = 2
    UPDATE = 3
    DELETE = 4


@dataclass
class BApiLinkStateUpdate:
    """Input payload: represents zebra's link-state message notification. Either
    link or prefix updates may be represented by this class.
    """

    event: LinkStateEvent
    data: LinkStateAttributes | LinkStatePrefix

    def to_dict(self) -> dict:
        return {"event": self.event, "data": self.data.to_dict()}


# ── BGP data structures ───────────────────────────────────────────────────────
# BGP-specific types; adheres to RFC and implemented similarly in FRR>


@dataclass
class BgpAttributes:
    """BGP attributes: core attributes sent from a BGP message describing a
    path.

    Used by BGP-LS to update BGP-LS consumers on reachability information, such
    as reachable links or reachable prefixes."""

    mp_reach_nlri: BgpLsLinkNlri | BgpLsPrefixNlri | None = None
    mp_unreach_nlri: BgpLsLinkNlri | BgpLsPrefixNlri | None = None

    def to_dict(self) -> dict:
        attr_dict = {}
        if self.mp_reach_nlri:
            attr_dict["mp_reach_nlri"] = self.mp_reach_nlri.to_dict()
        if self.mp_unreach_nlri:
            attr_dict["mp_unreach_nlri"] = self.mp_unreach_nlri.to_dict()
        return attr_dict
