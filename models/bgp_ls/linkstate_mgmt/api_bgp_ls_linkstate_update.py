"""Executable model of bgpd's link state edge-processing callback and prefix-
processing callback (api_bgp_ls_linkstate_update).

The four MBT artifacts a tester uses:

* State        — BgpLsLinkState. What bgpd remembers between calls. Based off
                 the BGP-LS Traffic Engineering Database (TED) and Routing
                 Information Base (RIB). Read from and written to by each call.
* Transition   — api_bgp_ls_linkstate_update (api). The action under test.
                 Returns BgpAttributes modeling the data payload sent to peers
                 after successfully originating a link or prefix. Can be null if
                 nothing occurs.
* Precondition — api_bgp_ls_linkstate_update (api). Guards the action. Random/
                 symbolic test generators use it to skip or shrink infeasible
                 inputs.
* Invariant    — Must hold at every state the model visits. Checked after each
                 transition.

Scope: api_bgp_ls_linkstate_update only. Node updates are out of scope. This
model currently only handles IPv6; IPv4, interoperability between IS-IS levels
and OSPF areas, SR/SRv6, and MT routing are out of scope.
"""

from bgp_ls.linkstate_mgmt.linkstate_data import *
from dataclasses import dataclass, field
from modeling_primitives import (
    clamp_u32,
    no_dup,
    opaque_addr_t,
    uint32_t,
)


# ── Model: state, contract, transition ────────────────────────────────────────


@dataclass
class BgpLsLinkState:
    """
    The model's overall state. Represents bgpd's memory between API calls.
    Tracks the BGP-LS TED and RIB. Handles both link updates and prefix updates.
    """

    asn: uint32_t = field(default=uint32_t(100))  # arbitrary ASN for now
    ted: list[LinkStateEdge | LinkStateSubnet] = field(default_factory=list)
    rib: list[BgpLsLinkNlri | BgpLsPrefixNlri] = field(default_factory=list)

    # ── Invariant ─────────────────────────────────────────────────────────────
    def invariant(self) -> bool:
        """
        Groups of constraints:
          1. Keys are unique within each table, and each IP address and prefix
             must be assigned to one uniquely identifiable node.
          2. RIB entries are well-formed; link NLRI include both node and link
             descriptors, and prefix NLRI include advertising node and prefix.
          3. The LSDB/TED and the RIB agree: every edge described in the NLRI
             corresponds to a link entry within the LSDB/TED.

        Future Modeling Notes:
        * Nexthop deduplication: Nexthops should be duplicated if using multi-
          domain (IS-IS and OSPF). Since the current scope is only IS-IS,
          deduplication is pending.
        """

        # ── Uniqueness ────────────────────────────────────────────────────────
        ted_edges = [
            entry for entry in self.ted if isinstance(entry, LinkStateEdge)
        ]

        ted_unique = no_dup(entry for entry in self.ted)
        ted_nonloop = all(edge.source != edge.destination for edge in ted_edges)
        ted_one_sys_many_ip = self._sys_id_matches_ip(ted_edges)
        ted_nonzero_ids = all(
            edge.source_node.iso_sys_id != 0
            and edge.destination_node.iso_sys_id != 0
            and edge.source != 0
            and edge.destination != 0
            for edge in ted_edges
        )

        # ── Format ────────────────────────────────────────────────────────────
        rib_links = [
            entry for entry in self.rib if isinstance(entry, BgpLsLinkNlri)
        ]

        nlri_nodes_nonnull = all(
            nlri.source and nlri.destination for nlri in rib_links
        )
        nlri_link_nonnull = all(nlri.link for nlri in rib_links)
        nlri_nonloop = all(
            nlri.source.igp_router_id != nlri.destination.igp_router_id
            for nlri in rib_links
        )

        rib_prefixes = [
            entry for entry in self.rib if isinstance(entry, BgpLsPrefixNlri)
        ]
        nlri_prefix_nonnull = all(
            nlri.local_node and nlri.prefix for nlri in rib_prefixes
        )
        nlri_one_sys_many_prefixes = self._sys_id_matches_prefix(rib_prefixes)

        # ── LSDB/TED ──────────────────────────────────────────────────────────
        ted_is_referenced = all(
            any(
                nlri.link.interface == edge.source
                and nlri.link.neighbor == edge.destination
                for edge in ted_edges
            )
            for nlri in rib_links
        ) and all(
            any(
                nlri.prefix.prefix == subnet.prefix
                for subnet in [
                    entry
                    for entry in self.ted
                    if isinstance(entry, LinkStateSubnet)
                ]
            )
            for nlri in rib_prefixes
        )

        return (
            ted_unique
            and ted_nonloop
            and ted_one_sys_many_ip
            and ted_nonzero_ids
            and nlri_nodes_nonnull
            and nlri_link_nonnull
            and nlri_nonloop
            and nlri_prefix_nonnull
            and nlri_one_sys_many_prefixes
            and ted_is_referenced
        )

    # ── Precondition ──────────────────────────────────────────────────────────
    def api_bgp_ls_linkstate_update_precondition(
        self, api: BApiLinkStateUpdate
    ) -> bool:
        """Action guard. The harness must only call api_bgp_ls_linkstate_update
        when this returns True."""

        return self.invariant()

    # ── Transition ────────────────────────────────────────────────────────────
    def api_bgp_ls_linkstate_update(
        self, api: BApiLinkStateUpdate
    ) -> BgpAttributes | None:
        """Process one zebra link-state update.

        Returns the payload bgpd would emit to connected BGP peers. After this
        call the state must still satisfy invariant() — the harness checks this.
        """

        # find and link reverse edge only if sync, add, or update event
        if api.event == LinkStateEvent.UNDEF:
            return None

        # route to appropriate action
        match api.data:
            case LinkStateAttributes() if api.event == LinkStateEvent.DELETE:
                return self._delete_edge(api.data)
            case LinkStateAttributes():
                return self._update_edge(api.data)
            case LinkStatePrefix() if api.event == LinkStateEvent.DELETE:
                return self._delete_subnet(api.data)
            case LinkStatePrefix():
                return self._update_subnet(api.data)
            case _:
                return None

    def to_dict(self) -> dict:
        """Converts this dataclass to a dictionary."""

        return {
            "asn": clamp_u32(self.asn),
            "linkstate_ted": [e.to_dict() for e in self.ted],
            "rib_nlri": [nlri.to_dict() for nlri in self.rib],
        }

    def _update_edge(self, attr: LinkStateAttributes) -> BgpAttributes | None:
        """Updates the model's state by adding a new edge.

        Corresponds to `bgp_ls_originate_link` in FRR."""

        if attr.adv_node == attr.remote_node or attr.local == attr.remote:
            # disallow loopbacks to be appended as NLRI
            return None

        # two-way connectivity check - in the FRR implementation, both forward
        # and reverse direction are checked
        edge = self._find_edge(attr.local, attr.remote)

        if not edge:
            self.ted.append(
                LinkStateEdge(
                    self.asn,
                    attr.local,
                    attr.remote,
                    attr.adv_node,
                    attr.remote_node,
                )
            )

        reverse = self._find_edge(attr.remote, attr.local)

        if not reverse:
            self.ted.append(
                LinkStateEdge(
                    self.asn,
                    attr.remote,
                    attr.local,
                    attr.remote_node,
                    attr.adv_node,
                )
            )

        ls_nlri = BgpLsLinkNlri(
            BgpLsNode(self.asn, attr.adv_node.iso_sys_id),
            BgpLsNode(self.asn, attr.remote_node.iso_sys_id),
            BgpLsLink(attr.local, attr.remote, self.asn),
        )

        # check if existing entry exists before updating
        if ls_nlri not in self.rib:
            self.rib.append(ls_nlri)

        return BgpAttributes(mp_reach_nlri=ls_nlri)

    def _update_subnet(self, prefix: LinkStatePrefix) -> BgpAttributes | None:
        """Updates the model's state by adding a new subnet.

        Corresponds to `bgp_ls_originate_prefix` in FRR."""

        subnet = self._find_subnet(prefix.prefix)

        if not subnet:
            self.ted.append(LinkStateSubnet(prefix.prefix))

        ls_nlri = BgpLsPrefixNlri(
            BgpLsNode(self.asn, prefix.adv.iso_sys_id),
            BgpLsPrefix(BgpRouteType.LOCAL, prefix.prefix),
        )

        if ls_nlri not in self.rib:
            self.rib.append(ls_nlri)

        return BgpAttributes(mp_reach_nlri=ls_nlri)

    def _delete_edge(self, attr: LinkStateAttributes) -> BgpAttributes | None:
        """Updates the model's state by withdrawing an existing edge.

        Corresponds to `bgp_ls_withdraw_link` in FRR."""

        edge = self._find_edge(attr.local, attr.remote)

        # build search NLRI
        ls_nlri = BgpLsLinkNlri(
            BgpLsNode(self.asn, attr.adv_node.iso_sys_id),
            BgpLsNode(self.asn, attr.remote_node.iso_sys_id),
            BgpLsLink(
                interface=attr.local,
                neighbor=attr.remote,
                remote_asn=self.asn,
            ),
        )

        to_update = False

        if ls_nlri in self.rib:
            self.rib.remove(ls_nlri)
            to_update = True

        if edge:
            self.ted.remove(edge)
            to_update = True

        return BgpAttributes(mp_unreach_nlri=ls_nlri) if to_update else None

    def _delete_subnet(self, prefix: LinkStatePrefix) -> BgpAttributes | None:
        """Updates the model's state by withdrawing an existing edge.

        Corresponds to `bgp_ls_withdraw_prefix` in FRR."""

        subnet = self._find_subnet(prefix.prefix)

        # build search NLRI - TODO BgpRoute as a free var
        ls_nlri = BgpLsPrefixNlri(
            BgpLsNode(self.asn, prefix.adv.iso_sys_id),
            BgpLsPrefix(BgpRouteType.LOCAL, prefix.prefix),
        )

        to_update = False

        if ls_nlri in self.rib:
            self.rib.remove(ls_nlri)
            to_update = True

        if subnet:
            self.ted.remove(subnet)
            to_update = True

        return BgpAttributes(mp_unreach_nlri=ls_nlri) if to_update else None

    def _find_edge(
        self, local: opaque_addr_t, remote: opaque_addr_t
    ) -> LinkStateEdge | None:
        """Searches for an existing LinkStateEdge corresponding to the `local`
        and `remote` nodes."""

        for e in [
            entry for entry in self.ted if isinstance(entry, LinkStateEdge)
        ]:
            if e.source == local and e.destination == remote:
                return e
        return None

    def _find_subnet(self, prefix: opaque_prefix_t) -> LinkStateSubnet | None:
        """Searches for an existing LinkStateSubnet corresponding to the given
        `prefix`."""

        for p in [
            entry for entry in self.ted if isinstance(entry, LinkStateSubnet)
        ]:
            if p.prefix == prefix:
                return p
        return None

    def _sys_id_matches_ip(self, edges: list[LinkStateEdge]) -> bool:
        """Verifies a strict 1:N mapping between system IDs and IPs."""

        pairs = []

        for e in edges:
            edge_pairs = (
                (e.source_node, e.source),
                (e.destination_node, e.destination),
            )

            for node_i, ip_i in edge_pairs:
                for node_j, ip_j in pairs:
                    if ip_i == ip_j and node_i != node_j:
                        return False

                pairs.append((node_i, ip_i))

        return True

    def _sys_id_matches_prefix(self, prefixes: list[BgpLsPrefixNlri]) -> bool:
        """Verifies a strict 1:N mapping between system IDs and IP prefixes."""

        pairs = []

        for p in prefixes:
            for node_i, prefix_i in pairs:
                if (
                    prefix_i == p.prefix.prefix
                    and node_i != p.local_node.igp_router_id
                ):
                    return False

            pairs.append((p.local_node.igp_router_id, p.prefix.prefix))

        return True
