"""CrossHair target for api_bgp_ls_linkstate_update.

The entry point for test generation is
`api_bgp_ls_linkstate_update_with_precondition`.
"""

from modeling_primitives import opaque_addr_t, uint8_t, uint32_t
from bgp_ls.linkstate_mgmt.linkstate_data import *
from bgp_ls.linkstate_mgmt.api_bgp_ls_linkstate_update import BgpLsLinkState
from bgp_ls.linkstate_mgmt.igp_primitives import sys_id_t


def _correct_edge_params(
    api_src_sys_id: int,
    api_dest_sys_id: int,
    api_local: int,
    api_remote: int,
) -> tuple[int, int, int, int]:
    """Ensures edge parameters supplied to the model API do not produce a broken
    state.

    For edges updates, the source node's ID and IP both must not be the same as
    the destination node's ID and IP. Special addresses, such as the unspecified
    address, must also be avoided due to how FRR processes these."""

    new_src_sys_id, new_dest_sys_id, new_local, new_remote = (
        api_src_sys_id,
        api_dest_sys_id,
        api_local,
        api_remote,
    )

    # ensure sys IDs and IPs are not unspecified
    DEFAULT_ID = 1
    ALT_ID = 9552

    if new_src_sys_id == 0:
        new_src_sys_id = DEFAULT_ID

    if new_dest_sys_id == 0:
        new_dest_sys_id = ALT_ID

    if new_local == 0:
        new_local = DEFAULT_ID

    if new_remote == 0:
        new_remote = ALT_ID

    sign = lambda x: (x > 0) - (x < 0)

    # ensure edge does not point back to the same node or through the same
    # interface; we simply assign it to an adjacent hashable address
    # note that we need to ensure the new number is not zero; to do this, we
    # add the sign to move it away from zero
    if new_src_sys_id == new_dest_sys_id:
        new_dest_sys_id += sign(new_dest_sys_id)

    if new_local == new_remote:
        new_remote += sign(new_remote)

    return new_src_sys_id, new_dest_sys_id, new_local, new_remote


def _correct_subnet_params(
    api_adv_node: int, api_prefix: int
) -> tuple[int, int]:
    """Ensures subnet parameters supplied to the model API do not produce a
    broken state.

    For subnet updates, both the advertising node's ID and the prefix must not
    be unspecified due to how FRR processes these.
    """

    if api_adv_node == 0:
        api_adv_node = 1

    if api_prefix == 0:
        api_prefix = 1

    return api_adv_node, api_prefix


def _correct_ted_seed(
    link_seed: list[tuple[int, int, int, int]],
    prefix_seed: list[tuple[int, int]],
    api_edge: tuple[int, int, int, int] | None,
    api_subnet: tuple[int, int] | None,
) -> tuple[list[tuple[int, int, int, int]], list[tuple[int, int]]]:
    """Ensures the TED seed supplied to the model API does not clash with edge
    or subnet updates and produce a broken state.

    Because this function handles both edge and subnet updates, both existing
    links and existing prefixes within the TED seed must be checked."""

    out_link: list[tuple[int, int, int, int]] = []
    out_prefix: list[tuple[int, int]] = []

    """
    Edges are checked for the following conditions:
      1. Each edge must not contain an unspecified ID or IP.
      2. Each IP (local and remote) must belong to only one uniquely
         identifiable node.
      3. Each edge must describe a link between two different nodes, not a link
         back to itself.
      4. Each edge must describe a link to a different node on an interface not
         already described by another edge.
      5. Each edge must describe a unique link.
    """

    sys_ip = {}

    match api_edge:
        case (api_src_sys_id, api_dest_sys_id, api_local, api_remote):
            sys_ip[api_src_sys_id] = {api_local}
            sys_ip[api_dest_sys_id] = {api_remote}

    for edge in link_seed:
        # skip edges with unspecified addresses
        if any(edge_id == 0 for edge_id in edge):
            continue

        src_sys_id, dest_sys_id, local, remote = edge
        edge_interfaces = ((src_sys_id, local), (dest_sys_id, remote))
        api_interfaces = ()
        match api_edge:
            case (api_src_sys_id, api_dest_sys_id, api_local, api_remote):
                api_interfaces = (
                    (api_src_sys_id, api_local),
                    (api_dest_sys_id, api_remote),
                )

        # skip mismatched edges, i.e. enforce one-to-many relationship
        # between ISO sys IDs to IP addresses
        if any(
            sys_id != node and ip in ips
            for sys_id, ips in sys_ip.items()
            for node, ip in edge_interfaces
        ):
            continue

        # skip edges back to the same node; doing this after mismatched edges
        # should ensure that each IP address belongs to only one uniquely
        # identifiable router
        if src_sys_id == dest_sys_id or local == remote:
            continue

        # skip edges with same node, same interface as parameters
        # this ensures that we do not need to model edge deletions at the same
        # time
        if (
            api_interfaces
            and sum(
                interface == api_interface
                for interface in edge_interfaces
                for api_interface in api_interfaces
            )
            == 1
        ):
            continue

        # skip duplicates
        if any(edge == e for e in out_link):
            continue

        # append the valid edge
        sys_ip.setdefault(src_sys_id, set()).add(local)
        sys_ip.setdefault(dest_sys_id, set()).add(remote)
        out_link.append(edge)

        rev = (dest_sys_id, src_sys_id, remote, local)
        if rev not in out_link:
            out_link.append(rev)

    """
    Subnets are checked for the following conditions:
      1. Each subnet must not contain an unspecified ID or IP prefix.
      2. Each IP prefix must belong to only one uniquely identifiable node.
      3. Each subnet must describe a unique prefix.
    """

    sys_prefix = {}

    match api_subnet:
        case (api_adv, api_prefix):
            sys_prefix[api_adv] = {api_prefix}

    for subnet in prefix_seed:
        # skip subnets with unspecified addresses
        if any(edge_id == 0 for edge_id in subnet):
            continue

        adv_node, prefix = subnet

        # skip mismatched subnets, i.e. enforce one-to-many relationship between
        # ISO sys IDs to IP subnets
        if any(
            sys_id != adv_node and prefix in prefixes
            for sys_id, prefixes in sys_prefix.items()
        ):
            continue

        # skip duplicates
        if any(subnet == s for s in out_prefix):
            continue

        # append the valid subnet
        sys_prefix.setdefault(adv_node, set()).add(prefix)
        out_prefix.append(subnet)

    return out_link, out_prefix


def _build_state_and_api(
    link_seed: list[tuple[int, int, int, int]],
    prefix_seed: list[tuple[int, int]],
    api_event: int,
    api_asn: int,
    api_level: int,
    api_ls: tuple[int, int, int, int] | tuple[int, int],
) -> tuple[BgpLsLinkState, BApiLinkStateUpdate]:
    """Construct the model state and API parameters from canonicalized inputs.

    Both the symbolic entry point and the postprocessor go through here. Callers
    must have already run _correct_edge_params, _correct_subnet_params, and
    _correct_ted_seed on the seed.

    """

    state = BgpLsLinkState(asn=uint32_t(api_asn))

    # populate TED and RIB with edges
    for src_sys_id, dest_sys_id, local, remote in link_seed:
        state.ted.append(
            LinkStateEdge(
                uint32_t(api_asn),
                opaque_addr_t(local),
                opaque_addr_t(remote),
                LinkStateNodeId(sys_id_t(src_sys_id), uint8_t(api_level)),
                LinkStateNodeId(sys_id_t(dest_sys_id), uint8_t(api_level)),
            )
        )
        state.rib.append(
            BgpLsLinkNlri(
                BgpLsNode(uint32_t(api_asn), sys_id_t(src_sys_id)),
                BgpLsNode(uint32_t(api_asn), sys_id_t(dest_sys_id)),
                BgpLsLink(
                    opaque_addr_t(local),
                    opaque_addr_t(remote),
                    uint32_t(api_asn),
                ),
            )
        )

    # populate TED and RIB with subnets
    for adv_node, prefix in prefix_seed:
        state.ted.append(LinkStateSubnet(opaque_prefix_t(prefix)))
        state.rib.append(
            BgpLsPrefixNlri(
                BgpLsNode(uint32_t(api_asn), sys_id_t(adv_node)),
                BgpLsPrefix(BgpRouteType.LOCAL, opaque_prefix_t(prefix)),
            )
        )

    # construct link-state message
    match api_ls:
        case (api_src_sys_id, api_dest_sys_id, api_local, api_remote):
            # edge update
            src_node = LinkStateNodeId(
                sys_id_t(api_src_sys_id), uint8_t(api_level)
            )
            dest_node = LinkStateNodeId(
                sys_id_t(api_dest_sys_id), uint8_t(api_level)
            )

            attr = LinkStateAttributes(
                local=opaque_addr_t(api_local),
                remote=opaque_addr_t(api_remote),
                adv_node=src_node,
                remote_node=dest_node,
            )

            api = BApiLinkStateUpdate(
                event=LinkStateEvent(api_event), data=attr
            )
        case (api_adv, api_prefix):
            # prefix update
            adv_node = LinkStateNodeId(sys_id_t(api_adv), uint8_t(api_level))

            prefix = LinkStatePrefix(
                adv=adv_node, prefix=opaque_prefix_t(api_prefix)
            )

            api = BApiLinkStateUpdate(
                event=LinkStateEvent(api_event), data=prefix
            )

    return state, api


def api_bgp_ls_linkstate_update_with_precondition(
    link_seed: list[tuple[int, int, int, int]],
    prefix_seed: list[tuple[int, int]],
    api_event: int,
    api_asn: int,
    api_level: int,
    api_ls: tuple[int, int, int, int] | tuple[int, int],
) -> BgpAttributes | None:

    api_event %= 5

    EDGE_TUPLE_LEN = 4
    SUBNET_TUPLE_LEN = 2

    if len(api_ls) == EDGE_TUPLE_LEN:
        # edge update event
        api_ls = _correct_edge_params(*api_ls)

        link_seed, prefix_seed = _correct_ted_seed(
            link_seed, prefix_seed, api_ls, None
        )

    elif len(api_ls) == SUBNET_TUPLE_LEN:
        # subnet update event
        api_ls = _correct_subnet_params(*api_ls)

        link_seed, prefix_seed = _correct_ted_seed(
            link_seed, prefix_seed, None, api_ls
        )

    state, api = _build_state_and_api(
        link_seed, prefix_seed, api_event, api_asn, api_level, api_ls
    )

    return state.api_bgp_ls_linkstate_update(api)
