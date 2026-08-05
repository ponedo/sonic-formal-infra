"""Shared BGP RIB types and helpers used across action models.

Mirrors FRR's bgp_dest → bgp_path_info hierarchy and provides helpers
that model common RIB operations (e.g., bgp_clear_stale_route).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from lib import Afi, Safi, prefix_t


# Peer identifier (mirrors FRR's struct peer * identity)
PeerId = int


@dataclass
class PathInfo:
    """One path in a RIB dest (mirrors bgp_path_info).

    peer_id: identifies which peer announced this path
    stale: BGP_PATH_STALE flag (path retained from pre-disconnect session)
    removed: BGP_PATH_REMOVED flag (marked for deletion, pending bgp_process)
    has_llgr_stale_community: path carries COMMUNITY_LLGR_STALE
    has_no_llgr_community: path carries COMMUNITY_NO_LLGR
    """
    peer_id: PeerId
    stale: bool
    removed: bool = False
    has_llgr_stale_community: bool = False
    has_no_llgr_community: bool = False


@dataclass
class RibDest:
    """One prefix entry in RIB (mirrors bgp_dest).

    Contains a list of paths (from different peers).
    prefix is the key in the table dict.
    """
    prefix: prefix_t
    paths: List[PathInfo] = field(default_factory=list)


# RIB type alias: per-AFI/SAFI tables, each maps prefix → RibDest
# Mirrors FRR: bgp->rib[afi][safi] which is a radix tree of bgp_dest
Rib = Dict[Tuple[Afi, Safi], Dict[prefix_t, RibDest]]


def bgp_set_llgr_stale(
    rib: Rib,
    afi_safi: Tuple[Afi, Safi],
    peer_id: PeerId,
) -> int:
    """Model bgp_set_llgr_stale(): tag peer's routes with LLGR_STALE community.

    Mirrors FRR bgp_fsm.c L791-806:
      Iterates ALL routes from peer in the given AFI/SAFI (not just stale).
      Skips routes with NO_LLGR community or already tagged LLGR_STALE.
      Sets LLGR_STALE community on the rest.

    Returns the number of newly-tagged paths.
    """
    table = rib.get(afi_safi, {})
    count = 0
    for prefix, dest in table.items():
        for path in dest.paths:
            if path.peer_id != peer_id:
                continue
            if path.has_no_llgr_community:
                continue
            if path.has_llgr_stale_community:
                continue
            path.has_llgr_stale_community = True
            count += 1
    return count


def bgp_clear_route_node(
    rib: Rib,
    afi_safi: Tuple[Afi, Safi],
    peer_id: PeerId,
    nsf_wait: bool,
    nsf: bool,
    bgp_process_triggered: bool,
) -> bool:
    """Model bgp_clear_route_node(): per-path stale-or-remove decision.

    Mirrors FRR bgp_route.c L7216-7278 (work_queue callback):
      For each path from peer in the given AFI/SAFI:
        If nsf_wait AND nsf[afi][safi]:
          → set BGP_PATH_STALE (preserve for GR, no bgp_process)
        Else:
          → bgp_rib_remove (mark REMOVED + trigger bgp_process)

    Note: ENHANCED_REFRESH and BGP_PATH_UNUSEABLE conditions are out of
    scope for GR modeling and are omitted.

    Returns the updated bgp_process_triggered flag.
    """
    table = rib.get(afi_safi, {})

    for prefix, dest in table.items():
        for path in dest.paths:
            if path.peer_id != peer_id:
                continue
            if nsf_wait and nsf:
                # GR mode: mark STALE, preserve for helper to re-send
                path.stale = True
            else:
                # Non-GR mode: mark REMOVED + trigger bgp_process
                # Skip if already REMOVED: bgp_process_internal returns
                # early when dest has BGP_NODE_PROCESS_SCHEDULED.
                if path.removed:
                    continue
                path.removed = True
                bgp_process_triggered = True

    return bgp_process_triggered


def bgp_clear_stale_route(
    rib: Rib,
    afi_safi: Tuple[Afi, Safi],
    peer_id: PeerId,
    bgp_process_triggered: bool,
    llgr_wait: bool = False,
) -> bool:
    """Model bgp_clear_stale_route(): mark stale paths as removed.

    Mirrors FRR bgp_route.c L8046-8077:
      For each path from peer:
        ① LLGR skip: if llgr_wait AND path has community (not NO_LLGR)
           → preserve (continue)
        ② if not stale → skip
        ③ else → bgp_rib_remove (mark removed + trigger bgp_process)

    The LLGR skip condition (bgp_route.c L8052-8058):
      CHECK_FLAG(peer->af_sflags[afi][safi], PEER_STATUS_LLGR_WAIT)
      && bgp_attr_get_community(pi->attr)
      && !community_include(..., COMMUNITY_NO_LLGR)

    After bgp_set_llgr_stale() has run, paths have either LLGR_STALE
    (preserved) or NO_LLGR (deleted).  When llgr_wait=False the
    condition is never triggered and all stale paths are removed.

    Returns the updated bgp_process_triggered flag.
    """
    table = rib.get(afi_safi, {})

    for prefix, dest in table.items():
        for path in dest.paths:
            if path.peer_id != peer_id:
                continue
            # ① LLGR skip: preserve paths with LLGR_STALE community
            #    (has community && not NO_LLGR) when LLGR_WAIT is active.
            if (llgr_wait
                    and path.has_llgr_stale_community
                    and not path.has_no_llgr_community):
                continue
            # ② Only stale paths are candidates for removal
            if not path.stale:
                continue
            # Skip if already REMOVED: bgp_process_internal returns
            # early when dest has BGP_NODE_PROCESS_SCHEDULED.
            if path.removed:
                continue
            # ③ bgp_path_info_mark_for_delete + bgp_rib_remove
            path.removed = True
            bgp_process_triggered = True

    return bgp_process_triggered


def deep_copy_rib(rib: Rib) -> Rib:
    """Deep copy RIB to avoid mutating input."""
    result: Rib = {}
    for afi_safi, table in rib.items():
        result[afi_safi] = {}
        for prefix, dest in table.items():
            result[afi_safi][prefix] = RibDest(
                prefix=dest.prefix,
                paths=[
                    PathInfo(
                        peer_id=p.peer_id,
                        stale=p.stale,
                        removed=p.removed,
                        has_llgr_stale_community=p.has_llgr_stale_community,
                        has_no_llgr_community=p.has_no_llgr_community,
                    )
                    for p in dest.paths
                ],
            )
    return result
