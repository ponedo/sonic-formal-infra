"""BGP packet action model for update_receive.

Models the GR-relevant behavior of FRR's bgp_update_receive()
(bgp_packet.c L2339), triggered when a Helper receives UPDATE messages
from a Restarter after reconnection.

Call chain in FRR:
  bgp_update_receive()          — parse UPDATE packet, extract NLRI
    → bgp_nlri_parse()          — dispatch by AFI/SAFI
      → bgp_nlri_parse_ip()     — iterate over prefixes
        → bgp_update()          — per-prefix route install/update
    → bgp_update_receive_eor()  — EOR handling (if UPDATE is EOR)

FRR RIB structure (mirrors bgp->rib[afi][safi]):
  RIB[afi][safi] → radix tree of bgp_dest
    └── bgp_dest (per prefix)
         └── bgp_path_info list (per peer, each with own flags)
              └── BGP_PATH_STALE flag (per path)

GR-relevant behavior:

  ① Normal UPDATE (bgp_update, bgp_route.c):
     - If existing stale path → unset STALE flag
     - If no existing path → create new path
     - bgp_process() → enqueue for path selection

  ② EOR UPDATE (bgp_update_receive_eor, bgp_packet.c L2287):
     - SET_FLAG(PEER_STATUS_EOR_RECEIVED)
     - UNSET_FLAG(PEER_STATUS_GR_WAIT_EOR)
     - If nsf[afi][safi] → bgp_clear_stale_route() (delete stale routes)

This model does NOT model:
  - bgp_process_main_one() path selection details
  - zebra message generation (deferred to path selection)

Returns UpdateReceiveOutput containing RIB state after processing,
EOR side-effects, and bgp_process trigger status.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from bgp_utils import (
    PathInfo,
    PeerId,
    Rib,
    RibDest,
    bgp_clear_stale_route,
    deep_copy_rib,
)
from lib import Afi, Safi, prefix_t


@dataclass
class BgpUpdateNlri:
    """Parsed UPDATE message content relevant to GR processing.

    Mirrors FRR's parsing of an UPDATE message into separate buckets:
      - ipv4_nlri: IPv4 Unicast NLRI from the UPDATE body
      - ipv4_withdrawn: IPv4 Unicast withdrawn routes from the UPDATE body
      - mp_reach: MP_REACH_NLRI attribute contents keyed by AFI/SAFI
      - mp_unreach: MP_UNREACH_NLRI attribute (AFI/SAFI + withdrawn routes)

    EOR is not an explicit field; it is derived from this structure exactly as
    FRR does at bgp_packet.c L2573.
    """

    ipv4_nlri: List[prefix_t] = field(default_factory=list)
    ipv4_withdrawn: List[prefix_t] = field(default_factory=list)
    mp_reach: Dict[Tuple[Afi, Safi], List[prefix_t]] = field(
        default_factory=dict
    )
    mp_unreach: Optional[Tuple[Tuple[Afi, Safi], List[prefix_t]]] = None


def _derive_eor_afi_safi(
    update: BgpUpdateNlri,
) -> Optional[Tuple[Afi, Safi]]:
    """Derive the EOR AFI/SAFI from UPDATE structure.

    Matches FRR bgp_packet.c L2573-2590:
      - EOR requires no IPv4 NLRI, no IPv4 withdrawn routes, no MP_REACH_NLRI.
      - Empty UPDATE (no attributes) => IPv4 Unicast EOR.
      - Empty MP_UNREACH_NLRI => EOR for that MP family.
      - Non-empty MP_UNREACH_NLRI => normal withdrawal, not EOR.
    """
    if update.ipv4_nlri or update.ipv4_withdrawn or update.mp_reach:
        return None

    if update.mp_unreach is None:
        return (Afi.IP, Safi.UNICAST)

    afi_safi, withdrawn = update.mp_unreach
    if withdrawn:
        return None  # pragma: no cover (MP_UNREACH withdrawal, not GR-relevant)

    return afi_safi


@dataclass
class UpdateReceiveInput:
    """Input for update_receive.

    Models receiving one UPDATE message from the Restarter after reconnection.
    A single UPDATE may contain NLRI for multiple AFI/SAFIs, and/or signal EOR
    for one AFI/SAFI (per RFC 4724 an EOR UPDATE carries no NLRI).

    from_peer: UPDATE sender (the Restarter peer)
    nsf: peer->nsf[afi][safi] for each AFI/SAFI (GR capability flag)
    update: the parsed UPDATE message content
    eor_received_flags: per-AFI/SAFI PEER_STATUS_EOR_RECEIVED state
                        before this UPDATE (prior state)
    gr_wait_eor_flags: per-AFI/SAFI PEER_STATUS_GR_WAIT_EOR state
                       before this UPDATE (prior state)
    llgr_wait_flags: per-AFI/SAFI PEER_STATUS_LLGR_WAIT state (mirrors
               peer->af_sflags[afi][safi] & PEER_STATUS_LLGR_WAIT).
               When True, bgp_clear_stale_route preserves paths with
               LLGR_STALE community.
    rib: current RIB snapshot, organized by AFI/SAFI → prefix → dest
    """
    from_peer: PeerId
    nsf: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    update: BgpUpdateNlri = field(default_factory=BgpUpdateNlri)
    eor_received_flags: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    gr_wait_eor_flags: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    llgr_wait_flags: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    rib: Rib = field(default_factory=dict)


@dataclass
class UpdateReceiveOutput:
    """Observable side-effects produced by update_receive.

    All path-level changes (refreshed, added, marked-removed) are observable
    by inspecting rib_after path flags — no separate change lists needed.

    eor_received_flags: per-AFI/SAFI PEER_STATUS_EOR_RECEIVED state
                        after processing this UPDATE
    gr_wait_eor_flags: per-AFI/SAFI PEER_STATUS_GR_WAIT_EOR state
                       after processing this UPDATE
    bgp_process_triggered: whether bgp_process() was enqueued
    rib_after: full RIB snapshot after processing
    """
    eor_received_flags: Dict[Tuple[Afi, Safi], bool]
    gr_wait_eor_flags: Dict[Tuple[Afi, Safi], bool]
    bgp_process_triggered: bool
    rib_after: Rib


def update_receive(inp: UpdateReceiveInput) -> UpdateReceiveOutput:
    """Model FRR's bgp_update_receive() GR-relevant behavior.

    Two phases:
    ① Normal UPDATE processing: iterate over NLRI, refresh/add paths
    ② EOR processing: for each EOR AFI/SAFI, set flags and clear stale routes

    bgp_process() is triggered if any NLRI is present.
    """
    rib = deep_copy_rib(inp.rib)
    from_peer = inp.from_peer

    eor_received_flags = dict(inp.eor_received_flags)
    gr_wait_eor_flags = dict(inp.gr_wait_eor_flags)
    bgp_process_triggered = False

    # ① Normal UPDATE processing: iterate over each AFI/SAFI with NLRI
    nlri_by_afi_safi: Dict[Tuple[Afi, Safi], List[prefix_t]] = {
        **inp.update.mp_reach,
        (Afi.IP, Safi.UNICAST): list(inp.update.ipv4_nlri),
    }
    # Do not add an empty IPv4 Unicast entry if there is no IPv4 NLRI.
    if not inp.update.ipv4_nlri:
        nlri_by_afi_safi.pop((Afi.IP, Safi.UNICAST), None)

    for afi_safi, prefixes in nlri_by_afi_safi.items():
        # Get or initialize the table for this AFI/SAFI
        table = rib.setdefault(afi_safi, {})

        for prefix in prefixes:
            if prefix in table:
                # Existing dest found
                dest = table[prefix]
                # Find path from this peer (mirrors FRR: pi->peer == peer)
                peer_path = next(
                    (p for p in dest.paths if p.peer_id == from_peer), None
                )
                if peer_path is not None:
                    if peer_path.removed:
                        # FRR bgp_route.c L6275-6286: Withdraw/Announce before
                        # fully processed → bgp_path_info_restore()
                        # Unset REMOVED, set VALID (path is "revived")
                        peer_path.removed = False
                        peer_path.stale = False
                        bgp_process_triggered = True
                    elif peer_path.stale:
                        # Unset BGP_PATH_STALE (bgp_route.c L6312-6316)
                        peer_path.stale = False
                        bgp_process_triggered = True  # bgp_process at L6263
                    # If not stale/removed, path is already valid — no GR action
                else:
                    # No path from this peer → add new path to existing dest
                    new_path = PathInfo(peer_id=from_peer, stale=False)
                    dest.paths.append(new_path)
                    bgp_process_triggered = True  # bgp_process at L6642
            else:
                # No dest for this prefix → create new dest with new path
                new_path = PathInfo(peer_id=from_peer, stale=False)
                new_dest = RibDest(prefix=prefix, paths=[new_path])
                table[prefix] = new_dest
                bgp_process_triggered = True  # bgp_process at L6642

    # ② EOR processing: handle EOR signals (bgp_update_receive_eor)
    update_eor_afi_safi = _derive_eor_afi_safi(inp.update)

    if update_eor_afi_safi is not None:
        # FRR: only set EOR_RECEIVED if it was not already set
        if not inp.eor_received_flags.get(update_eor_afi_safi, False):
            eor_received_flags[update_eor_afi_safi] = True

            # FRR: only clear GR_WAIT_EOR when EOR_RECEIVED transitions
            if gr_wait_eor_flags.get(update_eor_afi_safi, False):
                gr_wait_eor_flags[update_eor_afi_safi] = False

            # If nsf[afi][safi], mark stale routes for removal
            if inp.nsf.get(update_eor_afi_safi, False):
                bgp_process_triggered = bgp_clear_stale_route(
                    rib, update_eor_afi_safi, from_peer, bgp_process_triggered,
                    llgr_wait=inp.llgr_wait_flags.get(update_eor_afi_safi, False),
                )  # bgp_rib_remove → bgp_process at L5420

    return UpdateReceiveOutput(
        eor_received_flags=eor_received_flags,
        gr_wait_eor_flags=gr_wait_eor_flags,
        bgp_process_triggered=bgp_process_triggered,
        rib_after=rib,
    )
