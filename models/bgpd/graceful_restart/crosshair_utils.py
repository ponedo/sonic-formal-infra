"""Shared CrossHair RIB/NLRI seed types and builders.

Provides a common RIB and NLRI generation infrastructure used by multiple
crosshair_target modules (packet_action_model, timer_action_model).

Seed design: 2D fixed-slot + variable-entry
  - 4 fixed slots (one per NSF AFI/SAFI)
  - Each slot has a variable-length list of (peer_idx, prefix, llgr_stale, no_llgr)
  - peer_idx maps into PEERS via modular indexing
  - llgr_stale / no_llgr control LLGR community attributes on the path
"""
from typing import Dict, List, Tuple

from bgp_utils import PathInfo, PeerId, Rib, RibDest
from lib import Afi, Safi, prefix_t
from update_receive_model import BgpUpdateNlri


# ── AFI/SAFI universe (FOREACH_AFI_SAFI_NSF) ────────────────────────

NSF_AFI_SAFI: List[Tuple[Afi, Safi]] = [
    (Afi.IP, Safi.UNICAST),
    (Afi.IP, Safi.MULTICAST),
    (Afi.IPv6, Safi.UNICAST),
    (Afi.IPv6, Safi.MULTICAST),
]


# ── Peer topology defaults (exported for targets to pass explicitly) ──

PEERS: List[PeerId] = [1, 2]
"""All peers with active BGP sessions. RIB path_info peer_ids are drawn
from this set via index mapping."""

DISCONNECTED_PEERS: List[PeerId] = [1]
"""Subset of PEERS that have disconnected (restarting)."""


# ── Per-AFI/SAFI flag seed primitives ─────────────────────────────

AfSlotFlagSeed = Tuple[bool, bool, bool, bool]
"""One boolean flag dimension across the 4 NSF AFI/SAFI slots.
Slot order matches NSF_AFI_SAFI.  Each model's crosshair_target declares
as many AfSlotFlagSeed parameters as it has boolean flag dimensions,
then applies its own precondition check for mutual-exclusion constraints."""

AfSlotIntFlagSeed = Tuple[int, int, int, int]
"""One integer flag dimension across the 4 NSF AFI/SAFI slots.
Slot order matches NSF_AFI_SAFI.  Used for per-AF numeric configs
(e.g., llgr_stale_time)."""


def build_flag_dict(seed: AfSlotFlagSeed) -> Dict[Tuple[Afi, Safi], bool]:
    """Map a fixed-length boolean seed to per-AFI/SAFI dict."""
    return {NSF_AFI_SAFI[i]: seed[i] for i in range(len(NSF_AFI_SAFI))}


def build_af_int_dict(seed: AfSlotIntFlagSeed) -> Dict[Tuple[Afi, Safi], int]:
    """Map a fixed-length int seed to per-AFI/SAFI dict."""
    return {NSF_AFI_SAFI[i]: seed[i] for i in range(len(NSF_AFI_SAFI))}


# ── Seed types (2D: fixed AFI/SAFI slots × variable entries) ──────

RibEntrySeed = Tuple[int, int, bool, bool, bool]
"""One RIB entry: (peer_idx, prefix, has_llgr_stale, has_no_llgr, is_removed).
- peer_idx: maps to PEERS[peer_idx % len(PEERS)]
- has_llgr_stale: path carries COMMUNITY_LLGR_STALE
- has_no_llgr: path carries COMMUNITY_NO_LLGR
- is_removed: BGP_PATH_REMOVED flag (set by bgp_clear_route at disconnect)
AFI/SAFI is determined by the slot index, not stored in the entry.
Dedup: if same (prefix, peer_id) appears again in the slot, the later entry
replaces the earlier one (FRR: one path_info per peer per dest).
"""

RibSeed = Tuple[
    List[RibEntrySeed],   # slot 0: AFI/SAFI 0 entries
    List[RibEntrySeed],   # slot 1: AFI/SAFI 1 entries
    List[RibEntrySeed],   # slot 2: AFI/SAFI 2 entries
    List[RibEntrySeed],   # slot 3: AFI/SAFI 3 entries
]
"""RIB seed: 4 fixed slots (one per NSF AFI/SAFI), each with a
variable-length list of (peer_idx, prefix) entries."""



# ── Helper builders ──────────────────────────────────────────────────

def resolve_peer(idx: int, peer_ids: List[PeerId]) -> PeerId:
    """Map a symbolic index to a peer in peer_ids (for RIB paths)."""
    return peer_ids[idx % len(peer_ids)]


def resolve_disconnected_peer(idx: int, disconnected_peer_ids: List[PeerId]) -> PeerId:
    """Map a symbolic index to a peer in disconnected_peer_ids."""
    return disconnected_peer_ids[idx % len(disconnected_peer_ids)]


def upsert_path(
    table: Dict[prefix_t, RibDest],
    pfx: prefix_t,
    pid: PeerId,
    stale: bool,
    removed: bool = False,
    has_llgr_stale: bool = False,
    has_no_llgr: bool = False,
) -> None:
    """Insert or update a PathInfo in a RibDest table with dedup."""
    if pfx in table:
        for path in table[pfx].paths:
            if path.peer_id == pid:
                path.stale = stale
                path.removed = removed
                path.has_llgr_stale_community = has_llgr_stale
                path.has_no_llgr_community = has_no_llgr
                return
        table[pfx].paths.append(PathInfo(
            peer_id=pid, stale=stale, removed=removed,
            has_llgr_stale_community=has_llgr_stale,
            has_no_llgr_community=has_no_llgr,
        ))
    else:
        table[pfx] = RibDest(
            prefix=pfx,
            paths=[PathInfo(
                peer_id=pid, stale=stale, removed=removed,
                has_llgr_stale_community=has_llgr_stale,
                has_no_llgr_community=has_no_llgr,
            )],
        )


def build_rib_with_disconnected_peer(
    seed: RibSeed,
    nsf: Dict[Tuple[Afi, Safi], bool],
    peer_ids: List[PeerId],
    disconnected_peer_ids: List[PeerId],
    eor_received: Dict[Tuple[Afi, Safi], bool] = None,
) -> Rib:
    """Construct a legal Rib consistent with FRR state invariants.

    Args:
        seed: per-AFI/SAFI RIB entry seeds.
        nsf: per-AFI/SAFI NSF flags.
        peer_ids: all peers in the topology.
        disconnected_peer_ids: subset of peer_ids that have disconnected.
        eor_received: per-AFI/SAFI EOR-received flags (optional).

    Stale computation per path:
      stale = (peer in disconnected_peer_ids) AND nsf[afi_safi] AND NOT eor_received[afi_safi]

    Constraints enforced:
      - disconnected_peer_ids must be a subset of peer_ids
      - disconnected-peer routes require nsf (without NSF, routes are deleted
        at disconnect time, not retained — bgp_stop clears them immediately)
      - stale requires NOT eor_received (EOR receipt clears all stale immediately)
    """
    peer_set = frozenset(peer_ids)
    disconnected_set = frozenset(disconnected_peer_ids)
    assert disconnected_set <= peer_set, (
        f"disconnected_peer_ids {disconnected_peer_ids} must be subset of peer_ids {peer_ids}"
    )

    if eor_received is None:
        eor_received = {}
    rib: Rib = {}
    for i, entries in enumerate(seed):
        if not entries:
            continue
        afi_safi = NSF_AFI_SAFI[i]
        is_nsf = nsf.get(afi_safi, False)
        has_eor = eor_received.get(afi_safi, False)
        table: Dict[prefix_t, RibDest] = {}
        for peer_idx, prefix_val, has_llgr, has_no_llgr, is_removed in entries:
            pfx = prefix_t(prefix_val)
            pid = resolve_peer(peer_idx, peer_ids)
            # FRR invariant: disconnected peer's routes are deleted at
            # disconnect time for AFs without NSF; they never exist in RIB.
            if pid in disconnected_set and not is_nsf:
                continue
            stale = (pid in disconnected_set) and not has_eor
            # bgp_clear_route sets REMOVED on all disconnected-peer paths;
            # only meaningful for disconnected peers in NSF AFs.
            removed = is_removed and (pid in disconnected_set)
            upsert_path(table, pfx, pid, stale, removed, has_llgr, has_no_llgr)
        rib[afi_safi] = table
    return rib


# ── NLRI seed types ────────────────────────────────────────────────

NlriSeed = Tuple[
    List[int],   # slot 0: independent prefix values
    List[int],   # slot 1
    List[int],   # slot 2
    List[int],   # slot 3
]
"""NLRI seed: 4 fixed slots, each with independent prefix values.
Used when with_rib=False (added dest test cases)."""


# ── NLRI builders ────────────────────────────────────────────────────

def pick_single_mp_reach(
    mp_reach: Dict[Tuple[Afi, Safi], List[prefix_t]],
) -> Dict[Tuple[Afi, Safi], List[prefix_t]]:
    """Keep at most one MP_REACH_NLRI family.

    FRR rejects UPDATEs carrying more than one MP_REACH_NLRI attribute
    (duplicate BGP attribute type 14).  IPv4 Unicast NLRI is carried in
    the UPDATE body, not in MP_REACH_NLRI, so it remains independent.
    """
    for afi_safi in NSF_AFI_SAFI:
        if afi_safi == (Afi.IP, Safi.UNICAST):
            continue
        if afi_safi in mp_reach and mp_reach[afi_safi]:
            return {afi_safi: mp_reach[afi_safi]}
    return {}


def build_nlri_normal(
    eor_afi_safi: List[Tuple[Afi, Safi]],
    seed: NlriSeed,
) -> BgpUpdateNlri:
    """Construct NLRI from independent prefix values in seed.

    Used when with_rib=False — generates added dest test cases.
    Slot 0 (IPv4 Unicast) goes to ipv4_nlri; other slots go to mp_reach.
    At most one MP_REACH_NLRI family is kept to match FRR's constraint.
    """
    ipv4_nlri: List[prefix_t] = []
    mp_reach: Dict[Tuple[Afi, Safi], List[prefix_t]] = {}
    for i, prefix_vals in enumerate(seed):
        if not prefix_vals:
            continue
        pfx_list = [prefix_t(v) for v in prefix_vals]
        if NSF_AFI_SAFI[i] == (Afi.IP, Safi.UNICAST):
            ipv4_nlri = pfx_list
        else:
            mp_reach[NSF_AFI_SAFI[i]] = pfx_list
    return BgpUpdateNlri(ipv4_nlri=ipv4_nlri, mp_reach=pick_single_mp_reach(mp_reach))


def build_nlri_with_rib(
    eor_afi_safi: List[Tuple[Afi, Safi]],
    seed: RibSeed,
    peer_ids: List[PeerId],
    disconnected_peer_ids: List[PeerId],
) -> BgpUpdateNlri:
    """Construct NLRI from ALL disconnected peer prefixes in RIB.

    Used when with_rib=True. NLRI references disconnected peer prefixes,
    generating stale refresh test cases.
    Slot 0 (IPv4 Unicast) goes to ipv4_nlri; other slots go to mp_reach.
    At most one MP_REACH_NLRI family is kept to match FRR's constraint.
    """
    disconnected_set = frozenset(disconnected_peer_ids)
    ipv4_nlri: List[prefix_t] = []
    mp_reach: Dict[Tuple[Afi, Safi], List[prefix_t]] = {}
    for i, entries in enumerate(seed):
        prefixes = {
            prefix_t(prefix_val)
            for peer_idx, prefix_val, _, _, _ in entries
            if resolve_peer(peer_idx, peer_ids) in disconnected_set
        }
        if not prefixes:
            continue
        if NSF_AFI_SAFI[i] == (Afi.IP, Safi.UNICAST):
            ipv4_nlri = list(prefixes)
        else:
            mp_reach[NSF_AFI_SAFI[i]] = list(prefixes)
    return BgpUpdateNlri(ipv4_nlri=ipv4_nlri, mp_reach=pick_single_mp_reach(mp_reach))


def build_nlri_eor(
    eor_afi_safi: List[Tuple[Afi, Safi]],
) -> BgpUpdateNlri:
    """Construct an EOR UPDATE for the requested AFI/SAFI.

    Per FRR (bgp_packet.c L2573-2590):
      - IPv4 Unicast EOR: completely empty UPDATE.
      - MP EOR: empty MP_UNREACH_NLRI for the target family.
    """
    if not eor_afi_safi:
        return BgpUpdateNlri()

    target = eor_afi_safi[0]
    if target == (Afi.IP, Safi.UNICAST):
        return BgpUpdateNlri()

    return BgpUpdateNlri(mp_unreach=(target, []))


def build_nlri(
    eor_afi_safi: List[Tuple[Afi, Safi]],
    with_rib: bool,
    nlri_seed: NlriSeed,
    rib_seed: RibSeed,
    peer_ids: List[PeerId],
    disconnected_peer_ids: List[PeerId],
) -> BgpUpdateNlri:
    """Unified NLRI builder: dispatches to the appropriate build_nlri_* variant.

    - eor_afi_safi non-empty → build_nlri_eor
    - with_rib → build_nlri_with_rib (NLRI from RIB stale prefixes)
    - otherwise → build_nlri_normal (NLRI from independent seed)
    """
    if eor_afi_safi:
        return build_nlri_eor(eor_afi_safi)
    if with_rib:
        return build_nlri_with_rib(eor_afi_safi, rib_seed, peer_ids, disconnected_peer_ids)
    return build_nlri_normal(eor_afi_safi, nlri_seed)
