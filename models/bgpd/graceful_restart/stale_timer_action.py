"""BGP timer action model for stale_timer_action.

Models FRR's bgp_graceful_stale_timer_expire() (bgp_fsm.c L873-917),
triggered when t_gr_stale expires.

This is the "stalepath timer" from RFC 4724. It iterates over
FOREACH_AFI_SAFI_NSF and decides per-AF whether to clear stale routes
or skip (because LLGR retention is or will be active).

Per-AF skip logic (bgp_fsm.c L904-906):
  skip if:
    ① event_is_scheduled(peer->t_llgr_stale[afi][safi])
       — LLGR stale timer already running (restart timer already fired)
    ② peer->llgr[afi][safi].stale_time > 0
       AND event_is_scheduled(connection->t_gr_restart)
       — LLGR negotiated AND restart timer hasn't fired yet
       (when it fires, it will arm t_llgr_stale)

If neither condition holds → bgp_clear_stale_route(peer, afi, safi)

Note: this callback does NOT call bgp_graceful_restart_timer_off().
NSF_WAIT is not cleared here.

Returns StaleTimerOutput containing only the observable side-effects.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from bgp_utils import (
    PeerId,
    Rib,
    bgp_clear_stale_route,
    deep_copy_rib,
)
from lib import Afi, Safi


@dataclass
class StaleTimerInput:
    """Input for stale_timer_action.

    Inputs mirror the peer state at the time t_gr_stale expires.
    """
    # Peer whose stale routes are being cleared (mirror FRR struct peer *)
    peer_id: PeerId

    # Per-AFI/SAFI NSF state (mirror FRR peer->nsf[afi][safi])
    nsf: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)

    # Per-AFI/SAFI LLGR stale_time config (mirror peer->llgr[afi][safi].stale_time)
    # > 0 means LLGR is negotiated for this AFI/SAFI.
    llgr_stale_time: Dict[Tuple[Afi, Safi], int] = field(default_factory=dict)

    # Per-AFI/SAFI t_llgr_stale scheduled state
    # (mirror event_is_scheduled(peer->t_llgr_stale[afi][safi]))
    t_llgr_stale_scheduled: Dict[Tuple[Afi, Safi], bool] = field(
        default_factory=dict
    )

    # Global t_gr_restart scheduled state
    # (mirror event_is_scheduled(connection->t_gr_restart))
    t_gr_restart_scheduled: bool = False

    # Full RIB snapshot for this peer.
    rib: Rib = field(default_factory=dict)


@dataclass
class StaleTimerOutput:
    """Observable side-effects produced by stale_timer_action.

    All path-level changes are observable by inspecting rib_after path flags
    (stale and removed) — no separate change lists needed.

    bgp_process_triggered: whether bgp_process() was enqueued
    rib_after: full RIB snapshot after processing
    """
    bgp_process_triggered: bool
    rib_after: Rib


# AFI/SAFI universe (FOREACH_AFI_SAFI_NSF)
NSF_AFI_SAFI: List[Tuple[Afi, Safi]] = [
    (Afi.IP, Safi.UNICAST),
    (Afi.IP, Safi.MULTICAST),
    (Afi.IPv6, Safi.UNICAST),
    (Afi.IPv6, Safi.MULTICAST),
]



def stale_timer_action(inp: StaleTimerInput) -> StaleTimerOutput:
    """Model FRR's bgp_graceful_stale_timer_expire().

    Per-AFI/SAFI logic (bgp_fsm.c L900-916):
      if !peer->nsf[afi][safi]: skip (not NSF for this AF)
      if t_llgr_stale[afi][safi] is scheduled: skip (LLGR window running)
      if llgr[afi][safi].stale_time > 0 AND t_gr_restart is scheduled:
          skip (LLGR will take over when restart timer fires)
      else:
          bgp_clear_stale_route() — mark stale paths as removed
    """
    rib = deep_copy_rib(inp.rib)
    bgp_process_triggered = False

    for afi_safi in NSF_AFI_SAFI:
        nsf = inp.nsf.get(afi_safi, False)

        if not nsf:
            continue

        # Skip condition ①: t_llgr_stale already scheduled
        llgr_timer_scheduled = inp.t_llgr_stale_scheduled.get(afi_safi, False)

        # Skip condition ②: LLGR negotiated AND restart timer pending
        llgr_negotiated = inp.llgr_stale_time.get(afi_safi, 0) > 0
        restart_pending = inp.t_gr_restart_scheduled

        if llgr_timer_scheduled or (llgr_negotiated and restart_pending):
            # LLGR is (or will be) handling this AF → skip clear
            continue

        # Clear stale routes for this AFI/SAFI
        bgp_process_triggered = bgp_clear_stale_route(
            rib, afi_safi, inp.peer_id, bgp_process_triggered
        )

    return StaleTimerOutput(
        bgp_process_triggered=bgp_process_triggered,
        rib_after=rib,
    )
