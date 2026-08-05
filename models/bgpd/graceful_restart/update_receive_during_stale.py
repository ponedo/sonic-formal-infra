"""Scenario model: update_receive during stale timer period.

Models the Helper-side GR route synchronization scenario where:
  1. Peer restarts, stale routes remain in RIB
  2. Peer reconnects and sends UPDATE messages (possibly including EOR)
  3. t_gr_stale timer may fire at any point during UPDATE processing

The scenario driver interleaves update_receive and stale_timer_action
according to timer_fire_index, verifying the confluence property:
final RIB state is independent of timer firing time.

Confluence Property:
  Given fixed initial RIB and fixed UPDATE set, all valid interleavings
  produce identical final RIB state determined by:
    - announced_prefixes: union of all NLRI in UPDATEs
    - initial_stale_prefixes: prefixes with stale paths in initial RIB

  Final state:
    - announced_prefixes → stale=False, removed=False (valid paths)
    - initial_stale_prefixes - announced_prefixes → removed=True (cleared)
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from bgp_utils import PeerId, Rib, deep_copy_rib
from lib import Afi, Safi
from update_receive_model import (
    BgpUpdateNlri,
    UpdateReceiveInput,
    update_receive,
)
from stale_timer_action import (
    StaleTimerInput,
    stale_timer_action,
)


@dataclass
class UpdateReceiveDuringStaleInput:
    """Input for update_receive_during_stale scenario.

    Models UPDATE reception during the stale timer period from the
    Helper's perspective.

    peer_id: the restarting peer (Restarter)
    initial_rib: RIB snapshot at GR start (contains stale routes)
    updates: list of UPDATE messages received from Restarter
    timer_fire_index: when t_gr_stale fires (0 = before all UPDATEs,
                      len(updates) = after all UPDATEs)

    Per-AFI/SAFI flags (constant throughout scenario):
      nsf: peer->nsf[afi][safi] (GR capability)
      llgr_stale_time: peer->llgr[afi][safi].stale_time (0 = no LLGR)

    Initial flag state:
      eor_received_flags: per-AFI/SAFI EOR_RECEIVED at scenario start
      gr_wait_eor_flags: per-AFI/SAFI GR_WAIT_EOR at scenario start
      llgr_wait_flags: per-AFI/SAFI LLGR_WAIT at scenario start
    """
    peer_id: PeerId
    initial_rib: Rib
    updates: List[BgpUpdateNlri]
    timer_fire_index: int

    # Per-AFI/SAFI configuration (constant)
    nsf: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    llgr_stale_time: Dict[Tuple[Afi, Safi], int] = field(default_factory=dict)

    # Initial flag state
    eor_received_flags: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    gr_wait_eor_flags: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)
    llgr_wait_flags: Dict[Tuple[Afi, Safi], bool] = field(default_factory=dict)


@dataclass
class UpdateReceiveDuringStaleOutput:
    """Output from update_receive_during_stale scenario.

    rib_after: final RIB state after all events processed
    bgp_process_triggered: whether any bgp_process() was enqueued
    eor_received_flags: final per-AFI/SAFI EOR_RECEIVED state
    gr_wait_eor_flags: final per-AFI/SAFI GR_WAIT_EOR state
    timer_fired: whether stale_timer_action was invoked
    """
    rib_after: Rib
    bgp_process_triggered: bool
    eor_received_flags: Dict[Tuple[Afi, Safi], bool]
    gr_wait_eor_flags: Dict[Tuple[Afi, Safi], bool]
    timer_fired: bool


def update_receive_during_stale(
    inp: UpdateReceiveDuringStaleInput,
) -> UpdateReceiveDuringStaleOutput:
    """Run scenario: interleave UPDATEs and stale timer expiration.

    Execution flow:
      for i, update in enumerate(updates):
          if i == timer_fire_index:
              run stale_timer_action
          run update_receive(update)
      if timer_fire_index == len(updates):
          run stale_timer_action

    State threaded through:
      - rib: updated by each action
      - eor_received_flags: updated by update_receive
      - gr_wait_eor_flags: updated by update_receive
      - bgp_process_triggered: OR-accumulated
    """
    rib = deep_copy_rib(inp.initial_rib)
    eor_received_flags = dict(inp.eor_received_flags)
    gr_wait_eor_flags = dict(inp.gr_wait_eor_flags)
    llgr_wait_flags = dict(inp.llgr_wait_flags)
    bgp_process_triggered = False
    timer_fired = False

    # LLGR timer state: for Phase 2, assume no LLGR timer running
    # (t_llgr_stale is armed by restart_timer_action, not in this scenario)
    t_llgr_stale_scheduled: Dict[Tuple[Afi, Safi], bool] = {}

    def run_timer() -> None:
        nonlocal rib, bgp_process_triggered, timer_fired
        timer_input = StaleTimerInput(
            peer_id=inp.peer_id,
            nsf=inp.nsf,
            llgr_stale_time=inp.llgr_stale_time,
            t_llgr_stale_scheduled=t_llgr_stale_scheduled,
            t_gr_restart_scheduled=False,  # restart timer not pending
            rib=rib,
        )
        timer_output = stale_timer_action(timer_input)
        rib = timer_output.rib_after
        bgp_process_triggered = bgp_process_triggered or timer_output.bgp_process_triggered
        timer_fired = True

    def run_update(update: BgpUpdateNlri) -> None:
        nonlocal rib, eor_received_flags, gr_wait_eor_flags, bgp_process_triggered
        update_input = UpdateReceiveInput(
            from_peer=inp.peer_id,
            nsf=inp.nsf,
            update=update,
            eor_received_flags=eor_received_flags,
            gr_wait_eor_flags=gr_wait_eor_flags,
            llgr_wait_flags=llgr_wait_flags,
            rib=rib,
        )
        update_output = update_receive(update_input)
        rib = update_output.rib_after
        eor_received_flags = update_output.eor_received_flags
        gr_wait_eor_flags = update_output.gr_wait_eor_flags
        bgp_process_triggered = bgp_process_triggered or update_output.bgp_process_triggered

    # Interleave UPDATEs and timer
    for i, update in enumerate(inp.updates):
        if i == inp.timer_fire_index:
            run_timer()
        run_update(update)

    # Timer fires after all UPDATEs
    if inp.timer_fire_index == len(inp.updates):
        run_timer()

    return UpdateReceiveDuringStaleOutput(
        rib_after=rib,
        bgp_process_triggered=bgp_process_triggered,
        eor_received_flags=eor_received_flags,
        gr_wait_eor_flags=gr_wait_eor_flags,
        timer_fired=timer_fired,
    )
