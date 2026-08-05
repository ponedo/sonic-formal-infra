"""CrossHair targets for BGP Graceful Restart models.

Usage:
    crosshair cover crosshair_target.stale_timer_action_target --per_condition_timeout=10
    crosshair cover crosshair_target.update_receive_target --per_condition_timeout=30
    crosshair cover crosshair_target.update_receive_during_stale_target --per_condition_timeout=30
"""
from typing import List, Tuple

from crosshair_utils import (
    DISCONNECTED_PEERS,
    NSF_AFI_SAFI,
    PEERS,
    AfSlotFlagSeed,
    AfSlotIntFlagSeed,
    NlriSeed,
    RibSeed,
    build_af_int_dict,
    build_flag_dict,
    build_nlri,
    build_rib_with_disconnected_peer,
    resolve_disconnected_peer,
)
from lib import Afi, Safi

from stale_timer_action import (
    StaleTimerInput,
    stale_timer_action,
)
from update_receive_model import (
    UpdateReceiveInput,
    _derive_eor_afi_safi,
    update_receive,
)
from update_receive_during_stale import (
    UpdateReceiveDuringStaleInput,
    update_receive_during_stale,
)


# ── Precondition checks ──────────────────────────────────────────────


def stale_timer_action_input_flag_precondition_check(
    nsf_flags: AfSlotFlagSeed,
    llgr_stale_times: AfSlotIntFlagSeed,
    llgr_scheduled: AfSlotFlagSeed,
    restart_scheduled: bool,
) -> bool:
    """Reject invalid flag combinations for stale_timer_action (FRR constraints).

    Constraints:
      (0) at least one AF has NSF (stale timer fires only with NSF)
      (1) llgr_scheduled[i] implies nsf_flags[i] and llgr_stale_times[i] > 0
          (t_llgr_stale is armed only for NSF AFs with LLGR negotiated,
           bgp_fsm.c bgp_graceful_restart_timer_expire L840-874)
      (2) any(llgr_scheduled) implies not restart_scheduled
          (t_llgr_stale is armed only after t_gr_restart has fired, so the
           two timers can never be scheduled at the same time)
    """
    if not any(nsf_flags):
        return False
    for i in range(len(NSF_AFI_SAFI)):
        if llgr_scheduled[i] and not (nsf_flags[i] and llgr_stale_times[i] > 0):
            return False
    if any(llgr_scheduled) and restart_scheduled:
        return False
    return True


def update_receive_input_flag_precondition_check(
    nsf_seed: AfSlotFlagSeed,
    eor_received_seed: AfSlotFlagSeed,
    gr_wait_eor_seed: AfSlotFlagSeed,
    llgr_wait_seed: AfSlotFlagSeed,
) -> bool:
    """Reject invalid af_sflags combinations (FRR lifecycle constraints).

    Constraints (bgpd af_sflags invariants):
      (1) gr_wait_eor AND eor_received are mutually exclusive
      (2) gr_wait_eor requires nsf
      (3) llgr_wait requires nsf
    """
    for i in range(len(NSF_AFI_SAFI)):
        nsf = nsf_seed[i]
        eor_recv = eor_received_seed[i]
        gr_wait = gr_wait_eor_seed[i]
        llgr = llgr_wait_seed[i]
        # (1) mutually exclusive
        if gr_wait and eor_recv:
            return False
        # (2) gr_wait_eor requires nsf
        if gr_wait and not nsf:
            return False
        # (3) llgr_wait requires nsf
        if llgr and not nsf:
            return False
    return True


def scenario_precondition_check(
    nsf_seed: AfSlotFlagSeed,
    eor_received_seed: AfSlotFlagSeed,
    gr_wait_eor_seed: AfSlotFlagSeed,
    llgr_wait_seed: AfSlotFlagSeed,
    num_updates: int,
    timer_fire_index: int,
    eor_afi_safi_1: List[Tuple[Afi, Safi]],
    eor_afi_safi_2: List[Tuple[Afi, Safi]],
) -> bool:
    """Full precondition check for update_receive_during_stale target.

    Checks:
      (0) at least one AF has NSF (GR scenario requires NSF)
      (1) flag constraints (via update_receive_input_flag_precondition_check)
      (2) num_updates in [0, 2]
      (3) timer_fire_index in [0, num_updates]
      (4) EOR at most one AFI/SAFI per UPDATE, must be NSF-modeled
      (5) EOR uniqueness: cannot send EOR for already-received AFI/SAFI
      (6) EOR uniqueness: UPDATE 2 cannot repeat UPDATE 1's EOR AFI/SAFI
    """
    # (0) at least one AF has NSF
    if not any(nsf_seed):
        return False

    # (1) flag constraints
    if not update_receive_input_flag_precondition_check(
        nsf_seed, eor_received_seed, gr_wait_eor_seed, llgr_wait_seed
    ):
        return False

    # (2) num_updates must be exactly 0, 1, or 2
    if num_updates not in (0, 1, 2):
        return False

    # (3) timer_fire_index in valid range [0, num_updates]
    if timer_fire_index not in range(num_updates + 1):
        return False

    # (4) EOR at most one AFI/SAFI per UPDATE, must be NSF-modeled
    if len(eor_afi_safi_1) > 1 or len(eor_afi_safi_2) > 1:
        return False
    if eor_afi_safi_1 and eor_afi_safi_1[0] not in NSF_AFI_SAFI:
        return False
    if eor_afi_safi_2 and eor_afi_safi_2[0] not in NSF_AFI_SAFI:
        return False

    # (5)(6) EOR uniqueness
    eor_1 = eor_afi_safi_1[0] if eor_afi_safi_1 else None
    eor_2 = eor_afi_safi_2[0] if eor_afi_safi_2 else None
    if eor_1 is not None:
        idx_1 = NSF_AFI_SAFI.index(eor_1)
        if eor_received_seed[idx_1]:
            return False  # EOR already received before scenario
    if eor_2 is not None:
        idx_2 = NSF_AFI_SAFI.index(eor_2)
        if eor_received_seed[idx_2]:
            return False  # EOR already received before scenario
        if num_updates >= 2 and eor_1 == eor_2:
            return False  # UPDATE 1 already sent EOR for this AFI/SAFI

    return True


# ── CrossHair targets ────────────────────────────────────────────────


def stale_timer_action_target(
    nsf_flags: AfSlotFlagSeed,
    llgr_stale_times: AfSlotIntFlagSeed,
    llgr_scheduled: AfSlotFlagSeed,
    restart_scheduled: bool,
    rib_seed: RibSeed,
) -> int:
    """
    CrossHair target: symbolic inputs for stale_timer_action.

    pre: stale_timer_action_input_flag_precondition_check holds
    pre: all llgr_stale_times in [0, 3600]
    post: __return__ == 0
    """
    # Flag precondition (pure rejection)
    if not stale_timer_action_input_flag_precondition_check(
        nsf_flags, llgr_stale_times, llgr_scheduled, restart_scheduled
    ):
        return 0

    nsf = build_flag_dict(nsf_flags)
    llgr_stale_time = build_af_int_dict(llgr_stale_times)
    t_llgr_sched = build_flag_dict(llgr_scheduled)
    rib = build_rib_with_disconnected_peer(rib_seed, nsf, PEERS, DISCONNECTED_PEERS)

    peer_id = DISCONNECTED_PEERS[0]

    inp = StaleTimerInput(
        peer_id=peer_id,
        nsf=nsf,
        llgr_stale_time=llgr_stale_time,
        t_llgr_stale_scheduled=t_llgr_sched,
        t_gr_restart_scheduled=restart_scheduled,
        rib=rib,
    )
    output = stale_timer_action(inp)
    return 0


def update_receive_target(
    nsf_seed: AfSlotFlagSeed,
    eor_received_seed: AfSlotFlagSeed,
    gr_wait_eor_seed: AfSlotFlagSeed,
    llgr_wait_seed: AfSlotFlagSeed,
    rib_seed: RibSeed,
    nlri_seed: NlriSeed,
    eor_afi_safi: List[Tuple[Afi, Safi]],
    with_rib: bool,
    disconnected_peer_idx: int,
) -> int:
    """
    CrossHair target: symbolic inputs for update_receive.

    nsf_seed: per-AFI/SAFI NSF mode flags.
    eor_received_seed: per-AFI/SAFI EOR-received flags.
    gr_wait_eor_seed: per-AFI/SAFI GR-wait-EOR flags.
    llgr_wait_seed: per-AFI/SAFI LLGR-wait flags.
    disconnected_peer_idx: which peer is restarting (= from_peer).
    eor_afi_safi: non-empty → EOR-only UPDATE for the listed AFI/SAFI
                  (length 0 or 1; empty → no EOR).
    with_rib: True  → NLRI derived from RIB disconnected-peer prefixes
                      (generates stale refresh test cases).
              False → NLRI from independent seed
                      (generates added dest test cases).
    pre: flag constraints satisfied; EOR/NLRI contract holds
    post: __return__ == 0
    """
    # Flag precondition (pure rejection)
    if not update_receive_input_flag_precondition_check(
        nsf_seed, eor_received_seed, gr_wait_eor_seed, llgr_wait_seed
    ):
        return 0

    disconnected_peer = resolve_disconnected_peer(disconnected_peer_idx, DISCONNECTED_PEERS)

    # EOR precondition: at most one AFI/SAFI, must be NSF-modeled.
    if len(eor_afi_safi) > 1:
        return 0
    if eor_afi_safi and eor_afi_safi[0] not in NSF_AFI_SAFI:
        return 0

    # Build per-AFI/SAFI dicts
    nsf = build_flag_dict(nsf_seed)
    eor_received = build_flag_dict(eor_received_seed)
    gr_wait_eor = build_flag_dict(gr_wait_eor_seed)
    llgr_wait = build_flag_dict(llgr_wait_seed)

    # Build RIB (legal state: stale requires nsf AND NOT eor_received)
    rib = build_rib_with_disconnected_peer(
        rib_seed, nsf, PEERS, DISCONNECTED_PEERS, eor_received
    )
    update = build_nlri(eor_afi_safi, with_rib, nlri_seed, rib_seed, PEERS, DISCONNECTED_PEERS)

    # Precondition: in non-EOR modes the UPDATE must not be EOR-parseable.
    if not eor_afi_safi and _derive_eor_afi_safi(update) is not None:
        return 0

    inp = UpdateReceiveInput(
        from_peer=disconnected_peer,
        nsf=nsf,
        update=update,
        eor_received_flags=eor_received,
        gr_wait_eor_flags=gr_wait_eor,
        llgr_wait_flags=llgr_wait,
        rib=rib,
    )
    output = update_receive(inp)
    return 0


def update_receive_during_stale_target(
    nsf_seed: AfSlotFlagSeed,
    llgr_stale_time_seed: AfSlotIntFlagSeed,
    eor_received_seed: AfSlotFlagSeed,
    gr_wait_eor_seed: AfSlotFlagSeed,
    llgr_wait_seed: AfSlotFlagSeed,
    rib_seed: RibSeed,
    # Number of UPDATEs (0, 1, or 2)
    num_updates: int,
    # UPDATE 1
    nlri_seed_1: NlriSeed,
    eor_afi_safi_1: List[Tuple[Afi, Safi]],
    with_rib_1: bool,
    # UPDATE 2
    nlri_seed_2: NlriSeed,
    eor_afi_safi_2: List[Tuple[Afi, Safi]],
    with_rib_2: bool,
    # Timer interleaving
    timer_fire_index: int,
) -> int:
    """
    CrossHair target: symbolic inputs for update_receive_during_stale.

    Models 0-2 UPDATE messages with configurable timer_fire_index.

    nsf_seed: per-AFI/SAFI NSF mode flags.
    llgr_stale_time_seed: per-AFI/SAFI LLGR stale time (0 = no LLGR).
    eor_received_seed: per-AFI/SAFI EOR-received flags at start.
    gr_wait_eor_seed: per-AFI/SAFI GR-wait-EOR flags at start.
    llgr_wait_seed: per-AFI/SAFI LLGR-wait flags at start.
    rib_seed: initial RIB with stale routes.
    num_updates: number of UPDATE messages (0, 1, or 2).
    nlri_seed_N: NLRI seed for UPDATE N.
    eor_afi_safi_N: EOR AFI/SAFI for UPDATE N (empty = no EOR).
    with_rib_N: True = NLRI from RIB prefixes, False = independent.
    timer_fire_index: when t_gr_stale fires (0 to num_updates).

    pre: scenario_precondition_check holds
    post: __return__ == 0
    """
    # Precondition check (pure rejection)
    if not scenario_precondition_check(
        nsf_seed, eor_received_seed, gr_wait_eor_seed, llgr_wait_seed,
        num_updates, timer_fire_index,
        eor_afi_safi_1, eor_afi_safi_2,
    ):
        return 0

    # Build per-AFI/SAFI dicts
    nsf = build_flag_dict(nsf_seed)
    llgr_stale_time = build_af_int_dict(llgr_stale_time_seed)
    eor_received = build_flag_dict(eor_received_seed)
    gr_wait_eor = build_flag_dict(gr_wait_eor_seed)
    llgr_wait = build_flag_dict(llgr_wait_seed)

    # Build initial RIB
    rib = build_rib_with_disconnected_peer(
        rib_seed, nsf, PEERS, DISCONNECTED_PEERS, eor_received
    )

    # Build UPDATE messages based on num_updates
    updates = []
    if num_updates >= 1:
        updates.append(build_nlri(
            eor_afi_safi_1, with_rib_1, nlri_seed_1, rib_seed, PEERS, DISCONNECTED_PEERS
        ))
    if num_updates >= 2:
        updates.append(build_nlri(
            eor_afi_safi_2, with_rib_2, nlri_seed_2, rib_seed, PEERS, DISCONNECTED_PEERS
        ))

    peer_id = DISCONNECTED_PEERS[0]

    inp = UpdateReceiveDuringStaleInput(
        peer_id=peer_id,
        initial_rib=rib,
        updates=updates,
        timer_fire_index=timer_fire_index,
        nsf=nsf,
        llgr_stale_time=llgr_stale_time,
        eor_received_flags=eor_received,
        gr_wait_eor_flags=gr_wait_eor,
        llgr_wait_flags=llgr_wait,
    )
    output = update_receive_during_stale(inp)
    return 0
