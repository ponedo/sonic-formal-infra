"""Format CrossHair coverage results into JSON test cases for BGP Graceful Restart models.

Usage:
    python format_tests.py

Output:
    tests/stale_timer_action_tests.json
    tests/update_receive_tests.json
    tests/update_receive_during_stale_tests.json
"""
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parents[0]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from crosshair_utils import (
    DISCONNECTED_PEERS,
    NSF_AFI_SAFI,
    PEERS,
    build_af_int_dict,
    build_flag_dict,
    build_nlri,
    build_rib_with_disconnected_peer,
    resolve_disconnected_peer,
)
from lib.serializers import (
    af_flag_dict_to_json,
    af_int_dict_to_json,
    afi_safi_list_to_json,
    normalize_afi_safi_list,
    rib_dict_to_json,
    rib_to_json,
    update_to_json,
)
from lib.testgen import TargetConfig, main as testgen_main
from crosshair_target import (
    stale_timer_action_input_flag_precondition_check,
    scenario_precondition_check,
    update_receive_input_flag_precondition_check,
)
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

OUTPUT_DIR = PROJECT_ROOT / "tests"

# Path fields for timer_action_model RIB serialization (includes LLGR community flags).
_TIMER_PATH_FIELDS = (
    "peer_id", "stale", "removed",
    "has_llgr_stale_community", "has_no_llgr_community",
)


# ── stale_timer_action ───────────────────────────────────────────────

def _build_stale_input(d: Dict[str, Any]) -> StaleTimerInput:
    nsf = build_flag_dict(d["nsf_flags"])
    return StaleTimerInput(
        peer_id=DISCONNECTED_PEERS[0],
        nsf=nsf,
        llgr_stale_time=build_af_int_dict(d["llgr_stale_times"]),
        t_llgr_stale_scheduled=build_flag_dict(d["llgr_scheduled"]),
        t_gr_restart_scheduled=d["restart_scheduled"],
        rib=build_rib_with_disconnected_peer(d["rib_seed"], nsf, PEERS, DISCONNECTED_PEERS),
    )


def _format_stale_output(
    inp: StaleTimerInput, arg_dict: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    output = stale_timer_action(inp)
    expected = asdict(output)
    expected["rib_after"] = rib_dict_to_json(expected["rib_after"], _TIMER_PATH_FIELDS)

    input_json = {
        "peer_id": inp.peer_id,
        "nsf": af_flag_dict_to_json(inp.nsf),
        "llgr_stale_time": af_int_dict_to_json(inp.llgr_stale_time),
        "t_llgr_stale_scheduled": af_flag_dict_to_json(inp.t_llgr_stale_scheduled),
        "t_gr_restart_scheduled": inp.t_gr_restart_scheduled,
        "rib": rib_dict_to_json(inp.rib, _TIMER_PATH_FIELDS),
    }
    return expected, input_json


def _stale_precondition(d: Dict[str, Any]) -> bool:
    """FRR-reachable state when t_gr_stale expires (bgp_fsm.c)."""
    return stale_timer_action_input_flag_precondition_check(
        d["nsf_flags"],
        d["llgr_stale_times"],
        d["llgr_scheduled"],
        d["restart_scheduled"],
    )


# ── update_receive ───────────────────────────────────────────────────

def _build_update_input(d: Dict[str, Any]) -> UpdateReceiveInput:
    disconnected_peer = resolve_disconnected_peer(d["disconnected_peer_idx"], DISCONNECTED_PEERS)
    eor_afi_safi = normalize_afi_safi_list(d["eor_afi_safi"])

    nsf = build_flag_dict(d["nsf_seed"])
    eor_received = build_flag_dict(d["eor_received_seed"])
    gr_wait_eor = build_flag_dict(d["gr_wait_eor_seed"])
    llgr_wait = build_flag_dict(d["llgr_wait_seed"])

    rib = build_rib_with_disconnected_peer(
        d["rib_seed"], nsf, PEERS, DISCONNECTED_PEERS, eor_received
    )
    update = build_nlri(eor_afi_safi, d["with_rib"], d["nlri_seed"], d["rib_seed"], PEERS, DISCONNECTED_PEERS)

    return UpdateReceiveInput(
        from_peer=disconnected_peer,
        nsf=nsf,
        update=update,
        eor_received_flags=eor_received,
        gr_wait_eor_flags=gr_wait_eor,
        llgr_wait_flags=llgr_wait,
        rib=rib,
    )


def _format_update_output(
    inp: UpdateReceiveInput, arg_dict: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    output = update_receive(inp)

    expected = {
        "eor_received_flags": af_flag_dict_to_json(output.eor_received_flags),
        "gr_wait_eor_flags": af_flag_dict_to_json(output.gr_wait_eor_flags),
        "bgp_process_triggered": output.bgp_process_triggered,
        "rib_after": rib_to_json(output.rib_after),
    }

    input_json = {
        "from_peer": inp.from_peer,
        "nsf": af_flag_dict_to_json(inp.nsf),
        "update": update_to_json(inp.update),
        "with_rib": arg_dict["with_rib"] and not arg_dict["eor_afi_safi"],
        "eor_afi_safi": afi_safi_list_to_json(normalize_afi_safi_list(arg_dict["eor_afi_safi"])),
        "eor_received_flags": af_flag_dict_to_json(inp.eor_received_flags),
        "gr_wait_eor_flags": af_flag_dict_to_json(inp.gr_wait_eor_flags),
        "llgr_wait_flags": af_flag_dict_to_json(inp.llgr_wait_flags),
        "rib": rib_to_json(inp.rib),
    }
    return expected, input_json


def _update_precondition(d: Dict[str, Any]) -> bool:
    """Skip inputs that do not satisfy the EOR/NLRI contract."""
    # Flag precondition (FRR lifecycle constraints)
    if not update_receive_input_flag_precondition_check(
        d["nsf_seed"], d["eor_received_seed"], d["gr_wait_eor_seed"], d["llgr_wait_seed"]
    ):
        return False

    eor_afi_safi = normalize_afi_safi_list(d["eor_afi_safi"])
    update = build_nlri(eor_afi_safi, d["with_rib"], d["nlri_seed"], d["rib_seed"], PEERS, DISCONNECTED_PEERS)

    # Non-EOR modes must not emit an EOR-parseable UPDATE.
    if not eor_afi_safi and _derive_eor_afi_safi(update) is not None:
        return False

    # A single UPDATE can be EOR for at most one AFI/SAFI,
    # and that AFI/SAFI must be one of the NSF-modeled families.
    if len(eor_afi_safi) > 1:
        return False
    if eor_afi_safi and eor_afi_safi[0] not in NSF_AFI_SAFI:
        return False

    return True


# ── update_receive_during_stale ──────────────────────────────────────

def _build_scenario_input(d: Dict[str, Any]) -> UpdateReceiveDuringStaleInput:
    nsf = build_flag_dict(d["nsf_seed"])
    llgr_stale_time = build_af_int_dict(d["llgr_stale_time_seed"])
    eor_received = build_flag_dict(d["eor_received_seed"])
    gr_wait_eor = build_flag_dict(d["gr_wait_eor_seed"])
    llgr_wait = build_flag_dict(d["llgr_wait_seed"])

    rib = build_rib_with_disconnected_peer(
        d["rib_seed"], nsf, PEERS, DISCONNECTED_PEERS, eor_received
    )

    num_updates = d["num_updates"]
    updates = []
    if num_updates >= 1:
        eor_afi_safi_1 = normalize_afi_safi_list(d["eor_afi_safi_1"])
        updates.append(build_nlri(
            eor_afi_safi_1, d["with_rib_1"], d["nlri_seed_1"], d["rib_seed"], PEERS, DISCONNECTED_PEERS
        ))
    if num_updates >= 2:
        eor_afi_safi_2 = normalize_afi_safi_list(d["eor_afi_safi_2"])
        updates.append(build_nlri(
            eor_afi_safi_2, d["with_rib_2"], d["nlri_seed_2"], d["rib_seed"], PEERS, DISCONNECTED_PEERS
        ))

    return UpdateReceiveDuringStaleInput(
        peer_id=DISCONNECTED_PEERS[0],
        initial_rib=rib,
        updates=updates,
        timer_fire_index=d["timer_fire_index"],
        nsf=nsf,
        llgr_stale_time=llgr_stale_time,
        eor_received_flags=eor_received,
        gr_wait_eor_flags=gr_wait_eor,
        llgr_wait_flags=llgr_wait,
    )


def _format_scenario_output(
    inp: UpdateReceiveDuringStaleInput, arg_dict: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    output = update_receive_during_stale(inp)

    expected = {
        "rib_after": rib_to_json(output.rib_after),
        "bgp_process_triggered": output.bgp_process_triggered,
        "eor_received_flags": af_flag_dict_to_json(output.eor_received_flags),
        "gr_wait_eor_flags": af_flag_dict_to_json(output.gr_wait_eor_flags),
        "timer_fired": output.timer_fired,
    }

    input_json = {
        "peer_id": inp.peer_id,
        "initial_rib": rib_to_json(inp.initial_rib),
        "updates": [update_to_json(u) for u in inp.updates],
        "timer_fire_index": inp.timer_fire_index,
        "nsf": af_flag_dict_to_json(inp.nsf),
        "llgr_stale_time": af_int_dict_to_json(inp.llgr_stale_time),
        "eor_received_flags": af_flag_dict_to_json(inp.eor_received_flags),
        "gr_wait_eor_flags": af_flag_dict_to_json(inp.gr_wait_eor_flags),
        "llgr_wait_flags": af_flag_dict_to_json(inp.llgr_wait_flags),
    }
    return expected, input_json


def _scenario_precondition(d: Dict[str, Any]) -> bool:
    """Delegate to scenario_precondition_check from crosshair_target."""
    return scenario_precondition_check(
        d["nsf_seed"],
        d["eor_received_seed"],
        d["gr_wait_eor_seed"],
        d["llgr_wait_seed"],
        d["num_updates"],
        d["timer_fire_index"],
        normalize_afi_safi_list(d["eor_afi_safi_1"]),
        normalize_afi_safi_list(d["eor_afi_safi_2"]),
    )


# ── Target registry ──────────────────────────────────────────────────

# NOTE: CrossHair `cover` emits one example per explored branch, INCLUDING
# the target's early-`return 0` precondition branches.  The target's
# `return 0` guards therefore do NOT filter invalid inputs — they only
# document the contract.  Real filtering happens here in the precondition
# functions.

TARGETS: List[TargetConfig] = [
    (
        "crosshair_target.stale_timer_action_target",
        _build_stale_input,
        _format_stale_output,
        _stale_precondition,
        60,
    ),
    (
        "crosshair_target.update_receive_target",
        _build_update_input,
        _format_update_output,
        _update_precondition,
        60,
    ),
    (
        "crosshair_target.update_receive_during_stale_target",
        _build_scenario_input,
        _format_scenario_output,
        _scenario_precondition,
        180,
    ),
]


if __name__ == "__main__":
    testgen_main(
        TARGETS, OUTPUT_DIR,
        description="Generate CrossHair test cases for BGP Graceful Restart models.",
    )
