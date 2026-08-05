"""Shared enums and dataclasses for the layered BGP FSM models.

These definitions mirror FRR's bgpd.h enums and provide the common contract
between fsm_action_model, packet_action_model, timer_action_model, and scenario_model.
"""
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, NewType, Optional, Tuple

# Opaque integer identifiers for prefixes/addresses, matching the
# sonic-formal-infra convention. Concrete string representations are produced
# by mapper utilities for harnesses that drive real software.
prefix_t = NewType('prefix_t', int)
addr_t = NewType('addr_t', int)


class State(IntEnum):
    """enum bgp_fsm_status (bgpd.h)"""
    Idle = 1
    Connect = 2
    Active = 3
    OpenSent = 4
    OpenConfirm = 5
    Established = 6
    Clearing = 7
    Deleted = 8


class Event(IntEnum):
    """enum bgp_fsm_events (bgpd.h)"""
    BGP_Start = 1
    BGP_Stop = 2
    TCP_connection_open = 3
    TCP_connection_open_w_delay = 4
    TCP_connection_closed = 5
    TCP_connection_open_failed = 6
    TCP_fatal_error = 7
    ConnectRetry_timer_expired = 8
    Hold_Timer_expired = 9
    KeepAlive_timer_expired = 10
    DelayOpen_timer_expired = 11
    Receive_OPEN_message = 12
    Receive_KEEPALIVE_message = 13
    Receive_UPDATE_message = 14
    Receive_NOTIFICATION_message = 15
    Clearing_Completed = 16


class ActionResult(IntEnum):
    """Return codes from FRR action functions.

    Matches enum bgp_fsm_state_progress (bgp_fsm.h):
      BGP_FSM_FAILURE_AND_DELETE = -2
      BGP_FSM_FAILURE = -1
      BGP_FSM_SUCCESS = 0              (no state transfer)
      BGP_FSM_SUCCESS_STATE_TRANSFER = 1  (state transferred)
    """
    BGP_FSM_FAILURE_AND_DELETE = -2
    BGP_FSM_FAILURE = -1
    BGP_FSM_SUCCESS = 0
    BGP_FSM_SUCCESS_STATE_TRANSFER = 1


class Afi(IntEnum):
    """Address-family identifier (mirrors FRR afi_t)."""
    IP = 1
    IPv6 = 2
    L2VPN = 3
    MAX = 4


class Safi(IntEnum):
    """Subsequent address-family identifier (mirrors FRR safi_t)."""
    UNICAST = 1
    MULTICAST = 2
    MPLS_VPN = 3
    ENCAP = 4
    EVPN = 5
    MAX = 6


class ZebraRouteAction(IntEnum):
    """Zebra route install/withdraw actions."""
    ADD = 1
    DELETE = 2


@dataclass
class OpenMessage:
    """Structured OPEN message (used as both input and output)."""
    sent: bool = False
    gr_capability_present: bool = False
    r_bit: Optional[bool] = None       # Restart flag (Restarter)
    f_bit: Optional[bool] = None       # Forwarding preserved flag (per-AF, Restarter only)
    restart_time: Optional[int] = None # Restart time (seconds)
    n_bit: Optional[bool] = None       # Notification bit (RFC 8538)
    a_bit: Optional[bool] = None       # Address family bit
    # Per-AF F-bit encoding: maps (Afi, Safi) -> F-bit value.
    # Populated only when PEER_FLAG_GRACEFUL_RESTART (not helper-only).
    per_af_f_bits: Optional[Dict[Tuple[int, int], bool]] = None


@dataclass
class ZebraRouteMessage:
    """Structured zebra route message (BGP→Zebra route install/withdraw)."""
    action: int = 0              # ZebraRouteAction (ADD=1, DELETE=2)
    prefix: str = ''             # route prefix (symbolic placeholder)
    prefix_str: str = ''         # human-readable prefix for harness verification
    nexthop: Optional[str] = None  # nexthop for fresh route install


@dataclass
class NotificationMessage:
    """Structured NOTIFICATION message (used as both input and output)."""
    sent: bool = False
    error_code: int = 0          # BGP_NOTIFY_* code
    error_subcode: int = 0
    hard_reset: bool = False


@dataclass
class UpdateMessage:
    """Structured UPDATE message (used as both input and output)."""
    sent: bool = False
    eor_marker: bool = False
    has_llgr_stale_community: bool = False
    withdrawn_prefix_count: int = 0
    nlri_prefix_count: int = 0
