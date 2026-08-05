"""JSON serialization helpers shared across all model format_tests modules.

These functions convert internal BGP model types (Afi/Safi tuples, RIB dicts,
NLRI, BgpUpdateNlri, etc.) into JSON-serializable Python primitives.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

from lib import Afi, Safi, prefix_to_str, prefix_t
from update_receive_model import BgpUpdateNlri


def af_flag_dict_to_json(d: Dict[Tuple[Afi, Safi], bool]) -> Dict[str, bool]:
    """Serialize per-AFI/SAFI boolean dict with 'afi,safi' keys."""
    return {f"{int(k[0])},{int(k[1])}": v for k, v in d.items()}


def af_int_dict_to_json(d: Dict[Tuple[Afi, Safi], int]) -> Dict[str, int]:
    """Serialize per-AFI/SAFI int dict with 'afi,safi' keys."""
    return {f"{int(k[0])},{int(k[1])}": v for k, v in d.items()}


def rib_dict_to_json(
    rib: Dict[Tuple[Afi, Safi], Dict[Any, Any]],
    path_fields: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Serialize a RIB dict (dest-path hierarchy from ``asdict()``) for JSON.

    Keys are (Afi, Safi) tuples mapped to ``"afi,safi"`` strings.
    Prefix keys are prefix_t integers mapped to prefix_str strings.

    *path_fields* selects which path keys to keep.  Defaults to
    ``("peer_id", "stale", "removed")``.
    """
    from dataclasses import asdict as _asdict

    if path_fields is None:
        path_fields = ("peer_id", "stale", "removed")
    result: Dict[str, Any] = {}
    for afi_safi, table in rib.items():
        afi, safi = afi_safi
        key = f"{int(afi)},{int(safi)}"
        result[key] = {}
        for prefix, dest in table.items():
            prefix_str = prefix_to_str(prefix, ipv6=(int(afi) == int(Afi.IPv6)))
            d = _asdict(dest) if not isinstance(dest, dict) else dest
            result[key][prefix_str] = {
                "paths": [
                    {f: p[f] for f in path_fields}
                    for p in d["paths"]
                ]
            }
    return result


def rib_to_json(rib: Dict) -> Dict[str, Any]:
    """Serialize a Rib (nested dict with dataclass PathInfo values) for JSON."""
    result: Dict[str, Any] = {}
    for afi_safi, table in rib.items():
        af_key = f"{int(afi_safi[0])},{int(afi_safi[1])}"
        table_json: Dict[str, Any] = {}
        for pfx, dest in table.items():
            pfx_str = prefix_to_str(
                pfx, ipv6=(int(afi_safi[0]) == int(Afi.IPv6)),
            )
            paths_json = [
                {
                    "peer_id": pi.peer_id,
                    "stale": pi.stale,
                    "removed": pi.removed,
                    "has_llgr_stale_community": pi.has_llgr_stale_community,
                    "has_no_llgr_community": pi.has_no_llgr_community,
                }
                for pi in dest.paths
            ]
            table_json[pfx_str] = {"paths": paths_json}
        result[af_key] = table_json
    return result


def prefix_list_to_json(prefixes: List[prefix_t], ipv6: bool) -> List[str]:
    """Serialize a list of prefixes."""
    return [prefix_to_str(p, ipv6=ipv6) for p in prefixes]


def nlri_to_json(
    nlri: Dict[Tuple[Afi, Safi], List[prefix_t]],
) -> Dict[str, List[str]]:
    """Serialize NLRI dict for JSON output."""
    result: Dict[str, List[str]] = {}
    for afi_safi, prefixes in nlri.items():
        af_key = f"{int(afi_safi[0])},{int(afi_safi[1])}"
        result[af_key] = prefix_list_to_json(
            prefixes, ipv6=(int(afi_safi[0]) == int(Afi.IPv6)),
        )
    return result


def normalize_afi_safi_list(
    lst: List[Any],
) -> List[Tuple[Afi, Safi]]:
    """Normalize CrossHair output (int tuples or enum tuples) to (Afi, Safi)."""
    result: List[Tuple[Afi, Safi]] = []
    for item in lst:
        a, s = item
        result.append((Afi(int(a)), Safi(int(s))))
    return result


def afi_safi_list_to_json(lst: List[Tuple[Afi, Safi]]) -> List[str]:
    """Serialize list of AFI/SAFI tuples."""
    return [f"{int(a)},{int(s)}" for a, s in lst]


def update_to_json(update: BgpUpdateNlri) -> Dict[str, Any]:
    """Serialize BgpUpdateNlri for JSON output."""
    result: Dict[str, Any] = {
        "ipv4_nlri": prefix_list_to_json(update.ipv4_nlri, ipv6=False),
        "ipv4_withdrawn": prefix_list_to_json(update.ipv4_withdrawn, ipv6=False),
        "mp_reach": nlri_to_json(update.mp_reach),
    }
    if update.mp_unreach is not None:
        afi_safi, prefixes = update.mp_unreach
        af_key = f"{int(afi_safi[0])},{int(afi_safi[1])}"
        result["mp_unreach"] = {
            "afi_safi": af_key,
            "prefixes": prefix_list_to_json(
                prefixes, ipv6=(int(afi_safi[0]) == int(Afi.IPv6))
            ),
        }
    else:
        result["mp_unreach"] = None
    return result
