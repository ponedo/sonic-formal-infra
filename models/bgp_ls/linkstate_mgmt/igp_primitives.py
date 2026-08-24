"""IGP-specific primitives."""

import hashlib
from typing import NewType


# ── Opaque types ──────────────────────────────────────────────────────────────
# Aliase for an int. The BGP-LS model only compares them based on identity,
# similar to opaque_prefix_t, opaque_addr_t, and str63_t in modeling_primitives.
# Concrete ISO sys IDs are derived from integer values via to_sys_id below.
sys_id_t = NewType("sys_id_t", int)


# ── Opaque renderers ──────────────────────────────────────────────────────────

# OPAQUE_SYS_ROOT renders to the unspecified ID ('0000.0000.0000').
OPAQUE_SYS_ROOT = 0


def to_sys_id(s: sys_id_t) -> str:
    """Deterministic ISO system identifier for a sys_id_t identifier, over the
    full address space."""

    if s == OPAQUE_SYS_ROOT:
        return "0000.0000.0000"

    h = hashlib.blake2b(str(s).encode(), digest_size=6).digest()
    chunks = [h[i : i + 2].hex() for i in range(0, len(h), 2)]
    return ".".join(chunks)
