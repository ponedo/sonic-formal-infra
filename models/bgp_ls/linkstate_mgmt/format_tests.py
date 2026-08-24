"""Format script for CrossHair arg_dictionary test inputs.

Reads tests/linkstate_update_argdict.txt (or any arg_dictionary-format file from
`crosshair cover`), canonicalizes and dedupes inputs, re-executes the model on
each canonical input, and writes a JSON file of fully-populated test cases that
can compare against actual bgpd execution.

Run from anywhere:
    python3 path/to/format_tests.py [INPUT] [-o OUTPUT]
"""

import argparse
import copy
import json
import os
import sys
from dataclasses import dataclass
from collections.abc import Iterator

_HERE = os.path.dirname(
    os.path.abspath(__file__)
)  # <project-root>/models/bgp_ls/linkstate_mgmt/
_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(_HERE))
)  # root project directory
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "mbt"))
sys.path.insert(0, os.path.join(_ROOT, "models"))


print(f"_ROOT: {_ROOT}")

from models.bgp_ls.linkstate_mgmt.linkstate_data import (
    BApiLinkStateUpdate,
    LinkStateEvent,
)
from bgp_ls.linkstate_mgmt.api_bgp_ls_linkstate_update import (
    BgpLsLinkState,
    BgpAttributes,
)
from bgp_ls.linkstate_mgmt.crosshair_target import (
    _correct_edge_params,
    _correct_subnet_params,
    _correct_ted_seed,
    _build_state_and_api,
)


DEFAULT_INPUT = os.path.join(_HERE, "tests", "linkstate_update_argdict.txt")
DEFAULT_OUTPUT = os.path.join(_HERE, "tests", "linkstate_update_formatted.json")


@dataclass
class TestCase:
    """One row from a CrossHair arg_dictionary file, plus slots that the
    processing step fills in.

    After read_and_dedup_argdict, only test_id and inputs are populated.
    After format_test_case (which calls evaluate), all six are populated."""

    test_id: int  # sequential, starts at 1
    inputs: dict  # canonicalized kwargs
    initial_state: BgpLsLinkState | None = None
    api_param: BApiLinkStateUpdate | None = None
    final_state: BgpLsLinkState | None = None
    update_msg: BgpAttributes | None = None


def read_argdict(path: str) -> Iterator[TestCase]:
    """Stream TestCases from a CrossHair arg_dictionary output file.

    Each non-blank line is one Python expression (a dict of kwargs).
    Only the input side of TestCase is populated; computed fields stay None."""
    with open(path) as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            # eval, not ast.literal_eval: CrossHair emits walrus aliases
            # (e.g., `v1:=(0, [])`) which ast rejects. Restricted __builtins__
            # keeps this safe for our trusted-but-walrus-containing input.
            inputs = eval(line, {"__builtins__": {}}, {})
            yield TestCase(test_id=line_no, inputs=inputs)


def canonicalize(inputs: dict) -> dict:
    """Run the same seed coercions the symbolic wrapper applies.

    After this pass, two raw inputs that map to the same model behavior
    become byte-identical, which lets us dedupe."""

    api_ls = inputs["api_ls"]
    match len(api_ls):
        case 4:
            api_ls = _correct_edge_params(*api_ls)
        case 2:
            api_ls = _correct_subnet_params(*api_ls)
        case _:
            raise ValueError(
                "Invalid number of parameters passed for api_ls - must be 2 "
                "(prefix) or 4 (link)"
            )

    link_seed, prefix_seed = _correct_ted_seed(
        inputs["link_seed"],
        inputs["prefix_seed"],
        api_ls if len(api_ls) == 4 else None,
        api_ls if len(api_ls) == 2 else None,
    )

    return {
        "link_seed": link_seed,
        "prefix_seed": prefix_seed,
        "api_event": inputs["api_event"],
        "api_asn": inputs["api_asn"],
        "api_level": inputs["api_level"],
        "api_ls": api_ls,
    }


def _hash_key(canonical: dict) -> tuple:
    """Hashable fingerprint of canonical inputs (lists become tuples)."""
    return (
        tuple(
            (src_sys_id, dest_sys_id, src, dest)
            for src_sys_id, dest_sys_id, src, dest in canonical["link_seed"]
        ),
        tuple(
            (adv_node, prefix) for adv_node, prefix in canonical["prefix_seed"]
        ),
        canonical["api_event"],
        canonical["api_asn"],
        canonical["api_level"],
        canonical["api_ls"],
    )


def read_and_dedup_argdict(path: str) -> Iterator[TestCase]:
    """Read, canonicalize, and dedupe.

    Yields the first occurrence of each canonical key, with `inputs` replaced
    by its canonical form. `test_id` is preserved from the source line so the
    survivor still points back to its original row in the input file."""
    seen: set[tuple] = set()
    for tc in read_argdict(path):
        canonical = canonicalize(tc.inputs)
        key = _hash_key(canonical)
        if key in seen:
            continue
        seen.add(key)
        yield TestCase(test_id=tc.test_id, inputs=canonical)


def evaluate(
    test_id: int,
    canonical: dict,
) -> tuple[
    BgpLsLinkState, BApiLinkStateUpdate, BgpLsLinkState, BgpAttributes | None
]:
    """Re-execute the model on canonical inputs.

    Returns (initial_state, api_param, final_state, downstream_msgs).
    `initial_state` is the freshly-built pre-state; `final_state` is a
    deep copy mutated by the transition.

    Asserts the invariant before and after — before is a sanity check on
    canonicalize() (its job is to produce invariant-satisfying states);
    after is the model's claimed property. Each test case is thus also
    an invariant check."""
    print(f"{canonical!r}")
    initial_state, api = _build_state_and_api(**canonical)
    assert initial_state.invariant(), (
        f"canonicalized inputs produced a non-invariant state: {canonical!r} "
        f"(ID: {test_id})"
    )
    final_state = copy.deepcopy(initial_state)
    res = final_state.api_bgp_ls_linkstate_update(api)
    assert final_state.invariant(), (
        f"transition broke invariant; inputs={canonical!r}, res={res!r} "
        f"(ID: {test_id})"
    )
    return initial_state, api, final_state, res


def format_test_case(tc: TestCase) -> dict:
    """Re-execute the model and produce the formatted output dict.

    Populates tc.initial_state / api_param / final_state / downstream_msgs
    in place so in-memory consumers see a fully-formed TestCase."""
    initial_state, api, final_state, res = evaluate(tc.test_id, tc.inputs)
    tc.initial_state = initial_state
    tc.api_param = api
    tc.final_state = final_state
    tc.update_msg = res

    formatted = {
        "TestId": tc.test_id,
        "Op": f"api_bgp_ls_linkstate_{LinkStateEvent(api.event).name.lower()}",
        "InitialState": initial_state.to_dict(),
        "ApiParam": api.to_dict(),
        "FinalState": final_state.to_dict(),
    }

    if res and (msg_dict := res.to_dict()):
        formatted["UpdateMessage"] = msg_dict

    return formatted


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Read a CrossHair arg_dictionary file, canonicalize + dedupe inputs"
            ", re-execute the model, and emit JSON test cases."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=DEFAULT_INPUT,
        help=f"Path to arg_dictionary file (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Path to output JSON file (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    raw = sum(1 for _ in read_argdict(args.input))
    cases = list(read_and_dedup_argdict(args.input))
    formatted = [format_test_case(tc) for tc in cases]

    with open(args.output, "w") as f:
        json.dump(formatted, f, indent=2)

    print(f"path:     {args.input}")
    print(f"raw:      {raw} inputs")
    print(f"deduped:  {len(cases)} test cases")
    print(f"output:   {args.output}")


if __name__ == "__main__":
    main()
