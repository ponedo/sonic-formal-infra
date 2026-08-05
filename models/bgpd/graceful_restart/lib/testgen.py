"""Shared test-generation infrastructure for all CrossHair format_tests modules.

Provides the CrossHair runner (subprocess and coverage-tracked variants),
output parsing, the test-generation loop, and the CLI entry-point — so that
each model's ``format_tests.py`` only needs to declare its model-specific
build/format functions and TARGETS list.
"""
import ast
import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lib import Afi, Safi

# ── Target configuration type ────────────────────────────────────────

TargetConfig = Tuple[
    str,                                          # target name: module.function
    Callable[[Dict[str, Any]], Any],              # build input from arg dict
    Callable[[Any, Dict[str, Any]], Tuple[Dict[str, Any], Dict[str, Any]]],  # format
    Optional[Callable[[Dict[str, Any]], bool]],   # precondition
    int,                                          # per_condition_timeout
]


# ── CrossHair runner ─────────────────────────────────────────────────

def run_crosshair(
    target: str,
    per_condition_timeout: int = 30,
    per_path_timeout: int = 10,
    max_uninteresting_iterations: int = 500,
    coverage_type: str = "path",
) -> List[str]:
    """Run CrossHair cover and return raw output lines.

    When CROSSHAIR_IN_PROCESS=1 is set, CrossHair runs in an isolated
    subprocess with coverage tracking so that ``coverage combine`` can
    produce a unified report.
    """
    argv = [
        'crosshair', 'cover',
        '--example_output_format', 'arg_dictionary',
        '--coverage_type', coverage_type,
        '--per_condition_timeout', str(per_condition_timeout),
        '--per_path_timeout', str(per_path_timeout),
        '--max_uninteresting_iterations', str(max_uninteresting_iterations),
        target,
    ]
    if os.environ.get('CROSSHAIR_IN_PROCESS'):
        return _run_crosshair_in_process(argv)
    return _run_crosshair_subprocess(argv, target)


def _run_crosshair_subprocess(argv: List[str], target: str) -> List[str]:
    """Run CrossHair in a plain subprocess (no coverage tracking)."""
    argv_str = ', '.join(f"'{a}'" for a in argv)
    cmd = [
        sys.executable, "-c",
        f"import sys; sys.setrecursionlimit(50000); "
        f"from crosshair.main import main; "
        f"sys.argv = [{argv_str}]; "
        f"sys.exit(main())",
    ]
    result = subprocess.run(
        cmd, cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if result.returncode not in (0, 2):
        print(f"Warning: CrossHair for {target} exited {result.returncode}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return lines


def _run_crosshair_in_process(argv: List[str]) -> List[str]:
    """Run one CrossHair target in a fresh subprocess with coverage tracking.

    Spawns an isolated Python subprocess per target so that CrossHair's
    internal state (solver caches, audit wall) doesn't leak between targets.
    Each subprocess writes its own .coverage.<pid> file (--parallel-mode),
    which ``coverage combine`` merges into a single report afterwards.
    """
    argv_str = ', '.join(f"'{a}'" for a in argv)
    script = (
        "import sys, coverage; "
        "cov = coverage.Coverage(data_suffix=True); cov.start(); "
        "sys.setrecursionlimit(50000); "
        "from crosshair.main import main; "
        f"sys.argv = [{argv_str}]; "
        "r = 0;\n"
        "try:\n"
        "    r = main()\n"
        "except SystemExit as e:\n"
        "    r = e.code or 0\n"
        "finally:\n"
        "    try:\n"
        "        from crosshair.auditwall import disable_auditwall\n"
        "        disable_auditwall()\n"
        "    except Exception:\n"
        "        pass\n"
        "    cov.stop(); cov.save()\n"
        "    sys.exit(r)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return lines


# ── CrossHair output parsing ─────────────────────────────────────────

def expand_named_expressions(line: str) -> str:
    """Expand CrossHair's ``vN:=<value>`` shorthand."""
    defs: Dict[str, str] = {}
    for match in re.finditer(r"\bv(\d+):=(\([^)]*\))", line):
        defs[match.group(1)] = match.group(2)

    def _replace_ref(match: "re.Match[str]") -> str:
        return defs.get(match.group(1), match.group(0))

    line = re.sub(r"\bv(\d+)\b(?!:=)", _replace_ref, line)
    line = re.sub(r"\bv(\d+):=(\([^)]*\))", r"\2", line)
    return line


def parse_arg_dictionary(line: str) -> Dict[str, Any]:
    """Parse a CrossHair arg_dictionary output line.

    CrossHair may emit enum names (e.g. ``Afi.IP``, ``Safi.UNICAST``) for
    ``List[Tuple[Afi, Safi]]`` parameters; ``ast.literal_eval`` cannot parse
    those, so we fall back to a restricted ``eval`` with Afi/Safi in scope.
    """
    line = expand_named_expressions(line)
    try:
        return ast.literal_eval(line)
    except (ValueError, SyntaxError):
        return eval(line, {"Afi": Afi, "Safi": Safi})


# ── CLI helpers ───────────────────────────────────────────────────────

def make_parser(description: str) -> "argparse.ArgumentParser":
    """Create the standard argument parser for format_tests modules."""
    import argparse
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "models", nargs="*",
        help="Model names to generate.",
    )
    parser.add_argument("--list", action="store_true")
    parser.add_argument(
        "--coverage", action="store_true",
        help="Collect code coverage (implies CROSSHAIR_IN_PROCESS=1).",
    )
    return parser


def model_name_from_target(target: str) -> str:
    """Extract the model name from a CrossHair target string."""
    return target.split(".")[-1].replace("_target", "")


# ── Test generation loop ─────────────────────────────────────────────

def generate_tests(
    targets: List[TargetConfig],
    output_dir: Path,
    per_path_timeout: int = 10,
    max_uninteresting_iterations: int = 500,
    coverage_type: str = "path",
) -> None:
    """Run CrossHair for each target and write JSON test cases."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for target, build_input, format_output, precondition, per_condition_timeout in targets:
        model_name = model_name_from_target(target)
        print(f"Generating tests for {model_name}...")

        raw_lines = run_crosshair(
            target,
            per_condition_timeout=per_condition_timeout,
            per_path_timeout=per_path_timeout,
            max_uninteresting_iterations=max_uninteresting_iterations,
            coverage_type=coverage_type,
        )
        test_cases: List[Dict[str, Any]] = []
        seen_inputs: set = set()
        test_id = 0

        for line in raw_lines:
            try:
                arg_dict = parse_arg_dictionary(line)

                if precondition is not None and not precondition(arg_dict):
                    continue

                key = json.dumps(arg_dict, sort_keys=True)
                if key in seen_inputs:
                    continue
                seen_inputs.add(key)

                inp = build_input(arg_dict)
                expected, input_json = format_output(inp, arg_dict)
                test_id += 1
                test_cases.append({
                    "test_id": test_id,
                    "input": input_json,
                    "expected_output": expected,
                })
            except Exception as e:
                print(f"  Skipping invalid line: {line[:80]}... ({e})", file=sys.stderr)
                continue

        output_path = output_dir / f"{model_name}_tests.json"
        with open(output_path, "w") as f:
            json.dump({
                "model": model_name,
                "test_cases": test_cases,
            }, f, indent=2)

        print(f"  Wrote {len(test_cases)} test cases to {output_path}")


# ── Main entry point ─────────────────────────────────────────────────

def main(
    targets: List[TargetConfig],
    output_dir: Path,
    description: str,
) -> None:
    """CLI entry point for format_tests modules.

    Handles argument parsing, ``--list``, ``--coverage``, model filtering,
    and test generation.
    """
    parser = make_parser(description)
    args = parser.parse_args()

    available = [model_name_from_target(t[0]) for t in targets]

    if args.list:
        print("Available models:")
        for name in available:
            print(f"  {name}")
        sys.exit(0)

    if args.models:
        unknown = set(args.models) - set(available)
        if unknown:
            print(f"Unknown model(s): {', '.join(sorted(unknown))}")
            print(f"Available: {', '.join(available)}")
            sys.exit(1)
        targets = [
            t for t in targets
            if model_name_from_target(t[0]) in args.models
        ]

    if args.coverage:
        os.environ['CROSSHAIR_IN_PROCESS'] = '1'
        for f in glob.glob(str(PROJECT_ROOT / ".coverage.*")):
            os.remove(f)

    generate_tests(targets, output_dir)

    if args.coverage:
        import coverage as _cov
        import shutil
        cov = _cov.Coverage(omit=["proxy_*"])
        cov.combine()
        print("\n=== Coverage Report ===")
        cov.report(show_missing=False, include=["stale_timer_action.py", "update_receive_model.py", "update_receive_during_stale.py"])
        html_dir = output_dir / "coverage_html"
        # Clean stale HTML files and regenerate only for the current model.
        if html_dir.exists():
            shutil.rmtree(html_dir)
        model_name = output_dir.name
        cov.html_report(
            directory=str(html_dir),
            include=["stale_timer_action.py", "update_receive_model.py", "update_receive_during_stale.py"],
        )
        print(f"\nHTML coverage report: {html_dir / 'index.html'}")
