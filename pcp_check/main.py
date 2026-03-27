"""
pcp-check: Real-time CLI to detect TeamPCP and other active supply chain
attacks in your Python dependencies.

Usage:
    pcp-check [requirements.txt ...]
    pcp-check --json [requirements.txt ...]
    pcp-check --fail-on-compromised [requirements.txt ...]
"""

import sys
import os
import json
import re
import argparse
import urllib.request
import urllib.error
from typing import Optional, List, Tuple, Dict, Any

__version__ = "1.0.0"
API_BASE = os.environ.get("PCP_CHECK_API", "https://midnightrun.ai/api/pcp")

# ANSI colors — disabled if NO_COLOR or not a TTY
def _supports_color():
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def _c(code: str, text: str) -> str:
    if _supports_color():
        return f"\033[{code}m{text}\033[0m"
    return text

def green(t): return _c("32", t)
def red(t): return _c("31", t)
def yellow(t): return _c("33", t)
def bold(t): return _c("1", t)
def dim(t): return _c("2", t)
def cyan(t): return _c("36", t)


def check_package(ecosystem: str, package: str, version: str) -> Dict[str, Any]:
    """Call the PCP Check API for a single package version."""
    url = f"{API_BASE}/check/{ecosystem}/{package}/{version}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"pcp-check/{__version__}"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {
            "error": f"HTTP {e.code}",
            "ecosystem": ecosystem,
            "package": package,
            "version": version,
            "safe": None,
            "compromised": None,
        }
    except Exception as e:
        return {
            "error": str(e),
            "ecosystem": ecosystem,
            "package": package,
            "version": version,
            "safe": None,
            "compromised": None,
        }


def parse_requirements(filepath: str) -> List[Tuple[str, str]]:
    """
    Parse a requirements.txt file and return list of (package, version) tuples.
    Only includes pinned dependencies (== operator).
    """
    deps = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments, blank lines, options
                if not line or line.startswith(("#", "-", "http://", "https://")):
                    continue
                # Remove inline comments
                line = line.split("#")[0].strip()
                # Remove extras like package[extra]==1.0.0
                line_no_extras = re.sub(r"\[.*?\]", "", line)
                # Match pinned versions: package==1.0.0
                m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s,;]+)", line_no_extras)
                if m:
                    pkg = m.group(1)
                    ver = m.group(2)
                    deps.append((pkg, ver))
    except FileNotFoundError:
        print(red(f"  Error: File not found: {filepath}"), file=sys.stderr)
    return deps


def find_requirements_files() -> List[str]:
    """Auto-detect requirements files in current directory."""
    candidates = [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements/base.txt",
        "requirements/prod.txt",
        "requirements/production.txt",
    ]
    found = []
    for c in candidates:
        if os.path.exists(c):
            found.append(c)
    return found


def print_header(files: List[str]):
    print()
    print(bold(f"PCP Check v{__version__}") + dim(" — Supply Chain Attack Scanner"))
    print(dim(f"API: {API_BASE}"))
    print()
    for f in files:
        print(dim(f"Scanning: {f}"))
    print()


def print_result_row(result: Dict[str, Any]):
    pkg = result.get("package", "?")
    ver = result.get("version", "?")
    label = f"{pkg}=={ver}"
    pad = max(0, 32 - len(label))

    if result.get("error"):
        print(f"  {yellow('?')} {label}{' ' * pad} {yellow('ERROR')}  {dim(result['error'])}")
    elif result.get("compromised"):
        campaign = result.get("campaign") or "unknown"
        cve = result.get("cve") or ""
        print(f"  {red('✗')} {bold(label)}{' ' * pad} {red('COMPROMISED')}")
        print(f"    {dim('Campaign:')} {red(campaign)}{' (' + cve + ')' if cve else ''}")
        if result.get("payload"):
            print(f"    {dim('Payload:' )} {yellow(result['payload'])}")
        if result.get("safe_versions"):
            safe = ", ".join(result["safe_versions"])
            print(f"    {dim('Fix:     ')} upgrade to {green(safe)}")
    elif result.get("safe") is True:
        print(f"  {green('✓')} {label}{' ' * pad} {green('SAFE')}")
    else:
        print(f"  {yellow('?')} {label}{' ' * pad} {yellow('UNKNOWN')}")


def main():
    parser = argparse.ArgumentParser(
        prog="pcp-check",
        description="Detect TeamPCP and other active supply chain attacks in your dependencies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pcp-check                          # auto-detect requirements.txt
  pcp-check requirements.txt         # scan specific file
  pcp-check req.txt req-dev.txt      # scan multiple files
  pcp-check --json requirements.txt  # JSON output
  pcp-check --fail-on-compromised    # exit 1 if any compromised
        """,
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="requirements.txt files to scan (auto-detected if not specified)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--fail-on-compromised",
        action="store_true",
        help="Exit with code 1 if any compromised packages found",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pcp-check {__version__}",
    )
    parser.add_argument(
        "--api",
        default=API_BASE,
        help=f"API base URL (default: {API_BASE})",
    )

    args = parser.parse_args()

    global API_BASE
    API_BASE = args.api

    # Determine files to scan
    files = args.files if args.files else find_requirements_files()
    if not files:
        print(red("Error: No requirements.txt found. Specify a file or run from your project root."), file=sys.stderr)
        sys.exit(2)

    # Collect all deps
    all_deps: List[Tuple[str, str, str]] = []  # (file, pkg, version)
    for filepath in files:
        deps = parse_requirements(filepath)
        for pkg, ver in deps:
            all_deps.append((filepath, pkg, ver))

    if not all_deps:
        print(yellow("No pinned dependencies found (== operator required)."))
        sys.exit(0)

    if not args.json:
        print_header(files)
        total = len(all_deps)
        print(dim(f"  Checking {total} pinned {'dependency' if total == 1 else 'dependencies'}..."))
        print()

    # Check each package
    results = []
    compromised_count = 0
    error_count = 0

    for filepath, pkg, version in all_deps:
        result = check_package("pypi", pkg, version)
        result["_file"] = filepath
        results.append(result)

        if not args.json:
            print_result_row(result)

        if result.get("compromised"):
            compromised_count += 1
        if result.get("error"):
            error_count += 1

    if args.json:
        output = {
            "version": __version__,
            "files": files,
            "total": len(results),
            "compromised": compromised_count,
            "errors": error_count,
            "results": results,
        }
        print(json.dumps(output, indent=2))
    else:
        # Summary
        print()
        print(dim("─" * 52))
        if compromised_count == 0:
            print(f"  {green('RESULT:')} All {len(results)} packages checked — {green('no threats found.')}  ✓")
        else:
            print(f"  {red('RESULT:')} {red(f'{compromised_count} compromised')} package{'s' if compromised_count != 1 else ''} found!")
            print(f"  {dim('Update immediately — see fix suggestions above.')}")
        if error_count > 0:
            print(f"  {yellow(f'{error_count} packages could not be checked')} (network error)")
        print(dim("─" * 52))
        print()
        print(dim(f"  Full API: {API_BASE}/check/pypi/<pkg>/<version>"))
        print(dim(f"  Docs: https://midnightrun.ai/pcp-check"))
        print()

    if args.fail_on_compromised and compromised_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
