"""Command line entry point for connstrict."""

from __future__ import annotations

import argparse
import sys

from .parser import ConnectionStringError, diff, parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="connstrict",
        description="Validate and normalize a database connection string.",
    )
    parser.add_argument(
        "connection_string",
        nargs="?",
        help="the connection string to check (reads a line from stdin if omitted)",
    )
    parser.add_argument(
        "--diff",
        metavar="OTHER",
        help=(
            "compare connection_string against OTHER and report the fields "
            "that differ, instead of validating a single string"
        ),
    )
    parser.add_argument(
        "--lenient",
        action="store_true",
        help=(
            "accept ambiguous or malformed input instead of rejecting it, "
            "recovering with the same best-effort guess a permissive parser "
            "would make, and print each issue found as a warning"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the normalized connection string, no status line or warnings",
    )
    return parser


def _run_diff(raw: str, other: str, *, lenient: bool, quiet: bool) -> int:
    parsed = []
    for candidate in (raw, other):
        try:
            parsed.append(parse(candidate, lenient=lenient))
        except ConnectionStringError as exc:
            for issue in exc.issues:
                print(f"connstrict: error: {issue}", file=sys.stderr)
            return 1

    left, right = parsed
    if not quiet:
        for result in (left, right):
            for warning in result.warnings:
                print(f"connstrict: warning: {warning}", file=sys.stderr)

    changes = diff(left, right)
    if not changes:
        if not quiet:
            print("no differences")
        return 0

    for line in changes:
        print(line)
    return 3


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    raw = args.connection_string
    if args.diff is not None:
        if raw is None:
            print(
                "connstrict: --diff requires a connection string argument to compare",
                file=sys.stderr,
            )
            return 2
        return _run_diff(raw, args.diff, lenient=args.lenient, quiet=args.quiet)

    if raw is None:
        raw = sys.stdin.readline().rstrip("\n")

    if not raw:
        print("connstrict: no connection string given", file=sys.stderr)
        return 2

    try:
        result = parse(raw, lenient=args.lenient)
    except ConnectionStringError as exc:
        for issue in exc.issues:
            print(f"connstrict: error: {issue}", file=sys.stderr)
        return 1

    if not args.quiet:
        for warning in result.warnings:
            print(f"connstrict: warning: {warning}", file=sys.stderr)
        print("ok")

    print(result.normalized())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
