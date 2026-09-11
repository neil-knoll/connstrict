"""Command line entry point for connstrict."""

from __future__ import annotations

import argparse
import sys

from .parser import ConnectionStringError, parse


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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    raw = args.connection_string
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
