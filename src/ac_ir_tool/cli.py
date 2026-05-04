"""定义命令行参数，并把用户输入分发到品牌协议分析主流程。"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
import sys

from .core import analyze_brand_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ac_ir_tool",
        description="Analyze IR learning payloads and generate protocol reports.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze one brand directory under doc/",
    )
    analyze_parser.add_argument(
        "--brand-dir",
        required=True,
        help="Brand directory path, for example: doc/brand-name",
    )
    analyze_parser.add_argument(
        "--output-dir",
        help="Optional output directory. Defaults to the brand protocol analysis directory.",
    )
    analyze_parser.add_argument(
        "--manifest",
        help="Optional manifest path. Defaults to the brand sample manifest when present.",
    )
    analyze_parser.add_argument(
        "--legacy-description",
        help="Optional path to the legacy description text file.",
    )
    analyze_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Disable progress logs and only keep errors.",
    )
    return parser


def emit_cli_progress(message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        analyze_brand_directory(
            brand_dir=Path(args.brand_dir),
            output_dir=Path(args.output_dir) if args.output_dir else None,
            manifest_path=Path(args.manifest) if args.manifest else None,
            legacy_description=Path(args.legacy_description)
            if args.legacy_description
            else None,
            progress=None if args.quiet else emit_cli_progress,
        )
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 2
