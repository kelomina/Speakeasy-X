# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import argparse
import json
import logging
import multiprocessing as mp
import os
import shlex
import time

from rich.console import Console
from rich.logging import RichHandler

import speakeasy.winenv.arch as e_arch
from speakeasy import Speakeasy
from speakeasy.cli_config import (
    add_config_cli_arguments,
    apply_config_cli_overrides,
    get_config_cli_field_specs,
    get_default_config_dict,
    merge_config_dicts,
)
from speakeasy.config import SpeakeasyConfig
from speakeasy.volumes import apply_volumes

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool) -> None:
    root = logging.getLogger("speakeasy")
    root.handlers.clear()
    root.addHandler(RichHandler(console=Console(stderr=True), show_path=False))
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


def get_pseudocode_visual_format(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".svg":
        return "svg"
    if ext == ".xml":
        return "xml"
    raise ValueError("Unsupported pseudocode visual output extension. Use .svg or .xml")


def get_pseudocode_string_encoding(value: str) -> str:
    encoding = value.lower()
    if encoding in ("utf8", "utf-8"):
        return "utf8"
    if encoding in ("utf16", "utf-16", "utf16le", "utf-16le"):
        return "utf16"
    raise ValueError("Unsupported pseudocode string encoding. Use utf8 or utf16")


def emulate_binary(
    q,
    exit_event,
    fpath,
    cfg,
    argv,
    do_raw,
    arch="",
    dropped_files_path="",
    raw_offset=0x0,
    entry_point=None,
    emulate_children=False,
    verbose=False,
    gdb_port=None,
    pseudocode_out="",
    pseudocode_visual_out="",
    pseudocode_comments=True,
    pseudocode_string_encoding="utf8",
    pseudocode_keep_filtered_jumps=False,
    pseudocode_show_register_values=False,
    pseudocode_enable_heuristics=False,
):
    setup_logging(verbose)

    report = None
    se = None
    try:
        se = Speakeasy(config=cfg, argv=argv, exit_event=exit_event, gdb_port=gdb_port)
        pseudocode_enabled = bool(pseudocode_out or pseudocode_visual_out)
        if do_raw:
            arch = arch.lower()
            if arch == "x86":
                arch = e_arch.ARCH_X86
            elif arch in ("x64", "amd64"):
                arch = e_arch.ARCH_AMD64
            else:
                raise Exception(f"Unsupported architecture: {arch}")

            sc_addr = se.load_shellcode(fpath, arch)
            if pseudocode_enabled:
                se.enable_pseudocode(
                    include_comments=pseudocode_comments,
                    string_encoding=pseudocode_string_encoding,
                    keep_filtered_jumps=pseudocode_keep_filtered_jumps,
                    show_register_values=pseudocode_show_register_values,
                    enable_heuristics=pseudocode_enable_heuristics,
                )
            se.run_shellcode(sc_addr, offset=raw_offset or 0)
        else:
            module = se.load_module(fpath)
            if pseudocode_enabled:
                se.enable_pseudocode(
                    include_comments=pseudocode_comments,
                    string_encoding=pseudocode_string_encoding,
                    keep_filtered_jumps=pseudocode_keep_filtered_jumps,
                    show_register_values=pseudocode_show_register_values,
                    enable_heuristics=pseudocode_enable_heuristics,
                )
            se.run_module(
                module,
                all_entrypoints=True,
                emulate_children=emulate_children,
                entry_point=entry_point,
            )
    finally:
        if se is not None:
            report = se.get_json_report()
        q.put(report)

        if pseudocode_out and se is not None:
            pseudocode_text = se.get_pseudocode_text()
            logger.info("* Saving pseudocode to %s", pseudocode_out)
            with open(pseudocode_out, "w", encoding="utf-8") as f:
                f.write(pseudocode_text)

        if pseudocode_visual_out and se is not None:
            visual_format = get_pseudocode_visual_format(pseudocode_visual_out)
            pseudocode_visual = se.get_pseudocode_visual(format_name=visual_format)
            logger.info("* Saving pseudocode visual to %s", pseudocode_visual_out)
            with open(pseudocode_visual_out, "w", encoding="utf-8") as f:
                f.write(pseudocode_visual)

        if dropped_files_path and se is not None:
            data = se.create_file_archive()
            if data:
                logger.info("* Saving dropped files archive to %s", dropped_files_path)
                with open(dropped_files_path, "wb") as f:
                    f.write(data)
            else:
                logger.info("* No dropped files found")


def run_main(parser: argparse.ArgumentParser, args: argparse.Namespace, config_specs) -> None:
    target = args.target
    output = args.output
    dropped_files_path = args.dropped_files_path
    pseudocode_out = args.pseudocode_out
    pseudocode_visual_out = args.pseudocode_visual_out
    pseudocode_comments = args.pseudocode_comments
    pseudocode_string_encoding = get_pseudocode_string_encoding(args.pseudocode_string_encoding)
    pseudocode_keep_filtered_jumps = args.pseudocode_keep_filtered_jumps
    pseudocode_show_register_values = args.pseudocode_show_register_values
    pseudocode_enable_heuristics = args.pseudocode_enable_heuristics
    config_path = args.config
    emulate_children = args.emulate_children
    do_raw = args.do_raw
    raw_offset = args.raw_offset
    entry_point = args.entry_point
    arch = args.arch
    argv = shlex.split(args.argv) if args.argv else []
    verbose = args.verbose
    gdb_port = args.gdb_port if args.gdb else None

    setup_logging(verbose)

    if args.gdb and not args.no_mp:
        args.no_mp = True
        logger.info("--gdb requires --no-mp mode; enabling automatically")

    cfg = get_default_config_dict()

    if config_path:
        if not os.path.isfile(config_path):
            parser.error(f"Config file not found: {config_path}")
        with open(config_path) as f:
            user_cfg = json.load(f)
        cfg = merge_config_dicts(cfg, user_cfg)

    if args.volumes:
        apply_volumes(cfg, args.volumes)

    cfg = apply_config_cli_overrides(cfg, args, config_specs)

    try:
        validated = SpeakeasyConfig.model_validate(cfg)
    except Exception as err:
        parser.error(f"Invalid active configuration: {err}")

    active_cfg = validated.model_dump(mode="python")
    timeout = float(validated.timeout)

    if target and not os.path.isfile(target):
        parser.error(f"Target file not found: {target}")

    if not target:
        parser.error("No target file supplied")

    if pseudocode_visual_out:
        try:
            get_pseudocode_visual_format(pseudocode_visual_out)
        except ValueError as err:
            parser.error(str(err))

    q: mp.Queue = mp.Queue()
    evt = mp.Event()

    if args.no_mp:
        emulate_binary(
            q,
            evt,
            target,
            active_cfg,
            argv,
            do_raw,
            arch,
            dropped_files_path,
            raw_offset=raw_offset,
            entry_point=entry_point,
            emulate_children=emulate_children,
            verbose=verbose,
            gdb_port=gdb_port,
            pseudocode_out=pseudocode_out,
            pseudocode_visual_out=pseudocode_visual_out,
            pseudocode_comments=pseudocode_comments,
            pseudocode_string_encoding=pseudocode_string_encoding,
            pseudocode_keep_filtered_jumps=pseudocode_keep_filtered_jumps,
            pseudocode_show_register_values=pseudocode_show_register_values,
            pseudocode_enable_heuristics=pseudocode_enable_heuristics,
        )
        report = q.get()
    else:
        p = mp.Process(
            target=emulate_binary,
            args=(
                q,
                evt,
                target,
                active_cfg,
                argv,
                do_raw,
                arch,
                dropped_files_path,
            ),
            kwargs={
                "raw_offset": raw_offset,
                "entry_point": entry_point,
                "emulate_children": emulate_children,
                "verbose": verbose,
                "gdb_port": gdb_port,
                "pseudocode_out": pseudocode_out,
                "pseudocode_visual_out": pseudocode_visual_out,
                "pseudocode_comments": pseudocode_comments,
                "pseudocode_string_encoding": pseudocode_string_encoding,
                "pseudocode_keep_filtered_jumps": pseudocode_keep_filtered_jumps,
                "pseudocode_show_register_values": pseudocode_show_register_values,
                "pseudocode_enable_heuristics": pseudocode_enable_heuristics,
            },
        )
        p.start()

        report = None
        start_time = time.time()
        while True:
            if timeout and timeout < (time.time() - start_time):
                evt.set()
                logger.error("* Child process timeout reached after %d seconds", timeout)
                try:
                    report = q.get(timeout=5)
                except mp.queues.Empty:  # type: ignore[attr-defined]
                    pass
                break
            try:
                report = q.get(timeout=1)
                break
            except mp.queues.Empty:  # type: ignore[attr-defined]
                if not p.is_alive():
                    break
            except KeyboardInterrupt:
                evt.set()
                logger.error("\n* User exited")
                try:
                    report = q.get(timeout=5)
                except mp.queues.Empty:  # type: ignore[attr-defined]
                    pass
                break

    logger.info("* Finished emulating")

    if report and output:
        logger.info("* Saving emulation report to %s", output)
        with open(output, "w") as f:
            f.write(report)


def main():
    parser = argparse.ArgumentParser(description="Emulate a Windows binary with speakeasy", allow_abbrev=False)
    parser.add_argument(
        "-t", "--target", action="store", dest="target", required=False, help="Path to input file to emulate"
    )
    parser.add_argument(
        "-o", "--output", action="store", dest="output", required=False, help="Path to output file to save report"
    )
    parser.add_argument(
        "--pseudocode-out",
        action="store",
        dest="pseudocode_out",
        required=False,
        help="Path to output file to save simplified pseudocode",
    )
    parser.add_argument(
        "--pseudocode-visual-out",
        action="store",
        dest="pseudocode_visual_out",
        required=False,
        help="Path to output file to save pseudocode visualization (.svg or .xml)",
    )
    parser.add_argument(
        "--pseudocode-comments",
        action=argparse.BooleanOptionalAction,
        dest="pseudocode_comments",
        default=True,
        required=False,
        help="Include assembly comments and resolved context in pseudocode output",
    )
    parser.add_argument(
        "--pseudocode-string-encoding",
        action="store",
        dest="pseudocode_string_encoding",
        default="utf8",
        required=False,
        help="String decoding mode for pseudocode output: utf8 or utf16",
    )
    parser.add_argument(
        "--pseudocode-keep-filtered-jumps",
        action=argparse.BooleanOptionalAction,
        dest="pseudocode_keep_filtered_jumps",
        default=False,
        required=False,
        help="Keep filtered jump instructions as comment-only lines in pseudocode output",
    )
    parser.add_argument(
        "--pseudocode-show-register-values",
        action=argparse.BooleanOptionalAction,
        dest="pseudocode_show_register_values",
        default=False,
        required=False,
        help="Show current register values in pseudocode comments and XML output",
    )
    parser.add_argument(
        "--pseudocode-enable-heuristics",
        action=argparse.BooleanOptionalAction,
        dest="pseudocode_enable_heuristics",
        default=False,
        required=False,
        help="Enable heuristic recovery for aliases, function names, memory abstraction and folding",
    )
    parser.add_argument(
        "--argv",
        action="store",
        default="",
        dest="argv",
        required=False,
        help="Commandline parameters to supply to emulated process, as a quoted string "
        "(e.g. --argv=\"-log -path 'C:\\\\path with spaces\\\\'\")",
    )
    parser.add_argument(
        "-c", "--config", action="store", dest="config", required=False, help="Path to emulator config file"
    )
    parser.add_argument(
        "--dump-default-config",
        action="store_true",
        dest="dump_default_config",
        required=False,
        help="Print built-in default config JSON and exit",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        dest="do_raw",
        required=False,
        help="Attempt to emulate file as-is with no parsing (e.g. shellcode)",
    )
    parser.add_argument(
        "--raw-offset",
        type=lambda s: int(s, 0x10),
        default=0,
        required=False,
        dest="raw_offset",
        help="When in raw mode, offset (hex) to start emulating",
    )
    parser.add_argument(
        "--entry-point",
        type=lambda s: int(s, 0),
        default=None,
        required=False,
        dest="entry_point",
        help="RVA (hex) to use as entry point instead of the PE's default. "
        "Prefix with 0x for hex (e.g. 0x1234). Only applies to PE modules, not raw/shellcode.",
    )
    parser.add_argument(
        "--arch",
        action="store",
        dest="arch",
        required=False,
        help="Force architecture to use during emulation (for multi-architecture files or shellcode). "
        "Supported archs: [ x86 | amd64 ]",
    )
    parser.add_argument(
        "--dropped-files-path",
        action="store",
        dest="dropped_files_path",
        required=False,
        help="Path to store files created during emulation",
    )
    parser.add_argument(
        "-k",
        "--emulate-children",
        action="store_true",
        dest="emulate_children",
        required=False,
        help="Emulate any processes created with CreateProcess APIs after the input file finishes emulating",
    )
    parser.add_argument(
        "--no-mp",
        action="store_true",
        dest="no_mp",
        required=False,
        help="Run emulation in the current process instead of a child process",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        required=False,
        help="Enable verbose (DEBUG) logging",
    )
    parser.add_argument(
        "--gdb",
        action="store_true",
        dest="gdb",
        required=False,
        help="Enable GDB server stub (pauses before first instruction)",
    )
    parser.add_argument(
        "--gdb-port",
        action="store",
        dest="gdb_port",
        type=int,
        default=1234,
        required=False,
        help="GDB server port (default: 1234)",
    )
    parser.add_argument(
        "-V",
        "--volume",
        action="append",
        dest="volumes",
        default=[],
        help="Mount a host path into the emulated filesystem (host_path:guest_path). May be repeated.",
    )

    config_specs = get_config_cli_field_specs()
    add_config_cli_arguments(parser, config_specs)

    args = parser.parse_args()
    if args.dump_default_config:
        print(json.dumps(get_default_config_dict(), indent=4))
        return
    run_main(parser, args, config_specs)


if __name__ == "__main__":
    main()
