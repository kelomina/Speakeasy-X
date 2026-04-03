# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Data format versioning
__report_version__ = "3.0.0"

import hashlib
import time
import urllib.parse
import weakref
from collections import deque
from typing import Any
from xml.sax.saxutils import escape

from speakeasy.artifacts import MAX_EMBEDDED_FILE_SIZE, ArtifactStore
from speakeasy.pseudocode import PseudocodeRenderer
from speakeasy.profiler_events import (
    FILE_CREATE,
    FILE_OPEN,
    FILE_READ,
    FILE_WRITE,
    MEM_ALLOC,
    MEM_FREE,
    MEM_PROTECT,
    MEM_READ,
    MEM_WRITE,
    PROC_CREATE,
    REG_CREATE,
    REG_LIST,
    REG_OPEN,
    REG_READ,
    REG_WRITE,
    THREAD_CREATE,
    THREAD_INJECT,
    AnyEvent,
    ApiEvent,
    ExceptionEvent,
    FileCreateEvent,
    FileOpenEvent,
    FileReadEvent,
    FileWriteEvent,
    MemAllocEvent,
    MemFreeEvent,
    MemProtectEvent,
    MemReadEvent,
    MemWriteEvent,
    ModuleLoadEvent,
    NetDnsEvent,
    NetHttpEvent,
    NetTrafficEvent,
    ProcessCreateEvent,
    RegCreateKeyEvent,
    RegListSubkeysEvent,
    RegOpenKeyEvent,
    RegReadValueEvent,
    RegWriteValueEvent,
    ThreadCreateEvent,
    ThreadInjectEvent,
    TracePosition,
)
from speakeasy.report import (
    DroppedFile,
    DynamicCodeSegment,
    EntryPoint,
    ErrorInfo,
    LoadedModule,
    MemoryAccesses,
    MemoryLayout,
    MemoryRegion,
    ModuleSegment,
    Report,
    StringCollection,
    StringsReport,
    SymAccessReport,
)


class ProfileError(Exception):
    pass


class MemAccess:
    """
    Represents a symbolicated chunk of memory that can be tracked
    """

    def __init__(self, base=None, sym=None, size=0):
        self.base = base
        self.size = size
        self.sym = sym
        self.reads = 0
        self.writes = 0
        self.execs = 0


class Run:
    """
    This class represents the basic execution primative for the emulation engine
    A "run" can represent any form of execution: a thread, a callback, an exported function,
    or even a child process.
    """

    def __init__(self):
        self.instr_cnt: int = 0
        self.ret_val: int | None = None
        self.events: list[AnyEvent] = []
        self.sym_access: dict[int, MemAccess] = {}
        self.dropped_files: list[dict[str, Any]] = []
        self.mem_access: dict[Any, MemAccess] = {}
        self.section_access: dict[tuple[int, int], MemAccess] = {}
        self.dyn_code: dict[str, list[dict[str, int | str]] | set[int]] = {"mmap": [], "base_addrs": set()}
        self.process_context: Any | None = None
        self.thread: Any | None = None
        self.unique_apis: list[str] = []
        self.api_hash = hashlib.sha256()
        self.stack: MemAccess | None = None
        self.api_callbacks: list[tuple[int, str, list[Any] | tuple[Any, ...]]] = []
        self.exec_cache: deque[MemAccess] = deque(maxlen=4)
        self.read_cache: deque[MemAccess] = deque(maxlen=4)
        self.write_cache: deque[MemAccess] = deque(maxlen=4)

        self.args: list[Any] | tuple[Any, ...] | None = None
        self.start_addr: int | None = None
        self.type: str | int | None = None
        self.error: ErrorInfo | None = None
        self.num_apis: int = 0
        self.coverage: set[int] = set()
        self.instruction_trace: list[dict[str, Any]] = []
        self.memory_regions: list[dict[str, Any]] = []
        self.loaded_modules: list[dict[str, Any]] = []

    def get_api_count(self):
        """
        Get the number of APIs that were called during the run
        """
        return self.num_apis


class Profiler:
    """
    The profiler class exists to generate an execution report
    for all runs that occur within a binary emulation.
    """

    def __init__(self):
        super().__init__()

        self.start_time: float = 0
        self.strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
        self.decoded_strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
        self.last_data: list[int] = [0, 0]
        self.last_event: AnyEvent | dict[str, Any] = {}
        self.set_start_time()
        self.runtime: float = 0
        self.meta: dict[str, Any] = {}
        self.runs: list[Run] = []
        self.artifact_store = ArtifactStore()
        self.emulator_ref: weakref.ReferenceType[Any] | None = None
        self.pseudocode_enabled: bool = False
        self.pseudocode_include_comments: bool = True
        self.pseudocode_string_encoding: str = "utf8"
        self.pseudocode_keep_filtered_jumps: bool = False
        self.pseudocode_show_register_values: bool = False
        self.pseudocode_enable_heuristics: bool = False
        self.pseudocode_renderer: PseudocodeRenderer | None = None

    def attach_emulator(self, emulator: Any) -> None:
        self.emulator_ref = weakref.ref(emulator)

    def enable_pseudocode(
        self,
        enabled: bool = True,
        include_comments: bool = True,
        string_encoding: str = "utf8",
        keep_filtered_jumps: bool = False,
        show_register_values: bool = False,
        enable_heuristics: bool = False,
    ) -> None:
        self.pseudocode_enabled = enabled
        self.pseudocode_include_comments = include_comments
        self.pseudocode_string_encoding = string_encoding
        self.pseudocode_keep_filtered_jumps = keep_filtered_jumps
        self.pseudocode_show_register_values = show_register_values
        self.pseudocode_enable_heuristics = enable_heuristics
        self.pseudocode_renderer = None

    def is_pseudocode_enabled(self) -> bool:
        return self.pseudocode_enabled

    def get_emulator(self) -> Any | None:
        if self.emulator_ref is None:
            return None
        return self.emulator_ref()

    def get_pseudocode_renderer(self) -> PseudocodeRenderer | None:
        if not self.pseudocode_enabled:
            return None
        if self.pseudocode_renderer is not None:
            return self.pseudocode_renderer
        emulator = self.get_emulator()
        if emulator is None:
            return None
        self.pseudocode_renderer = PseudocodeRenderer(
            emulator,
            include_comments=self.pseudocode_include_comments,
            string_encoding=self.pseudocode_string_encoding,
            keep_filtered_jumps_in_comments=self.pseudocode_keep_filtered_jumps,
            show_register_values=self.pseudocode_show_register_values,
            enable_heuristics=self.pseudocode_enable_heuristics,
        )
        return self.pseudocode_renderer

    def record_instruction(self, run: Run | None, address: int, size: int) -> None:
        if run is None:
            return
        renderer = self.get_pseudocode_renderer()
        if renderer is None:
            return
        record = renderer.render_instruction_record(address, size)
        if record:
            run.instruction_trace.append(record)

    def get_pseudocode_lines(self) -> list[str]:
        lines: list[str] = []
        include_headers = sum(1 for run in self.runs if run.instruction_trace) > 1
        renderer = self.get_pseudocode_renderer()
        for index, run in enumerate(self.runs):
            if not run.instruction_trace:
                continue
            if include_headers:
                start_addr = hex(run.start_addr) if run.start_addr is not None else "unknown"
                lines.append(f"// entry_point[{index}] start={start_addr} type={run.type}")
            processed_records = self._get_processed_instruction_trace(run, renderer)
            function_info = self._describe_function_block(index, processed_records)
            if function_info:
                params = ", ".join(function_info["params"])
                returns = ", ".join(function_info["returns"]) if function_info["returns"] else "void"
                lines.append(f"// function {function_info['name']}({params}) -> {returns}")
            for record in processed_records:
                if renderer is None:
                    continue
                line = renderer.format_instruction_record(record)
                if line:
                    lines.append(line)
            if include_headers:
                lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        return lines

    def get_pseudocode_text(self) -> str:
        return "\n".join(self.get_pseudocode_lines())

    def get_pseudocode_visual(self, format_name: str = "svg") -> str:
        lines = self.get_pseudocode_lines()
        format_name = format_name.lower()
        if format_name == "svg":
            return self._render_pseudocode_svg(lines)
        if format_name == "xml":
            return self._render_pseudocode_xml(lines)
        raise ProfileError(f"Unsupported pseudocode visual format: {format_name}")

    def _render_pseudocode_xml(self, lines: list[str]) -> str:
        stylesheet = (
            "pseudocode{display:block;font-family:Consolas,monospace;background:#0f172a;color:#e2e8f0;"
            "padding:16px} entry{display:block;margin:0 0 18px 0;padding:12px;border:1px solid #334155}"
            " line{display:block;margin:8px 0;padding:8px;background:#111827;border-left:3px solid #475569}"
            " address,pseudocode_text,assembly,filtered,target_symbol,string_value,context,item{display:block;"
            "white-space:pre-wrap} address{color:#93c5fd} pseudocode_text{color:#f8fafc}"
            " assembly{color:#cbd5e1} filtered{color:#fbbf24} target_symbol{color:#86efac}"
            " string_value{color:#f9a8d4} context{margin-top:4px;color:#94a3b8} item{margin-left:16px}"
        )
        stylesheet_href = "data:text/css," + urllib.parse.quote(stylesheet, safe="")
        rendered = [
            '<?xml version="1.0" encoding="utf-8"?>',
            f'<?xml-stylesheet type="text/css" href="{stylesheet_href}"?>',
            "<pseudocode>",
        ]
        line_index = 1
        for run_index, run in enumerate(self.runs):
            if not run.instruction_trace:
                continue
            start_addr = hex(run.start_addr) if run.start_addr is not None else "unknown"
            rendered.append(f'  <entry index="{run_index}" start="{escape(start_addr)}" type="{escape(str(run.type))}">')
            processed_records = self._get_processed_instruction_trace(run, self.get_pseudocode_renderer())
            function_info = self._describe_function_block(run_index, processed_records)
            if function_info:
                rendered.append(f'    <function name="{escape(function_info["name"])}">')
                rendered.append("      <params>")
                for param in function_info["params"]:
                    rendered.append(f"        <param>{escape(param)}</param>")
                rendered.append("      </params>")
                rendered.append("      <returns>")
                for ret in function_info["returns"]:
                    rendered.append(f"        <value>{escape(ret)}</value>")
                rendered.append("      </returns>")
                rendered.append("    </function>")
            for record in processed_records:
                rendered.append(
                    '    <line index="{index}" filtered="{filtered}">'.format(
                        index=line_index,
                        filtered=str(bool(record.get("filtered"))).lower(),
                    )
                )
                rendered.append(f'      <address>{escape(str(record.get("address", "")))}</address>')
                rendered.append(f'      <pseudocode_text>{escape(str(record.get("pseudocode") or ""))}</pseudocode_text>')
                rendered.append(f'      <assembly>{escape(str(record.get("assembly") or ""))}</assembly>')
                rendered.append(f'      <filtered>{escape(str(record.get("filtered") or False).lower())}</filtered>')
                rendered.append(f'      <target_symbol>{escape(str(record.get("target_symbol") or ""))}</target_symbol>')
                rendered.append(f'      <string_value>{escape(str(record.get("string_value") or ""))}</string_value>')
                rendered.append(f'      <object_display>{escape(str(record.get("object_display") or ""))}</object_display>')
                rendered.append("      <register_values>")
                for key, value in (record.get("register_values") or {}).items():
                    rendered.append(f'        <register name="{escape(str(key))}">{escape(str(value))}</register>')
                rendered.append("      </register_values>")
                rendered.append("      <variable_aliases>")
                for key, value in (record.get("variable_aliases") or {}).items():
                    rendered.append(f'        <alias name="{escape(str(key))}">{escape(str(value))}</alias>')
                rendered.append("      </variable_aliases>")
                rendered.append("      <context>")
                for item in record.get("context", []):
                    rendered.append(f"        <item>{escape(str(item))}</item>")
                rendered.append("      </context>")
                rendered.append("    </line>")
                line_index += 1
            rendered.append("  </entry>")
        rendered.append("</pseudocode>")
        return "\n".join(rendered)

    def _get_processed_instruction_trace(self, run: Run, renderer: PseudocodeRenderer | None) -> list[dict[str, Any]]:
        records = list(run.instruction_trace)
        if renderer is None:
            return records
        return renderer.compact_instruction_records(records)

    def _describe_function_block(self, run_index: int, records: list[dict[str, Any]]) -> dict[str, list[str] | str]:
        params: list[str] = []
        returns: list[str] = []
        for record in records:
            for value in (record.get("variable_aliases") or {}).values():
                if not isinstance(value, str):
                    continue
                if value == "thisObj" or value.startswith("arg_"):
                    if value not in params:
                        params.append(value)
                if value == "retVal" and value not in returns:
                    returns.append(value)
        return {
            "name": f"entry_point_{run_index}",
            "params": params,
            "returns": returns,
        }

    def _render_pseudocode_svg(self, lines: list[str]) -> str:
        font_size = 14
        line_height = 22
        padding_x = 20
        padding_y = 24
        max_len = max((len(line) for line in lines), default=0)
        width = max(800, padding_x * 2 + max_len * 9)
        height = max(120, padding_y * 2 + max(len(lines), 1) * line_height)
        rendered = [
            '<?xml version="1.0" encoding="utf-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="#0f172a"/>',
        ]
        for index, line in enumerate(lines, start=1):
            y = padding_y + index * line_height
            escaped = escape(line)
            rendered.append(
                f'<text x="{padding_x}" y="{y}" fill="#e2e8f0" font-family="Consolas, Menlo, monospace" '
                f'font-size="{font_size}">{escaped}</text>'
            )
        rendered.append("</svg>")
        return "\n".join(rendered)

    def add_input_metadata(self, meta):
        """
        Add top level profiler fields containing metadata for the
        module that will be emulated
        """
        self.meta = meta

    def set_start_time(self):
        """
        Get the start time for a sample so we can time the execution length
        """
        self.start_time = time.time()

    def get_run_time(self):
        """
        Get the time spent emulating a specific "run"
        """
        return time.time() - self.start_time

    def stop_run_clock(self):
        """
        Stop the runtime clock to include in the report
        """
        self.runtime = self.get_run_time()

    def get_epoch_time(self):
        """
        Get the current time in epoch format
        """
        return int(time.time())

    def add_run(self, run: Run) -> None:
        """
        Add a new run to the captured run list
        """
        self.runs.append(run)

    def put_binary_data(self, data: bytes, limit: int | None = None) -> str | None:
        """Store binary data and return its artifact reference."""
        if not data:
            return None
        payload = data[:limit] if limit else data
        return self.artifact_store.put_bytes(payload)

    def merge_binary_data(self, artifact_ref: str | None, data: bytes, limit: int | None = None) -> str | None:
        """Append raw bytes to an existing artifact payload and store the merged result."""
        if not data and artifact_ref:
            return artifact_ref
        if not artifact_ref:
            return self.put_binary_data(data, limit=limit)
        merged = self.artifact_store.get_bytes(artifact_ref) + data
        if limit:
            merged = merged[:limit]
        return self.artifact_store.put_bytes(merged)

    def record_error_event(self, error: ErrorInfo) -> None:
        """Log a top level emulator error for the emulation report."""
        if not self.meta.get("errors"):
            self.meta["errors"] = []
        self.meta["errors"].append(error)

    def record_dropped_files_event(self, run, files):
        for f in files:
            data = f.get_data()
            if data is None:
                continue

            _hash = f.get_hash()
            data_ref = None
            if len(data) <= MAX_EMBEDDED_FILE_SIZE:
                data_ref = self.artifact_store.put_bytes(data)
            entry = {"path": f.path, "size": len(data), "sha256": _hash, "data_ref": data_ref}
            run.dropped_files.append(entry)

    def record_api_event(self, run, pos: TracePosition, name, ret, argv):
        """
        Log a call to an OS API. This includes arguments, return address, and return value
        """
        run.num_apis += 1

        if name not in run.unique_apis:
            run.api_hash.update(name.lower().encode("utf-8"))
            run.unique_apis.append(name)

        ret_str = hex(ret) if ret is not None else None

        args = argv.copy()
        for i, arg in enumerate(args):
            if isinstance(arg, int):
                args[i] = hex(arg)

        event = ApiEvent(
            pos=pos,
            api_name=name,
            args=args,
            ret_val=ret_str,
        )

        recent_events = [e for e in run.events[-3:] if isinstance(e, ApiEvent)]
        if not any(
            e.pos.pc == event.pos.pc
            and e.api_name == event.api_name
            and e.args == event.args
            and e.ret_val == event.ret_val
            for e in recent_events
        ):
            run.events.append(event)

    def record_file_access_event(
        self,
        run,
        pos: TracePosition,
        path,
        event_type,
        data=None,
        handle=0,
        disposition=[],
        access=[],
        buffer=0,
        size=None,
    ):
        """
        Log file access events. This will include things like handles being opened,
        data reads, and data writes.
        """
        data_ref = self.put_binary_data(data or b"", limit=1024)

        for et in (FILE_WRITE, FILE_READ):
            if event_type == et:
                for evt in reversed(run.events):
                    if isinstance(evt, (FileWriteEvent, FileReadEvent)) and evt.path == path and evt.event == et:
                        if size:
                            evt.size = (evt.size or 0) + size
                        if data:
                            evt.data_ref = self.merge_binary_data(evt.data_ref, data, limit=1024)
                        return

        handle_str = hex(handle) if handle else None
        buffer_str = hex(buffer) if buffer else None

        open_flags = None
        if disposition:
            open_flags = disposition if isinstance(disposition, list) else [disposition]
        access_flags = None
        if access:
            access_flags = access if isinstance(access, list) else [access]

        event: AnyEvent
        if event_type == FILE_CREATE:
            event = FileCreateEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == FILE_OPEN:
            event = FileOpenEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == FILE_READ:
            event = FileReadEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                size=size,
                data_ref=data_ref,
                buffer=buffer_str,
            )
        elif event_type == FILE_WRITE:
            event = FileWriteEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                size=size,
                data_ref=data_ref,
                buffer=buffer_str,
            )
        else:
            return

        run.events.append(event)

    def record_registry_access_event(
        self,
        run,
        pos: TracePosition,
        path,
        event_type,
        value_name=None,
        data=None,
        handle=0,
        disposition=[],
        access=[],
        buffer=0,
        size=None,
    ):
        """
        Log registry access events. This includes values and keys being accessed and
        being read/written
        """
        data_ref = self.put_binary_data(data or b"", limit=1024)

        handle_str = hex(handle) if handle else None
        buffer_str = hex(buffer) if buffer else None

        open_flags = None
        if disposition:
            open_flags = disposition if isinstance(disposition, list) else [disposition]
        access_flags_list = None
        if access:
            access_flags_list = access if isinstance(access, list) else [access]

        event: AnyEvent
        if event_type == REG_OPEN:
            event = RegOpenKeyEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == REG_CREATE:
            event = RegCreateKeyEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == REG_READ:
            event = RegReadValueEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                value_name=value_name,
                size=size,
                data_ref=data_ref,
                buffer=buffer_str,
            )
        elif event_type == REG_WRITE:
            event = RegWriteValueEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                value_name=value_name,
                size=size,
                data_ref=data_ref,
                buffer=buffer_str,
            )
        elif event_type == REG_LIST:
            event = RegListSubkeysEvent(
                pos=pos,
                path=path,
                handle=handle_str,
            )
        else:
            return

        run.events.append(event)

    def record_process_event(self, run, pos: TracePosition, proc, event_type, kwargs):
        """
        Log events related to a process accessing another process. This includes:
        creating a child process, reading/writing to a process, or creating a thread
        within another process.
        """
        pid = proc.id
        path = proc.path
        proc_pos = TracePosition(tick=pos.tick, tid=pos.tid, pid=pid, pc=pos.pc)

        event: AnyEvent
        if event_type == PROC_CREATE:
            event = ProcessCreateEvent(
                pos=proc_pos,
                path=path,
                cmdline=proc.cmdline,
            )

        elif event_type == MEM_ALLOC:
            event = MemAllocEvent(
                pos=proc_pos,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
                protect=kwargs.get("protect"),
            )

        elif event_type == MEM_PROTECT:
            event = MemProtectEvent(
                pos=proc_pos,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
                protect=kwargs.get("protect"),
            )

        elif event_type == MEM_FREE:
            event = MemFreeEvent(
                pos=proc_pos,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
            )

        elif event_type == MEM_WRITE:
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            if isinstance(last_evt, MemWriteEvent) and (last_base + last_size) == base:
                last_evt.data_ref = self.merge_binary_data(last_evt.data_ref, data, limit=1024)
                last_evt.size += len(data)
                self.last_data = [base, size]
                return
            event = MemWriteEvent(
                pos=proc_pos,
                path=path,
                base=hex(base),
                size=size,
                data_ref=self.put_binary_data(data, limit=1024),
            )
            self.last_data = [base, size]

        elif event_type == MEM_READ:
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            if isinstance(last_evt, MemReadEvent) and (last_base + last_size) == base:
                last_evt.data_ref = self.merge_binary_data(last_evt.data_ref, data, limit=1024)
                last_evt.size += len(data)
                self.last_data = [base, size]
                return
            event = MemReadEvent(
                pos=proc_pos,
                path=path,
                base=hex(base),
                size=size,
                data_ref=self.put_binary_data(data, limit=1024),
            )
            self.last_data = [base, size]

        elif event_type == THREAD_INJECT:
            event = ThreadInjectEvent(
                pos=proc_pos,
                path=path,
                start_addr=hex(kwargs["start_addr"]),
                param=hex(kwargs["param"]),
            )

        elif event_type == THREAD_CREATE:
            event = ThreadCreateEvent(
                pos=proc_pos,
                path=path,
                start_addr=hex(kwargs["start_addr"]),
                param=hex(kwargs["param"]),
            )

        else:
            return

        run.events.append(event)
        self.last_event = event

    def record_dns_event(self, run, pos: TracePosition, domain, ip=""):
        """
        Log DNS name lookups for the emulation report
        """
        for evt in run.events:
            if isinstance(evt, NetDnsEvent) and evt.query == domain and evt.response == ip:
                return

        event = NetDnsEvent(
            pos=pos,
            query=domain,
            response=ip if ip else None,
        )
        run.events.append(event)

    def record_http_event(
        self, run, pos: TracePosition, server, port, proto="http", headers="", body=b"", secure=False
    ):
        """
        Log HTTP traffic that occur during emulation
        """
        proto_str = "https" if secure else "http"
        body_ref = self.put_binary_data(body or b"", limit=0x3000)

        event = NetHttpEvent(
            pos=pos,
            server=server,
            port=port,
            proto=f"tcp.{proto_str}",
            headers=headers if headers else None,
            body_ref=body_ref,
        )

        for evt in run.events:
            if (
                isinstance(evt, NetHttpEvent)
                and evt.server == event.server
                and evt.port == event.port
                and evt.proto == event.proto
                and evt.headers == event.headers
            ):
                return

        run.events.append(event)

    def record_dyn_code_event(self, run, tag, base, size):
        """
        Log code that is generated at runtime and then executed
        """
        if base not in run.dyn_code["base_addrs"]:
            entry = {"tag": tag, "base": hex(base), "size": hex(size)}
            run.dyn_code["mmap"].append(entry)
            run.dyn_code["base_addrs"].add(base)

    def record_network_event(
        self, run, pos: TracePosition, server, port, typ="unknown", proto="unknown", data=b"", method=""
    ):
        """
        Log network activity for an emulation run
        """
        data_ref = self.put_binary_data(data or b"", limit=0x3000)

        event = NetTrafficEvent(
            pos=pos,
            server=server,
            port=port,
            proto=proto,
            type=typ if typ != "unknown" else None,
            data_ref=data_ref,
            method=method if method else None,
        )
        run.events.append(event)

    def record_exception_event(
        self,
        run,
        pos: TracePosition,
        instr,
        exception_code,
        handler_address,
        registers,
        faulting_address=None,
        pc_module=None,
        stack_trace=None,
    ):
        """Log a handled exception event."""
        event = ExceptionEvent(
            pos=pos,
            instr=instr,
            exception_code=hex(exception_code),
            handler_address=hex(handler_address),
            registers=registers,
            faulting_address=faulting_address,
            pc_module=pc_module,
            stack_trace=stack_trace,
        )
        run.events.append(event)

    def record_module_load_event(self, run, pos: TracePosition, name, path, base, size):
        """
        Log module (PE/DLL) load events
        """
        event = ModuleLoadEvent(
            pos=pos,
            name=name,
            path=path,
            base=hex(base),
            size=hex(size),
        )
        run.events.append(event)

    def get_json_report(self) -> str:
        """
        Retrieve the execution profile for the emulator as a json string
        """
        report = self.get_report()
        return report.model_dump_json(indent=4, exclude_none=True)

    def get_report(self) -> Report:
        """
        Retrieve the execution profile for the emulator
        """
        entry_points = []

        for r in self.runs:
            args: list[Any] = []
            for a in r.args or []:
                if isinstance(a, int):
                    args.append(hex(a))
                else:
                    args.append(a)

            error_info = r.error

            events = None
            if r.events:
                events = list(r.events)

            sym_accesses: list[SymAccessReport] | None = None
            if r.sym_access:
                sym_accesses = []
                for address, maccess in r.sym_access.items():
                    sym_accesses.append(
                        SymAccessReport(
                            symbol=maccess.sym,
                            reads=maccess.reads,
                            writes=maccess.writes,
                            execs=maccess.execs,
                        )
                    )
                if not sym_accesses:
                    sym_accesses = None

            dyn_code_segments = None
            if r.dyn_code and r.dyn_code.get("mmap"):
                dyn_code_segments = [
                    DynamicCodeSegment(tag=seg["tag"], base=seg["base"], size=seg["size"]) for seg in r.dyn_code["mmap"]
                ]

            dropped_files = None
            if r.dropped_files:
                dropped_files = [
                    DroppedFile(path=f["path"], size=f["size"], sha256=f["sha256"], data_ref=f.get("data_ref"))
                    for f in r.dropped_files
                ]

            memory_layout = None
            if r.memory_regions or r.loaded_modules:
                regions = []
                for reg in r.memory_regions:
                    accesses = None
                    if reg.get("accesses"):
                        accesses = MemoryAccesses(
                            reads=reg["accesses"]["reads"],
                            writes=reg["accesses"]["writes"],
                            execs=reg["accesses"]["execs"],
                        )
                    regions.append(
                        MemoryRegion(
                            tag=reg["tag"],
                            address=reg["address"],
                            size=reg["size"],
                            prot=reg["prot"],
                            is_free=reg.get("is_free", False),
                            accesses=accesses,
                            data_ref=reg.get("data_ref"),
                        )
                    )
                modules = []
                for mod in r.loaded_modules:
                    segs = [
                        ModuleSegment(
                            name=seg["name"],
                            address=seg["address"],
                            size=seg["size"],
                            prot=seg["prot"],
                        )
                        for seg in mod.get("segments", [])
                    ]
                    modules.append(
                        LoadedModule(
                            name=mod["name"],
                            path=mod["path"],
                            base=mod["base"],
                            size=mod["size"],
                            segments=segs,
                        )
                    )
                memory_layout = MemoryLayout(layout=regions, modules=modules)

            ep_tid = r.thread.tid if r.thread else None
            ep_pid = None
            if r.process_context:
                ep_pid = r.process_context.id
            elif r.thread and r.thread.process:
                ep_pid = r.thread.process.id

            ep = EntryPoint(
                ep_type=str(r.type) if r.type is not None else "",
                start_addr=r.start_addr,
                ep_args=args,
                pid=ep_pid,
                tid=ep_tid,
                instr_count=r.instr_cnt if r.instr_cnt else None,
                apihash=r.api_hash.hexdigest(),
                ret_val=r.ret_val,
                error=error_info,
                events=events,
                sym_accesses=sym_accesses,
                dynamic_code_segments=dyn_code_segments,
                coverage=sorted(r.coverage) if r.coverage else None,
                dropped_files=dropped_files,
                memory=memory_layout,
            )
            entry_points.append(ep)

        strings_report = None
        if (
            self.strings["ansi"]
            or self.strings["unicode"]
            or self.decoded_strings["ansi"]
            or self.decoded_strings["unicode"]
        ):
            strings_report = StringsReport(
                static=StringCollection(
                    ansi=self.strings["ansi"],
                    unicode=self.strings["unicode"],
                ),
                in_memory=StringCollection(
                    ansi=self.decoded_strings["ansi"],
                    unicode=self.decoded_strings["unicode"],
                ),
            )

        errors: list[ErrorInfo] | None = self.meta.get("errors") or None

        report_data = self.artifact_store.to_report_data()
        report = Report(
            report_version=__report_version__,
            emulation_total_runtime=round(self.runtime, 3),
            timestamp=int(self.start_time),
            arch=self.meta.get("arch"),
            filepath=self.meta.get("filepath"),
            sha256=self.meta.get("sha256"),
            size=self.meta.get("size"),
            filetype=self.meta.get("filetype"),
            image_base=self.meta.get("image_base"),
            errors=errors,
            strings=strings_report,
            data=report_data or None,
            entry_points=entry_points,
        )
        return report
