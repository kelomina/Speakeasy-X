import speakeasy.winenv.arch as e_arch
from speakeasy.profiler import Profiler, Run
from speakeasy.profiler_events import (
    FILE_WRITE,
    REG_WRITE,
    FileWriteEvent,
    RegWriteValueEvent,
    TracePosition,
)
from speakeasy.pseudocode import PseudocodeRenderer
from speakeasy.windows.fileman import File


def build_report(profiler: Profiler, run: Run):
    run.args = []
    run.start_addr = 0x401000
    run.type = "entry_point"
    profiler.add_run(run)
    profiler.stop_run_clock()
    return profiler.get_report()


class FakeEmulator:
    def __init__(self):
        self.import_table = {}
        self.curr_mod = None

    def get_arch(self):
        return e_arch.ARCH_AMD64

    def get_ptr_size(self):
        return 8

    def reg_read(self, reg_name):
        values = {
            "rcx": 0x5000,
            "rax": 0x1234,
            "rbp": 0x7000,
        }
        return values.get(reg_name, 0)

    def mem_read(self, address, size):
        if address == 0x5000:
            return (0x9000).to_bytes(8, "little")
        if address == 0x5008:
            return (0x401000).to_bytes(8, "little")
        if address == 0x7000 - 0x20:
            return b"C:\\tmp\\a.txt\x00".ljust(size, b"\x00")
        if address == 0x401000:
            return b"\x90" * size
        return b"\x00" * size

    def read_mem_string(self, address, width=1, max_chars=64):
        if address == 0x7000 - 0x20:
            return "C:\\tmp\\a.txt"
        return ""

    def get_symbol_from_address(self, address):
        if address == 0x401000:
            return "kernel32.InitializeCriticalSectionEx"
        return None

    def get_address_tag(self, address):
        if address == 0x5000:
            return "this"
        if address == 0x9000:
            return "vtable"
        return None

    def get_mod_from_addr(self, address):
        return None


def test_dropped_file_embeds_data_ref_when_within_limit():
    profiler = Profiler()
    run = Run()
    file_obj = File("C:\\temp\\drop.bin", data=b"payload")

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == 7
    assert dropped.data_ref == dropped.sha256
    assert dropped.data_ref in report.data


def test_dropped_file_skips_large_embedded_payload():
    profiler = Profiler()
    run = Run()
    payload = b"A" * ((10 * 1024 * 1024) + 1)
    file_obj = File("C:\\temp\\large.bin", data=payload)

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == len(payload)
    assert dropped.data_ref is None
    assert dropped.sha256 not in (report.data or {})


def test_file_write_merge_preserves_raw_bytes():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", FILE_WRITE, data=b"\x00\xff", size=2)
    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", FILE_WRITE, data=b"\x01\x02", size=2)
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, FileWriteEvent))
    assert event.size == 4
    assert event.data_ref in report.data
    artifact = profiler.artifact_store.get_bytes(event.data_ref)
    assert artifact == b"\x00\xff\x01\x02"


def test_registry_write_event_is_reported_with_data_ref():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_registry_access_event(
        run,
        pos,
        "HKEY_LOCAL_MACHINE\\Software\\Example",
        REG_WRITE,
        value_name="ValueName",
        data=b"abc",
        size=3,
    )
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, RegWriteValueEvent))
    assert event.value_name == "ValueName"
    assert event.data_ref in report.data
    assert profiler.artifact_store.get_bytes(event.data_ref) == b"abc"


def test_pseudocode_renderer_supports_aliases_and_repeated_block_folding():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, show_register_values=True, enable_heuristics=True)

    records = [
        {
            "address": "0x401000",
            "pseudocode": "movsb()",
            "assembly": "movsb",
            "context": ["rcx.this=this(vtable=vtable)"],
            "filtered": False,
            "target_symbol": None,
            "string_value": None,
            "object_display": "this(vtable=vtable)",
            "register_values": {"rcx": "0x5000"},
            "variable_aliases": {"rcx": "thisObj"},
        },
        {
            "address": "0x401001",
            "pseudocode": "movsb()",
            "assembly": "movsb",
            "context": [],
            "filtered": False,
            "target_symbol": None,
            "string_value": None,
            "object_display": None,
            "register_values": {"rcx": "0x5000"},
            "variable_aliases": {"rcx": "thisObj"},
        },
    ]

    compacted = renderer.compact_instruction_records(records)

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "memcpy(/* repeated block x2 */)"
    assert compacted[0]["target_symbol"] == "memcpy"


def test_profiler_xml_includes_object_display_and_register_values():
    profiler = Profiler()
    profiler.attach_emulator(FakeEmulator())
    profiler.enable_pseudocode(show_register_values=True, enable_heuristics=True)
    run = Run()
    run.start_addr = 0x401000
    run.type = "entry_point"
    run.instruction_trace.append(
        {
            "address": "0x401000",
            "pseudocode": "call kernel32.InitializeCriticalSectionEx",
            "assembly": "call qword ptr [rcx+8]",
            "context": ["rcx.this=this(vtable=vtable)"],
            "filtered": False,
            "target_symbol": "kernel32.InitializeCriticalSectionEx",
            "string_value": None,
            "object_display": "this(vtable=vtable)",
            "register_values": {"rcx": "0x5000"},
            "variable_aliases": {"rcx": "thisObj"},
        }
    )
    profiler.add_run(run)

    xml = profiler.get_pseudocode_visual("xml")

    assert "<object_display>this(vtable=vtable)</object_display>" in xml
    assert '<register name="rcx">0x5000</register>' in xml
    assert '<alias name="rcx">thisObj</alias>' in xml


def test_pseudocode_renderer_folds_handwritten_copy_loop_pattern():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {"address": "0x1", "pseudocode": "al = src", "assembly": "mov al, byte ptr [rsi]", "context": [], "filtered": False},
        {"address": "0x2", "pseudocode": "dst = al", "assembly": "mov byte ptr [rdi], al", "context": [], "filtered": False},
        {"address": "0x3", "pseudocode": "rsi = rsi + 1", "assembly": "inc rsi", "context": [], "filtered": False},
        {"address": "0x4", "pseudocode": "rdi = rdi + 1", "assembly": "inc rdi", "context": [], "filtered": False},
        {"address": "0x5", "pseudocode": "al = src", "assembly": "mov al, byte ptr [rsi]", "context": [], "filtered": False},
        {"address": "0x6", "pseudocode": "dst = al", "assembly": "mov byte ptr [rdi], al", "context": [], "filtered": False},
        {"address": "0x7", "pseudocode": "rsi = rsi + 1", "assembly": "inc rsi", "context": [], "filtered": False},
        {"address": "0x8", "pseudocode": "rdi = rdi + 1", "assembly": "inc rdi", "context": [], "filtered": False},
    ]

    compacted = renderer.compact_instruction_records(records)

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "memcpy(/* repeated block x8 */)"


def test_pseudocode_renderer_recovers_function_alias_from_import_context():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {
            "address": "0x10",
            "pseudocode": "call function_1",
            "assembly": "call 0x14001e528",
            "context": [],
            "filtered": False,
            "target_symbol": None,
            "string_value": None,
            "object_display": None,
            "register_values": {},
            "variable_aliases": {},
        },
        {
            "address": "0x11",
            "pseudocode": "call kernel32.InitializeCriticalSectionEx",
            "assembly": "call qword ptr [rip+0x20]",
            "context": [],
            "filtered": False,
            "target_symbol": "kernel32.InitializeCriticalSectionEx",
            "string_value": None,
            "object_display": None,
            "register_values": {},
            "variable_aliases": {},
        },
        {
            "address": "0x12",
            "pseudocode": "return",
            "assembly": "ret",
            "context": [],
            "filtered": False,
            "target_symbol": None,
            "string_value": None,
            "object_display": None,
            "register_values": {},
            "variable_aliases": {},
        },
    ]

    compacted = renderer.compact_instruction_records(records)

    assert compacted[0]["pseudocode"] == "call InitializeCriticalSectionEx"
    assert compacted[0]["target_symbol"] == "InitializeCriticalSectionEx"
