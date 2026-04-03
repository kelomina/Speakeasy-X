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


class CodeEmulator(FakeEmulator):
    def __init__(self, code_map=None, register_values=None):
        super().__init__()
        self.code_map = code_map or {}
        self.register_values = register_values or {}

    def reg_read(self, reg_name):
        if reg_name in self.register_values:
            return self.register_values[reg_name]
        return super().reg_read(reg_name)

    def mem_read(self, address, size):
        if address in self.code_map:
            return self.code_map[address]
        return super().mem_read(address, size)


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

    assert compacted[0]["pseudocode"] == "call InitializeCriticalSection"
    assert compacted[0]["target_symbol"] == "InitializeCriticalSection"


def test_pseudocode_renderer_folds_movzx_cmp_add_loop_pattern():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {"address": "0x20", "pseudocode": "al = src", "assembly": "movzx eax, byte ptr [rsi]", "context": [], "filtered": False},
        {"address": "0x21", "pseudocode": "compare(src, al)", "assembly": "cmp byte ptr [rdi], al", "context": [], "filtered": False},
        {"address": "0x22", "pseudocode": "rsi = rsi + 1", "assembly": "add rsi, 1", "context": [], "filtered": False},
        {"address": "0x23", "pseudocode": "rdi = rdi + 1", "assembly": "sub rdi, -1", "context": [], "filtered": False},
        {"address": "0x24", "pseudocode": "al = src", "assembly": "movzx eax, byte ptr [rsi]", "context": [], "filtered": False},
        {"address": "0x25", "pseudocode": "compare(src, al)", "assembly": "cmp byte ptr [rdi], al", "context": [], "filtered": False},
        {"address": "0x26", "pseudocode": "rsi = rsi + 1", "assembly": "add rsi, 1", "context": [], "filtered": False},
        {"address": "0x27", "pseudocode": "rdi = rdi + 1", "assembly": "sub rdi, -1", "context": [], "filtered": False},
    ]

    compacted = renderer.compact_instruction_records(records)

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "strcmp(/* repeated block x8 */)"


def test_pseudocode_renderer_recovers_function_alias_from_string_context():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {
            "address": "0x30",
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
            "address": "0x31",
            "pseudocode": 'filePath = "C:\\\\temp\\\\a.txt"',
            "assembly": "mov rcx, 0x7000",
            "context": [],
            "filtered": False,
            "target_symbol": None,
            "string_value": "C:\\temp\\a.txt",
            "object_display": None,
            "register_values": {},
            "variable_aliases": {"rcx": "filePath"},
        },
        {
            "address": "0x32",
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

    assert compacted[0]["pseudocode"] == "call OpenFile"
    assert compacted[0]["target_symbol"] == "OpenFile"


def test_pseudocode_renderer_recovers_while_from_repeated_condition_block():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {"address": "0x40", "pseudocode": "rbx = rbx + 0x10", "assembly": "add rbx, 0x10", "context": [], "filtered": False},
        {"address": "0x41", "pseudocode": "compare(rbx, rsi)", "assembly": "cmp rbx, rsi", "context": [], "filtered": False},
        {"address": "0x42", "pseudocode": "if (rbx != rsi)", "assembly": "jne 0x40", "context": [], "filtered": False},
        {"address": "0x43", "pseudocode": "rbx = rbx + 0x10", "assembly": "add rbx, 0x10", "context": [], "filtered": False},
        {"address": "0x44", "pseudocode": "compare(rbx, rsi)", "assembly": "cmp rbx, rsi", "context": [], "filtered": False},
        {"address": "0x45", "pseudocode": "if (rbx != rsi)", "assembly": "jne 0x43", "context": [], "filtered": False},
    ]

    compacted = renderer.compact_instruction_records(records)

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "while (rbx != rsi)"
    assert compacted[0]["target_symbol"] == "while"


def test_pseudocode_renderer_avoids_thisobj_alias_for_plain_ecx_immediate():
    emu = CodeEmulator(code_map={0x500000: bytes.fromhex("b9 01 00 00 00")}, register_values={"ecx": 1})
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    record = renderer.render_instruction_record(0x500000, 5)

    assert record is not None
    assert record["pseudocode"] == "arg_1 = 0x1"
    assert record["object_display"] is None
    assert record["variable_aliases"]["ecx"] == "arg_1"


def test_pseudocode_renderer_prunes_stack_noise_and_stack_spill_moves():
    emu = CodeEmulator(code_map={0x500100: bytes.fromhex("48 89 5c 24 08")})
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    spill_record = renderer.render_instruction_record(0x500100, 5)
    compacted = renderer.compact_instruction_records(
        [
            {
                "address": "0x500200",
                "pseudocode": None,
                "assembly": "sub rsp, 0x28",
                "context": [],
                "filtered": True,
                "target_symbol": None,
                "string_value": None,
                "object_display": None,
                "register_values": {},
                "variable_aliases": {},
            },
            {
                "address": "0x500204",
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
        ]
    )

    assert spill_record is None
    assert len(compacted) == 1
    assert compacted[0]["assembly"] == "call 0x14001e528"


def test_pseudocode_renderer_recovers_while_from_backward_jump_loop():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {"address": "0x1400336b2", "pseudocode": "test(al, al)", "assembly": "test al, al", "context": [], "filtered": False},
        {"address": "0x1400336b4", "pseudocode": "if (al == 0)", "assembly": "je 0x1400336bf", "context": [], "filtered": False},
        {"address": "0x1400336b6", "pseudocode": "rbx = rbx + 0x10", "assembly": "add rbx, 0x10", "context": [], "filtered": False},
        {"address": "0x1400336ba", "pseudocode": "compare(rbx, rsi)", "assembly": "cmp rbx, rsi", "context": [], "filtered": False},
        {"address": "0x1400336bd", "pseudocode": "if (rbx != rsi)", "assembly": "jne 0x1400336a5", "context": [], "filtered": False},
        {"address": "0x1400336a5", "pseudocode": "retVal = emu.module.vhdx_backup.0x140000000", "assembly": "mov rax, qword ptr [rbx]", "context": [], "filtered": False},
    ]

    compacted = renderer.compact_instruction_records(records)

    assert compacted[0]["pseudocode"] == "test(al, al)"
    assert compacted[1]["pseudocode"] == "if (al == 0)"
    assert compacted[2]["pseudocode"] == "while (rbx != rsi)"
    assert compacted[2]["target_symbol"] == "while"


def test_pseudocode_renderer_scores_function_alias_from_multiple_contexts():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = [
        {
            "address": "0x50",
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
            "address": "0x51",
            "pseudocode": "call kernel32.GetProcAddress",
            "assembly": "call qword ptr [rip+0x20]",
            "context": [],
            "filtered": False,
            "target_symbol": "kernel32.GetProcAddress",
            "string_value": None,
            "object_display": None,
            "register_values": {},
            "variable_aliases": {"rcx": "filePath"},
        },
        {
            "address": "0x52",
            "pseudocode": "retVal = filePath",
            "assembly": "mov rax, rcx",
            "context": [],
            "filtered": False,
            "target_symbol": None,
            "string_value": "C:\\temp\\b.txt",
            "object_display": None,
            "register_values": {},
            "variable_aliases": {"rcx": "filePath"},
        },
        {
            "address": "0x53",
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

    assert compacted[0]["pseudocode"] == "call OpenFile"
    assert compacted[0]["target_symbol"] == "OpenFile"


def test_profiler_text_includes_function_block_header():
    profiler = Profiler()
    profiler.attach_emulator(FakeEmulator())
    profiler.enable_pseudocode(enable_heuristics=True)
    run = Run()
    run.start_addr = 0x401000
    run.type = "entry_point"
    run.instruction_trace.append(
        {
            "address": "0x401000",
            "pseudocode": "call InitializeCriticalSectionEx",
            "assembly": "call qword ptr [rcx+8]",
            "context": [],
            "filtered": False,
            "target_symbol": "InitializeCriticalSectionEx",
            "string_value": None,
            "object_display": "this(vtable=vtable)",
            "register_values": {},
            "variable_aliases": {"rcx": "thisObj", "rdx": "arg_2", "rax": "retVal"},
        }
    )
    profiler.add_run(run)

    text = profiler.get_pseudocode_text()

    assert "// function entry_point_0(thisObj, arg_2) -> retVal" in text
