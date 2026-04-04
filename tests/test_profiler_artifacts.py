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


class ModuleAliasEmulator(FakeEmulator):
    def get_address_tag(self, address):
        if address == 0x1400520C0:
            return "emu.module.Quark_V6.6.5.788@@@dapi-5c2038ea-d570-466b-9653-09c7bb972487@@@.0x140000000"
        return super().get_address_tag(address)

    def get_mod_from_addr(self, address):
        if address == 0x1400520C0:
            return type("Module", (), {"base": 0x140000000})()
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


def test_pseudocode_renderer_normalizes_module_alias_name():
    emu = ModuleAliasEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    alias = renderer._get_memory_alias("", 0, 0x1400520C0, None, None)

    assert alias == "g_Quark_V6_6_5_788_dapi_520c0"


def test_pseudocode_renderer_folds_repeated_summary_records():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x1", "pseudocode": "while (rbx != rsi)", "assembly": "while_backedge x3", "context": [], "filtered": False, "target_symbol": "while"},
            {"address": "0x2", "pseudocode": "while (rbx != rsi)", "assembly": "while_backedge x3", "context": [], "filtered": False, "target_symbol": "while"},
            {"address": "0x3", "pseudocode": "while (rbx != rsi)", "assembly": "while_backedge x3", "context": [], "filtered": False, "target_symbol": "while"},
        ]
    )

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "while (rbx != rsi)"
    assert compacted[0]["assembly"] == "while_repeat x3"
    assert "repeated x3" in compacted[0]["context"]


def test_pseudocode_renderer_recovers_global_alias_from_xchg_context():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x10", "pseudocode": "xchg(g_slot_1, FlsAlloc)", "assembly": "xchg [rip+0x20], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x11", "pseudocode": "call g_slot_1", "assembly": "call qword ptr [rip+0x20]", "context": [], "filtered": False, "target_symbol": "g_slot_1"},
        ]
    )

    assert compacted[0]["pseudocode"] == "xchg(g_FlsSlotIndex, FlsAlloc)"
    assert compacted[1]["pseudocode"] == "call g_FlsSlotIndex"
    assert compacted[1]["target_symbol"] == "g_FlsSlotIndex"


def test_pseudocode_renderer_recovers_global_alias_from_recent_call_retval_store():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x20", "pseudocode": "call LoadLibraryEx", "assembly": "call 0x14002d05d", "context": [], "filtered": False, "target_symbol": "LoadLibraryEx"},
            {"address": "0x21", "pseudocode": "g_slot_2 = retVal", "assembly": "mov qword ptr [rip+0x28], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x22", "pseudocode": "retVal = g_slot_2", "assembly": "mov rax, qword ptr [rip+0x28]", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[1]["pseudocode"] == "g_LoadedModuleHandle = retVal"
    assert compacted[2]["pseudocode"] == "retVal = g_LoadedModuleHandle"


def test_pseudocode_renderer_recovers_global_alias_from_api_assignment():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {
                "address": "0x30",
                "pseudocode": "g_slot_3 = api.command_line.kernel32.GetCommandLineA.0x90a0",
                "assembly": "mov qword ptr [rip+0x30], rax",
                "context": [],
                "filtered": False,
                "target_symbol": None,
            }
        ]
    )

    assert compacted[0]["pseudocode"] == "g_CommandLineBufferA = api.command_line.kernel32.GetCommandLineA.0x90a0"


def test_pseudocode_renderer_recovers_global_alias_from_api_assignment_wide():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {
                "address": "0x31",
                "pseudocode": "g_slot_4 = api.command_line.kernel32.GetCommandLineW.0x90c0",
                "assembly": "mov qword ptr [rip+0x38], rax",
                "context": [],
                "filtered": False,
                "target_symbol": None,
            }
        ]
    )

    assert compacted[0]["pseudocode"] == "g_CommandLineBufferW = api.command_line.kernel32.GetCommandLineW.0x90c0"


def test_pseudocode_renderer_recovers_global_alias_from_flsgetvalue_context():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x32", "pseudocode": "xchg(g_slot_5, FlsGetValue2)", "assembly": "xchg [rip+0x40], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x33", "pseudocode": "call g_slot_5", "assembly": "call qword ptr [rip+0x40]", "context": [], "filtered": False, "target_symbol": "g_slot_5"},
        ]
    )

    assert compacted[0]["pseudocode"] == "xchg(g_FlsGetValueFn, FlsGetValue2)"
    assert compacted[1]["pseudocode"] == "call g_FlsGetValueFn"


def test_pseudocode_renderer_classifies_unknown_global_counter_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {
                "address": "0x34",
                "pseudocode": "g_vhdx_backup_53df8 = g_vhdx_backup_53df8 + 1",
                "assembly": "add dword ptr [rip+0x20], 1",
                "context": [],
                "filtered": False,
                "target_symbol": None,
            }
        ]
    )

    assert compacted[0]["pseudocode"] == "g_counter_53df8 = g_counter_53df8 + 1"


def test_pseudocode_renderer_classifies_unknown_global_flag_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x35", "pseudocode": "compare(g_vhdx_backup_5470c, 0x0)", "assembly": "cmp dword ptr [rip+0x24], 0", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x36", "pseudocode": "if (g_vhdx_backup_5470c != 0x0)", "assembly": "jne 0x1400327e4", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x37", "pseudocode": "g_vhdx_backup_5470c = 0x1", "assembly": "mov dword ptr [rip+0x24], 1", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "compare(g_flag_5470c, 0x0)"
    assert compacted[1]["pseudocode"] == "if (g_flag_5470c != 0x0)"
    assert compacted[2]["pseudocode"] == "g_flag_5470c = 0x1"


def test_pseudocode_renderer_classifies_unknown_global_state_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x38", "pseudocode": "g_vhdx_backup_52108 = 0x1", "assembly": "mov dword ptr [rip+0x30], 1", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x39", "pseudocode": "g_vhdx_backup_52108 = 0x2", "assembly": "mov dword ptr [rip+0x30], 2", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x3A", "pseudocode": "compare(g_vhdx_backup_52108, 0x3)", "assembly": "cmp dword ptr [rip+0x30], 3", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "g_state_52108 = 0x1"
    assert compacted[1]["pseudocode"] == "g_state_52108 = 0x2"
    assert compacted[2]["pseudocode"] == "compare(g_state_52108, 0x3)"


def test_pseudocode_renderer_folds_repeated_scalar_records():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x40", "pseudocode": "g_counter = g_counter + 1", "assembly": "add dword ptr [rip+0x20], 1", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x41", "pseudocode": "g_counter = g_counter + 1", "assembly": "add dword ptr [rip+0x20], 1", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x42", "pseudocode": "g_counter = g_counter + 1", "assembly": "add dword ptr [rip+0x20], 1", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x43", "pseudocode": "g_counter = g_counter + 1", "assembly": "add dword ptr [rip+0x20], 1", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "increment(g_counter, repeated x4)"
    assert compacted[0]["assembly"] == "scalar_repeat x4"
    assert "repeated x4" in compacted[0]["context"]


def test_pseudocode_renderer_folds_repeated_while_chains():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x60", "pseudocode": "while (api_heap_HeapAlloc_0x9a20 != bp)", "assembly": "jne 0x140027847", "context": [], "filtered": False, "target_symbol": "while"},
            {"address": "0x61", "pseudocode": "retVal = retVal + 1", "assembly": "inc eax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x62", "pseudocode": "while (thisObj.member_0 != bp)", "assembly": "jne 0x14002784a", "context": [], "filtered": False, "target_symbol": "while"},
            {"address": "0x63", "pseudocode": "while (api_heap_HeapAlloc_0x9a20 != bp)", "assembly": "jne 0x140027847", "context": [], "filtered": False, "target_symbol": "while"},
            {"address": "0x64", "pseudocode": "retVal = retVal + 1", "assembly": "inc eax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x65", "pseudocode": "while (thisObj.member_10 != bp)", "assembly": "jne 0x14002784a", "context": [], "filtered": False, "target_symbol": "while"},
        ]
    )

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "while_chain(object_slot_traversal != bp, x4)"
    assert compacted[0]["assembly"] == "while_chain x4"
    assert "while_chain_count=4" in compacted[0]["context"]


def test_pseudocode_renderer_classifies_unknown_global_path_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x66", "pseudocode": "localPath = g_vhdx_backup_44d58", "assembly": "mov rbx, qword ptr [rip+0x20]", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x67", "pseudocode": "arg_1 = localPath", "assembly": "mov rcx, rbx", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "localPath = g_path_44d58"


def test_pseudocode_renderer_classifies_unknown_global_slot_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x67", "pseudocode": "compare(FlsGetValue2, g_vhdx_backup_54700)", "assembly": "cmp rax, qword ptr [rip+0x24]", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x68", "pseudocode": "if (FlsGetValue2 == g_vhdx_backup_54700)", "assembly": "je 0x140032780", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "compare(FlsGetValue2, g_slot_54700)"
    assert compacted[1]["pseudocode"] == "if (FlsGetValue2 == g_slot_54700)"


def test_pseudocode_renderer_classifies_unknown_global_tls_slot_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x68", "pseudocode": "g_vhdx_backup_52330 = retVal", "assembly": "mov dword ptr [rip+0x28], eax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x69", "pseudocode": "compare(g_vhdx_backup_52330, -0x1)", "assembly": "cmp eax, -1", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6A", "pseudocode": "arg_1 = g_vhdx_backup_52330", "assembly": "mov ecx, eax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6B", "pseudocode": "call TlsAccess", "assembly": "call 0x14002aba6", "context": [], "filtered": False, "target_symbol": "TlsAccess"},
        ]
    )

    assert compacted[0]["pseudocode"] == "g_tls_slot_52330 = retVal"
    assert compacted[1]["pseudocode"] == "compare(g_tls_slot_52330, -0x1)"
    assert compacted[2]["pseudocode"] == "arg_1 = g_tls_slot_52330"


def test_pseudocode_renderer_classifies_unknown_global_module_handle_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x68", "pseudocode": "call LoadLibraryEx", "assembly": "call 0x14002d05d", "context": [], "filtered": False, "target_symbol": "LoadLibraryEx"},
            {"address": "0x69", "pseudocode": "g_vhdx_backup_54518 = retVal", "assembly": "mov qword ptr [rip+0x28], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6A", "pseudocode": "retVal = g_vhdx_backup_54518", "assembly": "mov rax, qword ptr [rip+0x28]", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[1]["pseudocode"] == "g_LoadedModuleHandle = retVal"
    assert compacted[2]["pseudocode"] == "retVal = g_LoadedModuleHandle"


def test_pseudocode_renderer_classifies_unknown_global_table_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x6C", "pseudocode": "g_vhdx_backup_540e0 = retVal", "assembly": "mov qword ptr [rip+0x30], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6D", "pseudocode": "arg_2 = g_vhdx_backup_540e0", "assembly": "mov rdx, qword ptr [rip+0x30]", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6E", "pseudocode": "compare(g_slot_52368, arg_2)", "assembly": "cmp qword ptr [rip+0x34], rdx", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6F", "pseudocode": "compare(g_slot_52388, arg_2)", "assembly": "cmp qword ptr [rip+0x38], rdx", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "g_slot_table_540e0 = retVal"
    assert compacted[1]["pseudocode"] == "arg_2 = g_slot_table_540e0"


def test_pseudocode_renderer_prefers_table_alias_over_tls_context():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x70", "pseudocode": "call TlsAccess", "assembly": "call 0x14002aba6", "context": [], "filtered": False, "target_symbol": "TlsAccess"},
            {"address": "0x71", "pseudocode": "g_vhdx_backup_540e0 = retVal", "assembly": "mov qword ptr [rip+0x30], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x72", "pseudocode": "arg_2 = g_vhdx_backup_540e0", "assembly": "mov rdx, qword ptr [rip+0x30]", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x73", "pseudocode": "compare(g_slot_52368, arg_2)", "assembly": "cmp qword ptr [rip+0x34], rdx", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x74", "pseudocode": "compare(g_slot_52388, arg_2)", "assembly": "cmp qword ptr [rip+0x38], rdx", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[1]["pseudocode"] == "g_slot_table_540e0 = retVal"
    assert compacted[2]["pseudocode"] == "arg_2 = g_slot_table_540e0"


def test_pseudocode_renderer_classifies_table_alias_from_static_arg_sources():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x74", "pseudocode": "arg_1 = &0x140053700", "assembly": "lea rcx, [rip+0x10]", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x75", "pseudocode": "arg_2 = &0x140053718", "assembly": "lea rdx, [rip+0x18]", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x76", "pseudocode": "g_vhdx_backup_53710 = arg_1", "assembly": "mov qword ptr [rip+0x20], rcx", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x77", "pseudocode": "g_vhdx_backup_53720 = arg_2", "assembly": "mov qword ptr [rip+0x28], rdx", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[2]["pseudocode"] == "g_descriptor_table_53710 = arg_1"
    assert compacted[3]["pseudocode"] == "g_descriptor_table_53720 = arg_2"


def test_pseudocode_renderer_classifies_unknown_global_cache_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x6B", "pseudocode": "xchg(g_vhdx_backup_5a008, retVal)", "assembly": "xchg qword ptr [rip+0x30], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x6C", "pseudocode": "retVal = g_vhdx_backup_5a008", "assembly": "mov rax, qword ptr [rip+0x30]", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "xchg(g_cache_5a008, retVal)"
    assert compacted[1]["pseudocode"] == "retVal = g_cache_5a008"


def test_pseudocode_renderer_classifies_unknown_global_path_pointer_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x7C", "pseudocode": "g_vhdx_backup_536e8 = localPath", "assembly": "mov qword ptr [rip+0x20], rbx", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x7D", "pseudocode": "g_vhdx_backup_536f0 = filePath", "assembly": "mov qword ptr [rip+0x28], rdi", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "g_path_ptr_536e8 = localPath"
    assert compacted[1]["pseudocode"] == "g_path_ptr_536f0 = filePath"


def test_pseudocode_renderer_classifies_proc_cache_over_tls_slot_context():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x75", "pseudocode": "call TlsAccess", "assembly": "call 0x14002aba6", "context": [], "filtered": False, "target_symbol": "TlsAccess"},
            {"address": "0x76", "pseudocode": "retVal = retVal", "assembly": "mov rax, rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x77", "pseudocode": "call GetProcAddress", "assembly": "call 0x14002d18e", "context": [], "filtered": False, "target_symbol": "GetProcAddress"},
            {"address": "0x78", "pseudocode": "retVal = retVal", "assembly": "mov rax, rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x79", "pseudocode": "retVal = retVal", "assembly": "mov rax, rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x7A", "pseudocode": "xchg(g_vhdx_backup_5a008, retVal)", "assembly": "xchg qword ptr [rip+0x30], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x7B", "pseudocode": "retVal = g_vhdx_backup_5a008", "assembly": "mov rax, qword ptr [rip+0x30]", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[5]["pseudocode"] == "xchg(g_GetProcAddress, retVal)"
    assert compacted[6]["pseudocode"] == "retVal = g_GetProcAddress"


def test_pseudocode_renderer_classifies_unknown_global_proc_cache_alias():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x70", "pseudocode": "call GetProcAddress", "assembly": "call 0x14002d18e", "context": [], "filtered": False, "target_symbol": "GetProcAddress"},
            {"address": "0x71", "pseudocode": "retVal = retVal", "assembly": "mov rax, rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x72", "pseudocode": "retVal = retVal", "assembly": "mov rax, rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x73", "pseudocode": "xchg(g_vhdx_backup_5a010, retVal)", "assembly": "xchg qword ptr [rip+0x34], rax", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x74", "pseudocode": "retVal = g_vhdx_backup_5a010", "assembly": "mov rax, qword ptr [rip+0x34]", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert compacted[0]["pseudocode"] == "call GetProcAddress"
    assert compacted[3]["pseudocode"] == "xchg(g_GetProcAddress, retVal)"
    assert compacted[4]["pseudocode"] == "retVal = g_GetProcAddress"


def test_pseudocode_renderer_summarizes_repeated_compare_records():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    compacted = renderer.compact_instruction_records(
        [
            {"address": "0x50", "pseudocode": "compare(g_counter, arg_2)", "assembly": "cmp eax, ecx", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x51", "pseudocode": "compare(g_counter, arg_2)", "assembly": "cmp eax, ecx", "context": [], "filtered": False, "target_symbol": None},
            {"address": "0x52", "pseudocode": "compare(g_counter, arg_2)", "assembly": "cmp eax, ecx", "context": [], "filtered": False, "target_symbol": None},
        ]
    )

    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "compare(g_counter, arg_2) repeated x3"
    assert compacted[0]["assembly"] == "scalar_repeat x3"


def test_pseudocode_renderer_folds_repeated_normalized_windows():
    emu = FakeEmulator()
    renderer = PseudocodeRenderer(emu, enable_heuristics=True)

    records = []
    for index, base in enumerate((0x1000, 0x1100, 0x1200)):
        records.extend(
            [
                {"address": hex(base + 0), "pseudocode": f"arg_1 = &0x{base:x}", "assembly": "lea rcx, [rip+0x10]", "context": [], "filtered": False, "target_symbol": None},
                {"address": hex(base + 1), "pseudocode": "call function_1", "assembly": "call 0x14002d4e4", "context": [], "filtered": False, "target_symbol": None},
                {"address": hex(base + 2), "pseudocode": "while (retVal < 0x5)", "assembly": "while_fold x20", "context": [], "filtered": False, "target_symbol": "while"},
                {"address": hex(base + 3), "pseudocode": "retVal = retVal + 1", "assembly": "inc eax", "context": [], "filtered": False, "target_symbol": None},
                {"address": hex(base + 4), "pseudocode": "arg_1 = arg_1 + 1", "assembly": "inc rcx", "context": [], "filtered": False, "target_symbol": None},
                {"address": hex(base + 5), "pseudocode": "while (retVal < 0x5)", "assembly": "while_backedge x2", "context": [], "filtered": False, "target_symbol": "while"},
                {"address": hex(base + 6), "pseudocode": "rdi = rdi + 0x48", "assembly": "add rdi, 0x48", "context": [], "filtered": False, "target_symbol": None},
                {"address": hex(base + 7), "pseudocode": "while (retVal != localPath)", "assembly": "while_backedge x3", "context": [], "filtered": False, "target_symbol": "while"},
            ]
        )

    compacted = renderer.compact_instruction_records(records)

    assert len(compacted) == 9
    assert compacted[7]["pseudocode"] == "while (retVal != localPath)"
    assert compacted[8]["pseudocode"] == "repeat_window(while (retVal < 0x5), x2)"
    assert compacted[8]["assembly"] == "repeat_window size=8 x2"


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
