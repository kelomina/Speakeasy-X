import speakeasy.winenv.arch as e_arch
from speakeasy.profiler import Profiler, Run
from speakeasy.profiler_events import (
    FILE_WRITE,
    REG_WRITE,
    ApiEvent,
    ApiEventSchema,
    FileWriteEvent,
    NetDnsEvent,
    NetHttpEvent,
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


# ---------------------------------------------------------------------------
# P0-12/P0-13/P0-16 回归测试：DNS/HTTP 去重、ApiEvent dataclass、采样上限
# ---------------------------------------------------------------------------


def test_trace_position_namedtuple_defaults():
    """TracePosition 改 NamedTuple 后字段访问和默认值正确。"""
    pos = TracePosition(tick=1, tid=2, pid=3)
    assert pos.tick == 1
    assert pos.tid == 2
    assert pos.pid == 3
    assert pos.pc is None

    pos2 = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    assert pos2.pc == 0x401000

    # _asdict() 返回 dict，用于序列化
    d = pos2._asdict()
    assert d == {"tick": 1, "tid": 2, "pid": 3, "pc": 0x401000}


def test_api_event_to_dict_matches_schema():
    """ApiEvent.to_dict() 输出应与 ApiEventSchema 兼容。"""
    pos = TracePosition(tick=10, tid=20, pid=30, pc=0x401000)
    event = ApiEvent(
        pos=pos,
        api_name="kernel32.CreateFileA",
        args=["0x100", "0x200"],
        ret_val="0x300",
    )

    d = event.to_dict()
    assert d["event"] == "api"
    assert d["pos"] == {"tick": 10, "tid": 20, "pid": 30, "pc": 0x401000}
    assert d["api_name"] == "kernel32.CreateFileA"
    assert d["args"] == ["0x100", "0x200"]
    assert d["ret_val"] == "0x300"

    # Pydantic 应能验证 to_dict() 输出
    schema = ApiEventSchema.model_validate(d)
    assert schema.event == "api"
    assert schema.api_name == "kernel32.CreateFileA"
    assert schema.args == ["0x100", "0x200"]
    assert schema.ret_val == "0x300"
    assert schema.pos.tick == 10
    assert schema.pos.pc == 0x401000


def test_api_event_to_dict_with_none_ret_val():
    """ApiEvent.to_dict() 应正确处理 ret_val=None。"""
    pos = TracePosition(tick=0, tid=1, pid=1)
    event = ApiEvent(pos=pos, api_name="ntdll.NtClose", args=[])

    d = event.to_dict()
    assert d["ret_val"] is None
    assert d["args"] == []

    schema = ApiEventSchema.model_validate(d)
    assert schema.ret_val is None


def test_api_event_roundtrip_json():
    """ApiEvent 通过 to_dict -> Pydantic -> JSON -> Pydantic 往返一致。"""
    pos = TracePosition(tick=42, tid=7, pid=11, pc=0xDEAD)
    event = ApiEvent(
        pos=pos,
        api_name="kernel32.VirtualAlloc",
        args=["0x0", "0x1000", "0x3000", "0x40"],
        ret_val="0x5000",
    )

    d = event.to_dict()
    schema = ApiEventSchema.model_validate(d)
    json_str = schema.model_dump_json()
    restored = ApiEventSchema.model_validate_json(json_str)

    assert restored.api_name == event.api_name
    assert restored.args == event.args
    assert restored.ret_val == event.ret_val
    assert restored.pos.tick == pos.tick
    assert restored.pos.tid == pos.tid
    assert restored.pos.pid == pos.pid
    assert restored.pos.pc == pos.pc


def test_dns_dedup_preserves_first_event():
    """DNS 去重改 set 后应保留首次事件，丢弃重复事件。"""
    profiler = Profiler()
    run = Run()
    pos1 = TracePosition(tick=1, tid=2, pid=3, pc=0x1000)
    pos2 = TracePosition(tick=10, tid=2, pid=3, pc=0x2000)

    profiler.record_dns_event(run, pos1, "example.com", ip="1.2.3.4")
    profiler.record_dns_event(run, pos2, "example.com", ip="1.2.3.4")

    assert len(run.events) == 1
    event = run.events[0]
    assert isinstance(event, NetDnsEvent)
    assert event.query == "example.com"
    assert event.response == "1.2.3.4"
    # 应保留首次事件的 pos
    assert event.pos.tick == 1


def test_dns_dedup_with_empty_ip_normalizes():
    """DNS 去重应将空 ip 标准化为 None，避免 ip="" 重复事件。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x1000)

    # 第一次 ip=""，response 存为 None
    profiler.record_dns_event(run, pos, "empty.com", ip="")
    # 第二次 ip=""，应被去重
    profiler.record_dns_event(run, pos, "empty.com", ip="")

    assert len(run.events) == 1
    event = run.events[0]
    assert isinstance(event, NetDnsEvent)
    assert event.response is None


def test_dns_dedup_different_ip_not_merged():
    """不同 ip 的相同 domain 不应被去重。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x1000)

    profiler.record_dns_event(run, pos, "multi.com", ip="1.1.1.1")
    profiler.record_dns_event(run, pos, "multi.com", ip="2.2.2.2")

    assert len(run.events) == 2


def test_http_dedup_preserves_first_event():
    """HTTP 去重改 set 后应保留首次事件。"""
    profiler = Profiler()
    run = Run()
    pos1 = TracePosition(tick=1, tid=2, pid=3, pc=0x1000)
    pos2 = TracePosition(tick=10, tid=2, pid=3, pc=0x2000)

    profiler.record_http_event(run, pos1, "evil.com", 80, body=b"first")
    profiler.record_http_event(run, pos2, "evil.com", 80, body=b"second")

    assert len(run.events) == 1
    event = run.events[0]
    assert isinstance(event, NetHttpEvent)
    assert event.server == "evil.com"
    assert event.port == 80
    # 应保留首次事件的 pos
    assert event.pos.tick == 1


def test_http_dedup_no_artifact_leak():
    """HTTP 去重时不应为重复事件创建 artifact（原代码会泄漏）。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x1000)

    profiler.record_http_event(run, pos, "dup.com", 443, secure=True, body=b"data")
    # 记录当前 artifact 数量
    artifacts_after_first = len(profiler.artifact_store._artifacts)

    # 重复事件
    profiler.record_http_event(run, pos, "dup.com", 443, secure=True, body=b"duplicate")
    artifacts_after_second = len(profiler.artifact_store._artifacts)

    assert artifacts_after_first == artifacts_after_second, "重复 HTTP 事件泄漏了 artifact"
    assert len(run.events) == 1


def test_http_dedup_different_port_not_merged():
    """不同端口的 HTTP 事件不应被去重。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x1000)

    profiler.record_http_event(run, pos, "srv.com", 80)
    profiler.record_http_event(run, pos, "srv.com", 443, secure=True)

    assert len(run.events) == 2


def test_record_instruction_sampling_respects_limit():
    """record_instruction 超过上限后应启用采样。"""
    from unittest.mock import patch

    profiler = Profiler()
    profiler.attach_emulator(FakeEmulator())
    profiler.enable_pseudocode(enable_heuristics=True)
    profiler.max_instruction_trace = 5  # 设置小上限便于测试

    # 显式创建 renderer 并设置到 profiler 上，避免 get_pseudocode_renderer 返回 None
    renderer = PseudocodeRenderer(FakeEmulator(), enable_heuristics=True)
    profiler.pseudocode_renderer = renderer

    run = Run()
    run.start_addr = 0x401000
    run.type = "entry_point"

    # mock render_instruction_record 使其总是返回有效记录，避免依赖具体指令
    def fake_render(addr, size):
        return {"address": hex(addr), "pseudocode": "nop", "assembly": "nop", "context": [], "filtered": False}

    with patch.object(renderer, "render_instruction_record", side_effect=fake_render):
        # 记录 20 条指令
        for i in range(20):
            run.instr_cnt = i
            profiler.record_instruction(run, 0x401000 + i, 1)

    # 超过上限后采样，trace_len 应远小于实际指令数
    # 上限 5，记录了 20 条指令，trace_len 应该在 5-15 之间（采样减慢但不阻止增长）
    assert len(run.instruction_trace) < 20, "采样逻辑未生效，trace_len 等于实际指令数"
    assert len(run.instruction_trace) >= 5, "采样不应在达到上限前丢弃记录"


def test_record_instruction_below_limit_records_all():
    """未超过上限时应记录所有指令。"""
    from unittest.mock import patch

    profiler = Profiler()
    profiler.attach_emulator(FakeEmulator())
    profiler.enable_pseudocode(enable_heuristics=True)
    profiler.max_instruction_trace = 100

    renderer = PseudocodeRenderer(FakeEmulator(), enable_heuristics=True)
    profiler.pseudocode_renderer = renderer

    run = Run()
    run.start_addr = 0x401000
    run.type = "entry_point"

    def fake_render(addr, size):
        return {"address": hex(addr), "pseudocode": "nop", "assembly": "nop", "context": [], "filtered": False}

    with patch.object(renderer, "render_instruction_record", side_effect=fake_render):
        for i in range(10):
            run.instr_cnt = i
            profiler.record_instruction(run, 0x401000 + i, 1)

    assert len(run.instruction_trace) == 10


def test_record_instruction_disabled_when_limit_zero():
    """max_instruction_trace=0 时应禁用采样限制。"""
    from unittest.mock import patch

    profiler = Profiler()
    profiler.attach_emulator(FakeEmulator())
    profiler.enable_pseudocode(enable_heuristics=True)
    profiler.max_instruction_trace = 0

    renderer = PseudocodeRenderer(FakeEmulator(), enable_heuristics=True)
    profiler.pseudocode_renderer = renderer

    run = Run()
    run.start_addr = 0x401000
    run.type = "entry_point"

    def fake_render(addr, size):
        return {"address": hex(addr), "pseudocode": "nop", "assembly": "nop", "context": [], "filtered": False}

    with patch.object(renderer, "render_instruction_record", side_effect=fake_render):
        for i in range(50):
            run.instr_cnt = i
            profiler.record_instruction(run, 0x401000 + i, 1)

    # limit=0 禁用采样，所有记录应保留
    assert len(run.instruction_trace) == 50


def test_merge_binary_data_via_profiler_no_stale_artifact():
    """Profiler.merge_binary_data 调用后，旧 artifact 不应残留在报告中。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    # 连续两次 FILE_WRITE 同 path，触发 merge_binary_data
    profiler.record_file_access_event(run, pos, "C:\\temp\\m.bin", FILE_WRITE, data=b"\xaa", size=1)
    profiler.record_file_access_event(run, pos, "C:\\temp\\m.bin", FILE_WRITE, data=b"\xbb", size=1)

    report = build_report(profiler, run)

    # 报告中只应有一个 data artifact（合并后的），旧的不应残留
    if report.data:
        assert len(report.data) == 1, f"报告中有多余 artifact: {list(report.data)}"


def test_get_report_serializes_api_event_dataclass():
    """get_report 应正确序列化 dataclass 类型的 ApiEvent。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_api_event(run, pos, "kernel32.GetTickCount", 0x1234, [])

    report = build_report(profiler, run)

    events = report.entry_points[0].events
    assert events is not None
    assert len(events) == 1
    # 事件应正确序列化为 ApiEventSchema
    assert events[0].event == "api"
    assert events[0].api_name == "kernel32.GetTickCount"
    assert events[0].ret_val == "0x1234"


def test_get_report_json_roundtrip_with_api_event():
    """ApiEvent 通过 JSON 序列化/反序列化往返应一致。"""
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=5, tid=10, pid=20, pc=0x402000)

    profiler.record_api_event(run, pos, "kernel32.Sleep", None, [0x3E8])

    report = build_report(profiler, run)
    json_str = report.model_dump_json(exclude_none=True)

    # 反序列化
    from speakeasy.report import Report
    restored = Report.model_validate_json(json_str)

    ep = restored.entry_points[0]
    assert ep.events is not None
    assert len(ep.events) == 1
    event = ep.events[0]
    assert event.event == "api"
    assert event.api_name == "kernel32.Sleep"
    assert event.ret_val is None
    assert event.pos.tick == 5
    assert event.pos.pc == 0x402000
