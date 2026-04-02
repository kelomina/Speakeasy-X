import pytest

from speakeasy import Speakeasy
from speakeasy.errors import WindowsEmuError
from speakeasy.profiler import Run
from speakeasy.windows import objman

DLL_BINS = ["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"]
EXE_BINS = ["argv_test_x86.exe.xz", "argv_test_x64.exe.xz"]


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_call_without_run_module(config, load_test_bin, bin_file):
    """call() should work without run_module() being called first (GH-21)."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])
    finally:
        se.shutdown()


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_call_after_run_module(config, load_test_bin, bin_file):
    """call() should still work after run_module() has set up context."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.run_module(mod)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])
    finally:
        se.shutdown()


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_call_queued_during_run(config, load_test_bin, bin_file):
    """call() queued while run_queue is non-empty defers context to execution time."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        ep = mod.base + mod.ep
        se.call(ep, [mod.base, 1, 0])
        se.call(ep, [mod.base, 1, 0])
    finally:
        se.shutdown()


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_call_context_is_consistent(config, load_test_bin, bin_file):
    """After call(), every run has process_context, thread, and active PEB."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])

        emu = se.emu
        assert emu.curr_process is not None, "no process after call()"
        assert emu.curr_process.is_peb_active, "PEB not activated"
        assert emu.curr_thread is not None, "no thread after call()"
        for run in emu.runs:
            assert run.process_context is not None, f"run {run.type} missing process_context"
            assert run.thread is not None, f"run {run.type} has no thread"
            assert run.thread.process is run.process_context, (
                f"run {run.type} thread.process mismatch"
            )
    finally:
        se.shutdown()


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_call_context_consistent_after_run_module(config, load_test_bin, bin_file):
    """After run_module() + call(), context is consistent across all runs."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.run_module(mod)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])

        emu = se.emu
        assert emu.curr_process is not None
        assert emu.curr_process.is_peb_active
        assert emu.curr_thread is not None
        for run in emu.runs:
            assert run.process_context is not None, f"run {run.type} missing process_context"
            assert run.thread is not None, f"run {run.type} has no thread"
            assert run.thread.process is run.process_context, (
                f"run {run.type} thread.process mismatch"
            )
    finally:
        se.shutdown()


# --- EXE call() without run_module() ---


@pytest.mark.parametrize("bin_file", EXE_BINS)
def test_exe_call_without_run_module(config, load_test_bin, bin_file):
    """call() on an EXE entrypoint creates a module-backed process, not a container."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        ep = mod.base + mod.ep
        se.call(ep, [0, 0, 0, 0])

        emu = se.emu
        assert emu.curr_process is not None
        assert emu.curr_process.pe is mod, "EXE call() should produce a module-backed process"
        assert emu.curr_process.base == mod.base
    finally:
        se.shutdown()


# --- Process bookkeeping ---


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_process_in_processes_after_run_module(config, load_test_bin, bin_file):
    """After run_module(), curr_process must be discoverable in self.processes."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.run_module(mod)

        emu = se.emu
        assert emu.curr_process is not None
        assert emu.curr_process in emu.processes, "curr_process not in self.processes"
    finally:
        se.shutdown()


@pytest.mark.parametrize("bin_file", EXE_BINS)
def test_process_in_processes_after_exe_run_module(config, load_test_bin, bin_file):
    """After EXE run_module(), the active process is in self.processes."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.run_module(mod)

        emu = se.emu
        assert emu.curr_process is not None
        assert emu.curr_process in emu.processes, "EXE curr_process not in self.processes"
    finally:
        se.shutdown()


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_process_in_processes_after_call(config, load_test_bin, bin_file):
    """After call() without run_module(), curr_process is in self.processes."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])

        emu = se.emu
        assert emu.curr_process is not None
        assert emu.curr_process in emu.processes
    finally:
        se.shutdown()


# --- Queued call does not mutate SP ---


@pytest.mark.parametrize("bin_file", DLL_BINS)
def test_queued_call_does_not_mutate_sp(config, load_test_bin, bin_file):
    """Invoking call() while the queue is non-empty must not change SP/BP."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        ep = mod.base + mod.ep

        placeholder = Run()
        placeholder.type = "placeholder"
        placeholder.start_addr = ep
        placeholder.args = [mod.base, 1, 0]
        se.emu.add_run(placeholder)

        sp_before = se.emu.get_stack_ptr()
        se.call(ep, [mod.base, 1, 0])
        sp_after = se.emu.get_stack_ptr()

        assert sp_before == sp_after, (
            f"call() mutated SP while queue non-empty: {sp_before:#x} -> {sp_after:#x}"
        )
    finally:
        se.shutdown()


# --- Shellcode ---


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_shellcode_context(config, arch):
    """Shellcode runs get proper process, thread, and register initialization."""
    sc_data = b"\xc3"  # ret
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode("test_shellcode", arch, data=sc_data)
        se.run_shellcode(sc_addr)

        emu = se.emu
        assert len(emu.runs) >= 1
        sc_run = emu.runs[0]
        assert sc_run.process_context is not None, "shellcode run missing process_context"
        assert sc_run.thread is not None, "shellcode run missing thread"
        assert sc_run.thread.process is sc_run.process_context
        assert sc_run.process_context in emu.processes
    finally:
        se.shutdown()


# --- Fail-fast on conflicting thread/process ---


def test_conflicting_thread_process_raises(config, load_test_bin):
    """A run whose thread is bound to a different process should fail fast."""
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)

        proc_a = objman.Process(se.emu)
        proc_b = objman.Process(se.emu)
        thread = objman.Thread(se.emu, stack_base=se.emu.stack_base)
        thread.process = proc_a
        proc_a.threads.append(thread)

        run = Run()
        run.type = "test_conflict"
        run.start_addr = mod.base + mod.ep
        run.args = [mod.base, 1, 0]
        run.process_context = proc_b
        run.thread = thread

        se.emu.add_run(run)

        with pytest.raises(WindowsEmuError, match="different process"):
            se.emu.start()
    finally:
        se.shutdown()
