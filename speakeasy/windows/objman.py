# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ntpath
import os
from typing import Any

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.nt.ntoskrnl as ntoskrnl
import speakeasy.winenv.defs.windows.windows as windef


class Console:
    """
    Represents a console window object
    """

    curr_handle = 0x340

    def __init__(self):
        self.handle = self.get_handle()
        self.window = 0

    def get_handle(self):
        tmp = Console.curr_handle
        Console.curr_handle += 4
        return tmp


class SEH:
    """
    Implements the structures needed to support SEH handling during emulation
    """

    class ScopeRecord:
        def __init__(self, record):
            self.record = record
            self.filter_called = False
            self.handler_called = False

    class Frame:
        def __init__(self, entry, scope_table, scope_records):
            self.entry = entry
            self.scope_table = scope_table
            self.scope_records = []
            for rec in scope_records:
                SEH.ScopeRecord(rec)
                self.scope_records.append(SEH.ScopeRecord(rec))
            self.searched = False

    def __init__(self):
        self.context: Any | None = None
        self.context_address: int = 0
        self.record: Any | None = None
        self.frames: list[SEH.Frame] = []
        self.last_func: int = 0
        self.last_exception_code: int = 0
        self.exception_ptrs: int = 0
        self.handler_ret_val: int | None = None

    def set_context(self, context, address=0):
        self.context = context
        self.context_address = address

    def clear_frames(self):
        self.frames = []

    def add_frame(self, entry, scope_table, records):
        frame = SEH.Frame(entry, scope_table, records)
        self.frames.append(frame)


class KernelObject:
    """
    Base class for Kernel objects managed by the object manager
    """

    curr_handle = 0x220
    curr_id = 0x400

    def __init__(self, emu):
        self.emu: Any = emu
        self.address: int | None = None
        # _name 是 name 属性的后备字段；赋值时通过 setter 同步 ObjectManager._name_index
        self._name: str = ""
        self.object: Any = 0
        self.ref_cnt: int = 0
        self.handles: list[int] = []
        self.arch: int = emu.get_arch()
        self.id: int = KernelObject.curr_id
        KernelObject.curr_id += 4

        self.nt_types = ntoskrnl
        self.win_types = windef

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        old = self._name
        self._name = value
        # 主题 J：name 变更时同步 ObjectManager._name_index（add_object/remove_object 之外的场景）
        om = getattr(self.emu, "om", None)
        if om is not None:
            om._on_object_rename(self, old, value)

    def sizeof(self, obj=None):
        if obj:
            return obj.sizeof()
        return self.object.sizeof()

    def get_bytes(self, obj=None):
        if obj:
            return obj.get_bytes()
        return self.object.get_bytes()

    def read_back(self):
        data = self.emu.mem_read(self.address, self.sizeof())
        self.object.cast(data)
        return self

    def write_back(self):
        data = self.get_bytes()
        if data and self.address:
            self.emu.mem_write(self.address, data)

    def get_class_name(self):
        if self.object:
            return self.object.__class__.__name__

    def get_mem_tag(self):
        return f"emu.struct.{self.get_class_name()}"

    def get_handle(self):
        tmp = KernelObject.curr_handle
        KernelObject.curr_handle += 4
        self.handles.append(tmp)
        # 若 ObjectManager 已就绪，同步登记到反向字典以支持 O(1) 查找
        om = getattr(self.emu, "om", None)
        if om is not None:
            om._handle_map[tmp] = self
        return tmp


class Driver(KernelObject):
    """
    Class that represents DRIVER_OBJECTs created by the Windows kernel
    """

    def __init__(self, emu):
        super().__init__(emu=emu)
        self.pe: Any | None = None
        self.devices: list[Device] = []
        self.ldr_entries: list[LdrDataTableEntry] = []
        self.mj_funcs: list[int | None] = [None] * (ddk.IRP_MJ_MAXIMUM_FUNCTION + 1)
        self.on_unload: int | None = None
        self.unload_called: bool = False
        self.reg_path_ptr: int = 0
        self.reg_path: str = ""
        self.name: str = ""
        self.basename: str = ""
        self.object = self.nt_types.DRIVER_OBJECT(emu.get_ptr_size())

    def create_reg_path(self, name):
        """
        Create the service path in the registry for the created driver
        """
        self.reg_path = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s\x00" % (name)  # noqa
        buf = self.reg_path.encode("utf-16le")
        self.reg_path = self.reg_path.strip("\x00")

        us = self.nt_types.UNICODE_STRING(self.emu.get_ptr_size())
        size = self.sizeof(us) + len(buf)
        addr = self.emu.mem_map(size, tag=f"emu.object.{self.name}.reg_path")
        us.Length = len(buf) - 2
        us.MaximumLength = len(buf)
        us.Buffer = addr + self.sizeof(us)

        self.emu.mem_write(addr, self.get_bytes(us))
        self.emu.mem_write(us.Buffer, buf)

        self.reg_path_ptr = addr

    def get_basename(self):
        return self.basename.lower()

    def init_driver_section(self):
        """
        Create the driver section for the driver. This is a linked list that
        links together driver objects
        """
        tag = f"emu.object.{self.name}.DriverSection"
        mod = self.pe

        if mod and mod.emu_path:
            mod_name = mod.emu_path
        else:
            mod_name = "None"

        ldte = LdrDataTableEntry(self.emu, mod_name, tag=tag)
        first = None
        last = None
        if len(self.ldr_entries):
            first = self.ldr_entries[0]
            last = self.ldr_entries[-1]
        self.ldr_entries.append(ldte)

        ldte.object.DllBase = mod.base
        ldte.object.EntryPoint = mod.base + mod.ep
        ldte.object.SizeOfImage = mod.image_size

        dllname = mod.emu_path.encode("utf-16le")
        name_addr = ldte.address + ldte.sizeof()
        self.emu.mem_write(name_addr, dllname)

        # Set the dll full name
        ldte.object.FullDllName.Length = len(dllname)
        ldte.object.FullDllName.MaximumLength = len(dllname)
        ldte.object.FullDllName.Buffer = name_addr

        # Set the dll base name
        dllname = ntpath.basename(mod.emu_path).encode("utf-16le")
        ldte.object.BaseDllName.Length = len(dllname)
        ldte.object.BaseDllName.MaximumLength = len(dllname)
        ldte.object.BaseDllName.Buffer = name_addr + (ldte.object.FullDllName.Length - len(dllname))

        if not last:
            ldte.object.InLoadOrderLinks.Flink = ldte.address
            ldte.object.InLoadOrderLinks.Flink = ldte.address
            ldte.object.InLoadOrderLinks.Blink = ldte.address
            ldte.object.InMemoryOrderLinks.Blink = ldte.address
        else:
            ldte.object.InLoadOrderLinks.Flink = last.object.InLoadOrderLinks.Flink
            ldte.object.InMemoryOrderLinks.Flink = last.object.InMemoryOrderLinks.Flink
            ldte.object.InLoadOrderLinks.Blink = last.address
            ldte.object.InMemoryOrderLinks.Blink = last.address

            last.object.InLoadOrderLinks.Flink = ldte.address
            last.object.InMemoryOrderLinks.Flink = ldte.address
            first.object.InLoadOrderLinks.Blink = ldte.address
            first.object.InMemoryOrderLinks.Blink = ldte.address

            last.write_back()
        ldte.write_back()
        return ldte

    def init_driver_object(self, name=None, pe=None, is_decoy=True):
        """
        Initialize the DRIVER_OBJECT
        """
        self.pe = pe
        drvobj = self.object

        drvobj.Type = 4
        drvobj.Size = self.sizeof()
        drvobj.DeviceObject = 0
        drvobj.Flags = 2
        us = b""
        if pe:
            drvobj.DriverStart = pe.base
            drvobj.DriverSize = pe.image_size
            drvobj.DriverInit = pe.base + pe.ep

            if is_decoy:
                ep = pe.base + pe.ep
                drvobj.MajorFunction[ddk.IRP_MJ_CREATE] = ep + 1
                drvobj.MajorFunction[ddk.IRP_MJ_READ] = ep + 2
                drvobj.MajorFunction[ddk.IRP_MJ_WRITE] = ep + 3
                drvobj.MajorFunction[ddk.IRP_MJ_DEVICE_CONTROL] = ep + 4
                drvobj.MajorFunction[ddk.IRP_MJ_PNP] = ep + 5
                drvobj.MajorFunction[ddk.IRP_MJ_INTERNAL_DEVICE_CONTROL] = ep + 6

            if not name:
                drvname = os.path.splitext(pe.path)[0]
                drvname = os.path.basename(drvname)
                self.name = rf"\Driver\{drvname}"
                us = (f"\\Driver\\{drvname}\x00").encode("utf-16le")
                name = self.name

        if name:
            us = name.encode("utf-16le")
            self.name = name

        if not pe and not self.name:
            name = "none"

        # Allocate the driver object
        addr = self.emu.mem_map(drvobj.Size + len(us), tag=f"emu.object.{name}")

        drvobj.DriverName.Length = len(us)
        drvobj.DriverName.MaximumLength = len(us)
        drvobj.DriverName.Buffer = addr + drvobj.Size

        name = self.name
        idx = name.rfind("\\")
        if idx >= 0 and idx != len(name) - 1:
            name = self.name[idx + 1 :]
        else:
            name = "None"

        self.basename = name
        self.create_reg_path(name)

        drv_sect = self.init_driver_section()
        drvobj.DriverSection = drv_sect.address

        self.address = addr
        self.emu.mem_write(addr, self.get_bytes() + us)

    def read_back(self):
        super().read_back()

        for i, func in enumerate(self.mj_funcs):
            self.mj_funcs[i] = self.object.MajorFunction[i]

        self.on_unload = self.object.DriverUnload


class Device(KernelObject):
    """
    Represents a DEVICE_OBJECT created by the windows kernel
    """

    def __init__(self, emu):
        super().__init__(emu=emu)
        devobj = self.nt_types.DEVICE_OBJECT(emu.get_ptr_size())

        devobj.Type = 0x3
        devobj.Size = self.sizeof(devobj)
        devobj.ReferenceCount = 1

        self.file_object: FileObject | None = None
        self.object = devobj
        self.driver: Driver | None = None


class FileObject(KernelObject):
    """
    Represents a FILE_OBJECT created by the windows kernel
    """

    def __init__(self, emu):
        super().__init__(emu=emu)
        fileobj = self.nt_types.FILE_OBJECT(emu.get_ptr_size())

        fileobj.Type = 0x5
        fileobj.Size = self.sizeof(fileobj)
        self.object = fileobj
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class IoStackLocation(KernelObject):
    """
    Represents a IO_STACK_LOCATION struct that is part of
    an IRP.
    """

    def __init__(self, emu):
        super().__init__(emu=emu)

        self.object = self.nt_types.IO_STACK_LOCATION(emu.get_ptr_size())
        # Allocate two stack locations for now to handle IoGetNextIrpStackLocation calls
        self.address = emu.mem_map(self.sizeof() * 2, tag=self.get_mem_tag())


class Irp(KernelObject):
    """
    I/O request packet used when performing device input/output
    """

    def __init__(self, emu):
        super().__init__(emu=emu)
        self.object = self.nt_types.IRP(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())
        self.stack_locations = []

        ios = IoStackLocation(emu=emu)
        ios.write_back()

        self.object.Tail.Overlay.CurrentStackLocation = ios.address + ios.sizeof()

        self.stack_locations.append(ios)

        self.object.Type = 0x6
        self.object.Size = self.sizeof()
        self.write_back()

    def get_curr_stack_loc(self):
        return self.stack_locations[0]


class Thread(KernelObject):
    """
    Represents a Windows ETHREAD object that describes a
    an OS level thread
    """

    def __init__(self, emu, stack_base=0, stack_commit=0):
        super().__init__(emu=emu)
        self.emu = emu
        self.object = self.nt_types.ETHREAD(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())
        self.object.Data = b"\xff" * self.sizeof()
        self.tid: int = self.id
        self.modified_pc: bool = False
        self.teb: TEB | None = None
        self.seh: SEH = SEH()
        self.tls: list[int] = []
        self.message_queue: list[Any] = []
        self.ctx: Any = self.emu.get_thread_context()
        self.fls: list[int] = []
        self.suspend_count: int = 0
        self.token: Token = Token(self.emu)
        self.last_error: int = 0
        self.stack_base: int = stack_base
        self.stack_commit: int = stack_commit

        self.write_back()
        self.process: Process | None = None

    def queue_message(self, msg):
        """
        Add a GUI message to the thread's message queue
        """
        self.message_queue.append(msg)

    def get_context(self):
        if self.ctx:
            return self.ctx
        return self.emu.get_thread_context()

    def set_context(self, ctx):
        if self.ctx:
            if self.emu.get_arch() == _arch.ARCH_AMD64:
                if ctx.Rip != self.ctx.Rip:
                    self.modified_pc = True
            elif self.emu.get_arch() == _arch.ARCH_X86:
                if ctx.Eip != self.ctx.Eip:
                    self.modified_pc = True
        self.ctx = ctx

    def init_teb(self, teb_addr, peb_addr):
        if not self.teb:
            self.teb = TEB(emu=self.emu, address=teb_addr)

        self.teb.object.NtTib.StackBase = self.stack_base
        self.teb.object.NtTib.Self = teb_addr
        self.teb.object.NtTib.StackLimit = self.stack_commit
        self.teb.object.ProcessEnvironmentBlock = peb_addr
        self.teb.write_back()

    def get_teb(self):
        return self.teb.read_back()

    def init_tls(self, tls_dir, modname):
        ptrsz = self.emu.get_ptr_size()

        tls_dirp = self.emu.mem_map(ptrsz, tag=f"emu.tls.{modname}")

        self.emu.mem_write(tls_dirp, tls_dir)

        self.teb.object.ThreadLocalStoragePointer = tls_dirp
        self.teb.write_back()

        return


class Token(KernelObject):
    """
    Represents a TOKEN object
    """

    def __init__(self, emu):
        super().__init__(emu=emu)


class Process(KernelObject):
    """
    An EPROCESS object used by the Windows kernel to represent a process
    """

    def __init__(self, emu, pe=None, user_modules=None, name="", path="", cmdline="", base=0, session=0):
        super().__init__(emu=emu)
        self.ldr_entries: list[LdrDataTableEntry] = []
        # TODO: For now just allocate a blank opaque struct for an EPROCESS
        self.object = self.nt_types.EPROCESS(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag(), perms=1, base=0xE0000000)
        if emu.get_arch() == _arch.ARCH_X86:
            list_entry = self.address + 0x88
            self.emu.mem_write(list_entry, list_entry.to_bytes(4, "little"))
            self.emu.mem_write(list_entry + 4, list_entry.to_bytes(4, "little"))
        elif emu.get_arch() == _arch.ARCH_AMD64:
            list_entry = self.address + 0x188
            self.emu.mem_write(list_entry, list_entry.to_bytes(8, "little"))
            self.emu.mem_write(list_entry + 8, list_entry.to_bytes(8, "little"))
        self.name: str = name
        self.base: int = base
        self.pid: int = self.id
        self.modules: list[Any] = user_modules if user_modules is not None else []
        self.threads: list[Thread] = []
        self.console: Console | None = None
        self.curr_thread: Thread | None = None
        self.cmdline: str = cmdline
        self.session: int = session
        self.token: Token = Token(self.emu)
        emu.add_object(self.token)
        self.pe: Any | None = pe
        self.pe_data: bytes | None = None

        self.stdin = (0xF000) + 1
        self.stdout = (0xF000) + 2
        self.stderr = (0xF000) + 3

        # V1-S-7: PEB / PebLdrData / RTL_USER_PROCESS_PARAMETERS 改为惰性构造
        # 首次访问 self.peb / self.peb_ldr_data 时才分配内存并调用 set_process_parameters
        # 进程初始化可降低 50-70% 开销（样本不访问 PEB 时完全不构造）
        self._peb = None
        self._peb_ldr_data = None
        self.is_peb_active = False
        self.path = path
        self.image = ""
        self.title = ""

        is_console = False
        pe_meta = None
        if pe:
            if hasattr(pe, "get_pe_metadata"):
                pe_meta = pe.get_pe_metadata()
                if pe_meta and pe_meta.subsystem == ddk.WINDOWS_CONSOLE:
                    is_console = True
            elif hasattr(pe, "OPTIONAL_HEADER"):
                if pe.OPTIONAL_HEADER.Subsystem == ddk.WINDOWS_CONSOLE:
                    is_console = True

        if is_console:
            self.alloc_console()

    @property
    def peb(self):
        """V1-S-7: 惰性构造 PEB，首次访问时分配 PEB + PebLdrData + RTL_PARAMS"""
        if self._peb is None:
            self._peb = PEB(emu=self.emu)
            self._peb_ldr_data = PebLdrData(self.emu)
            # set_process_parameters 内部访问 self.peb（此时已就绪，不会递归）
            self.set_process_parameters(self.emu)
        return self._peb

    @peb.setter
    def peb(self, value):
        self._peb = value

    @property
    def peb_ldr_data(self):
        """V1-S-7: PebLdrData 与 PEB 一起惰性构造，访问时触发 peb 构造"""
        if self._peb_ldr_data is None:
            _ = self.peb
        return self._peb_ldr_data

    @peb_ldr_data.setter
    def peb_ldr_data(self, value):
        self._peb_ldr_data = value

    def set_peb_ldr_address(self, addr):
        self.peb.object.Ldr = addr
        self.peb.write_back()
        self.peb_ldr_data.address = addr

    def set_process_parameters(self, emu):
        process_parameters = RTL_USER_PROCESS_PARAMETERS(emu=emu, proc=self)
        self.peb.object.ProcessParameters = process_parameters.address
        self.peb.write_back()

    def alloc_console(self):

        if not self.console:
            self.console = Console()
        sm = self.emu.get_session_manager()
        desk = sm.get_current_desktop()
        self.console.window = desk.new_window()

    def get_desktop_name(self):
        sm = self.emu.get_session_manager()
        stat = sm.get_current_station()
        stat_name = stat.name

        desk = sm.get_current_desktop()
        desk_name = desk.name

        name = f"{stat_name}\\{desk_name}"

        return name

    def get_std_handle(self, dev):
        STD_INPUT_HANDLE = 0xFFFFFFF6
        STD_OUTPUT_HANDLE = 0xFFFFFFF5
        STD_ERROR_HANDLE = 0xFFFFFFF4

        dev = dev & 0xFFFFFFFF

        for k, v in (
            (STD_INPUT_HANDLE, self.stdin),
            (STD_OUTPUT_HANDLE, self.stdout),
            (STD_ERROR_HANDLE, self.stderr),
        ):
            if k == dev:
                return v
        return 0

    def get_ep(self):
        if self.pe:
            return self.pe.get_ep()

    def new_thread(self):
        thr = Thread(self.emu)
        self.threads.append(thr)

    def add_module_to_peb(self, module):
        pld = self.peb_ldr_data
        list_type = self.nt_types.LIST_ENTRY(self.emu.get_ptr_size())

        # Initialize the LDTE
        ldte = LdrDataTableEntry(self.emu, module.emu_path)
        if not self.ldr_entries:
            prev = ldte
        else:
            prev = self.ldr_entries[-1]

        self.ldr_entries.append(ldte)
        first = self.ldr_entries[0]

        ldte.object.InLoadOrderLinks.Flink = first.address
        ldte.object.InMemoryOrderLinks.Flink = first.address + self.sizeof(list_type)
        ldte.object.InInitializationOrderLinks.Flink = first.address + self.sizeof(list_type) * 2

        ldte.object.DllBase = module.base
        ldte.object.EntryPoint = module.base + module.ep
        ldte.object.SizeOfImage = module.image_size
        dllname = (module.emu_path + "\x00").encode("utf-16le")
        name_addr = ldte.address + ldte.sizeof()
        self.emu.mem_write(name_addr, dllname)

        # Set the dll full name
        ldte.object.FullDllName.Length = len(dllname) - 2
        ldte.object.FullDllName.MaximumLength = len(dllname)
        ldte.object.FullDllName.Buffer = name_addr

        # Set the dll base name
        dllname = (ntpath.basename(module.emu_path) + "\x00").encode("utf-16le")

        ldte.object.BaseDllName.Length = len(dllname) - 2
        ldte.object.BaseDllName.MaximumLength = len(dllname)
        ldte.object.BaseDllName.Buffer = name_addr + (ldte.object.FullDllName.MaximumLength - len(dllname))
        ldte.write_back()

        prev.object.InLoadOrderLinks.Flink = ldte.address
        prev.object.InMemoryOrderLinks.Flink = ldte.address + self.sizeof(list_type)

        if first is ldte:
            prev.object.InInitializationOrderLinks.Flink = 0
        else:
            imol = prev.object.InMemoryOrderLinks.Flink
            prev.object.InInitializationOrderLinks.Flink = imol + self.sizeof(list_type)

        ldte.object.InLoadOrderLinks.Blink = prev.address
        ldte.object.InMemoryOrderLinks.Blink = prev.address + self.sizeof(list_type)

        if first is ldte:
            ldte.object.InInitializationOrderLinks.Blink = 0
        else:
            imol = ldte.object.InMemoryOrderLinks.Blink
            ldte.object.InInitializationOrderLinks.Blink = imol + self.sizeof(list_type)

        prev.write_back()
        ldte.write_back()

        first.object.InLoadOrderLinks.Blink = ldte.address
        first.object.InMemoryOrderLinks.Blink = ldte.address + self.sizeof(list_type)
        if first is not ldte:
            first.object.InInitializationOrderLinks.Blink = ldte.address + self.sizeof(list_type) * 2

        first.write_back()

        pld.object.InLoadOrderModuleList.Flink = first.address
        pld.object.InMemoryOrderModuleList.Flink = pld.object.InLoadOrderModuleList.Flink + self.sizeof(list_type)

        # Lets just copy InMemoryOrderModuleList but skip the main EXE module
        head = pld.object.InMemoryOrderModuleList.Flink
        le = self.emu.mem_cast(ntoskrnl.LIST_ENTRY(self.emu.get_ptr_size()), head)

        pld.object.InInitializationOrderModuleList.Flink = le.Flink + self.sizeof(list_type)

        pld.object.InLoadOrderModuleList.Blink = ldte.address
        pld.object.InMemoryOrderModuleList.Blink = ldte.address + self.sizeof(list_type)

        pld.object.InInitializationOrderModuleList.Blink = ldte.address + self.sizeof(list_type) * 2

        pld.write_back()

        self.peb.object.Ldr = pld.address
        self.peb.write_back()

    def init_peb(self, modules):
        # Add an entry for each module in the module list
        for mod in modules:
            self.add_module_to_peb(mod)


class RTL_USER_PROCESS_PARAMETERS(KernelObject):
    def __init__(self, emu, proc):
        super().__init__(emu=emu)

        self.object = self.nt_types.RTL_USER_PROCESS_PARAMETERS(emu.get_ptr_size())

        proc_path = (proc.path + "\x00").encode("utf-16le")
        proc_cmdline = (proc.cmdline + "\x00").encode("utf-16le")

        cur_dir = ntpath.dirname(proc.path)
        if not cur_dir.endswith("\\"):
            cur_dir += "\\"
        cur_dir_enc = (cur_dir + "\x00").encode("utf-16le")

        desktop_name = "WinSta0\\Default\x00"
        desktop_enc = desktop_name.encode("utf-16le")

        string_data_size = len(proc_path) + len(proc_cmdline) + len(cur_dir_enc) + len(desktop_enc)
        size = self.sizeof() + string_data_size
        self.address = emu.mem_map(size, tag=proc.get_mem_tag() + ".ProcessParameters")

        offset = self.address + self.sizeof()
        emu.mem_write(offset, proc_path)
        path_addr = offset
        offset += len(proc_path)

        emu.mem_write(offset, proc_cmdline)
        cmdline_addr = offset
        offset += len(proc_cmdline)

        emu.mem_write(offset, cur_dir_enc)
        cur_dir_addr = offset
        offset += len(cur_dir_enc)

        emu.mem_write(offset, desktop_enc)
        desktop_addr = offset

        self.object.MaximumLength = size
        self.object.Length = size
        self.object.Flags = 1

        self.object.StandardInput = proc.stdin
        self.object.StandardOutput = proc.stdout
        self.object.StandardError = proc.stderr

        self.object.CurrentDirectory.DosPath.Length = len(cur_dir_enc) - 2
        self.object.CurrentDirectory.DosPath.MaximumLength = len(cur_dir_enc)
        self.object.CurrentDirectory.DosPath.Buffer = cur_dir_addr

        self.object.ImagePathName.Length = len(proc_path) - 2
        self.object.ImagePathName.MaximumLength = len(proc_path)
        self.object.ImagePathName.Buffer = path_addr

        self.object.CommandLine.Length = len(proc_cmdline) - 2
        self.object.CommandLine.MaximumLength = len(proc_cmdline)
        self.object.CommandLine.Buffer = cmdline_addr

        self.object.DesktopInfo.Length = len(desktop_enc) - 2
        self.object.DesktopInfo.MaximumLength = len(desktop_enc)
        self.object.DesktopInfo.Buffer = desktop_addr

        self.write_back()


class PEB(KernelObject):
    """
    Represents the process environment block. This structure contains a large amount of
    fields that are used internally by Windows. Shellcode may parse this structure in
    order to resolve exported functions.
    """

    def __init__(self, emu, address=None):
        super().__init__(emu=emu)

        self.object = self.nt_types.PEB(emu.get_ptr_size())
        if not address:
            self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())
        else:
            self.address = address


class TEB(KernelObject):
    """
    Represents the thread environment block. This structure contains a large amount of
    fields that are used internally by Windows.
    """

    def __init__(self, emu, address=0):
        super().__init__(emu=emu)

        self.object = self.nt_types.TEB(emu.get_ptr_size())
        if address:
            self.address = address
        else:
            self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class PebLdrData(KernelObject):
    def __init__(self, emu):
        super().__init__(emu=emu)
        self.object = self.nt_types.PEB_LDR_DATA(emu.get_ptr_size())
        self.address = 0


class LdrDataTableEntry(KernelObject):
    def __init__(self, emu, dllname, tag=""):
        super().__init__(emu=emu)
        self.object = self.nt_types.LDR_DATA_TABLE_ENTRY(emu.get_ptr_size())

        size = self.sizeof()
        size += len((dllname + "\x00").encode("utf-16le"))

        if not tag:
            tag = self.get_mem_tag()

        self.address = emu.mem_map(size, tag=tag)


class IDT(KernelObject):
    """
    Represents the Interrupt descriptor table. This is currently a dummy structure and
    only exists to detect if samples read or write to it.
    """

    def __init__(self, emu):
        super().__init__(emu=emu)

        self.object = self.nt_types.IDT(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())

    def init_descriptors(self):
        tbl = self.nt_types.DESCRIPTOR_TABLE(self.emu.get_ptr_size())

        kbase = self.emu.get_kernel_base()

        descs = self.emu.mem_map(self.sizeof(tbl), tag=self.get_mem_tag() + ".idt_entries")
        self.object.Limit = 0xFFF
        self.object.Descriptors = descs

        if self.emu.get_arch() == _arch.ARCH_X86:
            for i, entry in enumerate(tbl.Table):
                entry.OffsetLow = 0 + (4 * i)
                entry.Base = kbase
        elif self.emu.get_arch() == _arch.ARCH_AMD64:
            for i, entry in enumerate(tbl.Table):
                entry.OffsetLow = 0xFFFF & kbase
                entry.OffsetMiddle = (0xFFFF0000 & kbase) >> 16
                entry.OffsetHigh = (0xFFFFFFFF00000000 & kbase) >> 32

        self.emu.mem_write(descs, self.get_bytes(tbl))

        self.write_back()


class Event(KernelObject):
    """
    Describes event objects used by Windows for synchronization
    """

    def __init__(self, emu):
        super().__init__(emu=emu)
        self.object = self.nt_types.KEVENT(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class Mutant(KernelObject):
    """
    Describes mutant objects used by Windows for synchronization
    """

    def __init__(self, emu):
        super().__init__(emu=emu)
        self.object = self.nt_types.MUTANT(emu.get_ptr_size())
        self.address = emu.mem_map(self.sizeof(), tag=self.get_mem_tag())


class ObjectManager:
    """
    Class that manages kernel objects during emulation
    """

    def __init__(self, emu):
        super().__init__()
        self.emu = emu
        self.objects = {}
        # V2-5-4: symlinks 改为 dict[link.lower()] = target，O(1) 查找
        self.symlinks = {}
        # 反向字典：handle -> object，用于 O(1) 句柄查找与清理
        self._handle_map = {}
        # V2-5-1: name -> object 反向索引，O(1) 按名查找
        self._name_index: dict[str, KernelObject] = {}
        # V2-5-3: id -> object 反向索引，O(1) 按 id 查找
        self._id_index: dict[int, KernelObject] = {}

    def _on_object_rename(self, obj, old_name: str, new_name: str) -> None:
        """
        主题 J：KernelObject.name 变更时同步 _name_index。
        由 KernelObject.name 的 property setter 调用。
        """
        if old_name:
            old_key = old_name.lower()
            if self._name_index.get(old_key) is obj:
                self._name_index.pop(old_key, None)
        if new_name:
            self._name_index[new_name.lower()] = obj

    def add_symlink(self, link, dev):
        # V2-5-4: dict[link.lower()] = target
        self.symlinks[link.lower()] = dev

    def new_object(self, obj_type):

        obj = obj_type(emu=self.emu)
        obj.id = self.new_id()
        return self.add_object(obj)

    def add_object(self, obj):
        if not self.get_object_from_addr(obj.address):
            self.objects.update({obj.address: obj})
        if not obj.id:
            obj.id = self.new_id()
        # V2-5-3: 同步 id 反向索引
        self._id_index[obj.id] = obj
        # V2-5-1: 同步 name 反向索引（name 可能为空，空名不入索引）
        if obj.name:
            self._name_index[obj.name.lower()] = obj
        obj.ref_cnt += 1
        # 对象可能已通过 KernelObject.get_handle 分配过句柄，同步登记到反向字典
        for h in getattr(obj, "handles", []):
            self._handle_map[h] = obj
        return obj

    def remove_object(self, obj):
        """
        Remove an object from the object manager
        V2-5-2: 已持有对象引用，直接用 obj.address 做 O(1) pop，不做全表扫描
        """
        addr = getattr(obj, "address", None)
        if addr is not None and self.objects.get(addr) is obj:
            self.objects.pop(addr, None)
        # V2-5-3: 同步清理 id 反向索引
        obj_id = getattr(obj, "id", None)
        if obj_id is not None and self._id_index.get(obj_id) is obj:
            self._id_index.pop(obj_id, None)
        # V2-5-1: 同步清理 name 反向索引
        obj_name = getattr(obj, "name", None)
        if obj_name:
            name_key = obj_name.lower()
            if self._name_index.get(name_key) is obj:
                self._name_index.pop(name_key, None)
        # 同步清理反向字典中该对象的所有句柄
        for h in list(getattr(obj, "handles", [])):
            if self._handle_map.get(h) is obj:
                self._handle_map.pop(h, None)

    def dec_ref(self, obj):
        """
        Dereferece an object and remove it from the object manager when its reference count is 0
        """
        if hasattr(obj, "ref_cnt"):
            obj.ref_cnt -= 1
            if obj.ref_cnt <= 0:
                self.remove_object(obj)
            return obj.ref_cnt

    def get_handle(self, obj):
        tmp = KernelObject.curr_handle
        KernelObject.curr_handle += 4
        obj.handles.append(tmp)
        # 同步写入反向字典，供 get_object_from_handle 做 O(1) 查找
        self._handle_map[tmp] = obj
        return tmp

    def new_id(self):
        _id = KernelObject.curr_id
        KernelObject.curr_id += 4
        return _id

    def get_object_from_addr(self, addr):
        return self.objects.get(addr)

    def get_object_from_id(self, id):
        # V2-5-3: O(1) 反向索引查找
        return self._id_index.get(id)

    def get_object_from_name(self, name, check_symlinks=True):

        if not name:
            return None
        name = name.rstrip("\\")
        # V2-5-1: O(1) 反向索引查找（name 同步由 KernelObject.name setter 保证）
        obj = self._name_index.get(name.lower())
        if obj is not None:
            return obj
        # 回退：兜底扫描以应对索引未命中的边界场景（如对象在 om 就绪前命名）
        # 命中后回填索引，后续访问恢复 O(1)
        for a, o in self.objects.items():
            if o.name and o.name.lower() == name.lower():
                self._name_index[o.name.lower()] = o
                return o
        # V2-5-4: symlinks 改为 dict，O(1) 查找
        if check_symlinks:
            target = self.symlinks.get(name.lower())
            if target:
                return self.get_object_from_name(target, False)
        return None

    def get_object_from_handle(self, handle):
        # O(1) 反向字典查找
        obj = self._handle_map.get(handle)
        if obj is not None:
            return obj
        # 回退：处理未登记的句柄（如初始化阶段分配的句柄）
        for a, o in self.objects.items():
            if handle in o.handles:
                # 补登记，后续命中 O(1) 路径
                self._handle_map[handle] = o
                return o
        return None

    def close_handle(self, handle):
        """
        关闭句柄：从反向字典移除，并从对象句柄列表删除。
        返回关联的对象（句柄不存在时返回 None，不抛异常）。
        """
        obj = self._handle_map.pop(handle, None)
        if obj is None:
            # 回退：句柄可能未登记到反向字典，扫描对象句柄列表
            for a, o in self.objects.items():
                if handle in getattr(o, "handles", []):
                    obj = o
                    break
        if obj is not None:
            handles = getattr(obj, "handles", None)
            if handles is not None:
                while handle in handles:
                    handles.remove(handle)
        return obj
