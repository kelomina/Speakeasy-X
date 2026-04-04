from __future__ import annotations

import re
import string
from typing import Any

import capstone
import capstone.x86_const as x86_const

import speakeasy.winenv.arch as e_arch


class PseudocodeRenderer:
    def __init__(
        self,
        emu,
        include_comments: bool = True,
        string_encoding: str = "utf8",
        keep_filtered_jumps_in_comments: bool = False,
        show_register_values: bool = False,
        enable_heuristics: bool = False,
    ) -> None:
        self.emu = emu
        self.include_comments = include_comments
        self.string_encoding = string_encoding.lower()
        self.keep_filtered_jumps_in_comments = keep_filtered_jumps_in_comments
        self.show_register_values = show_register_values
        self.enable_heuristics = enable_heuristics
        self.register_aliases: dict[str, str] = {}
        self.memory_aliases: dict[str, str] = {}
        self.pending_compare: dict[str, str] | None = None
        self.local_index = 0
        self.global_index = 0
        self.function_index = 0
        mode = capstone.CS_MODE_64 if emu.get_arch() == e_arch.ARCH_AMD64 else capstone.CS_MODE_32
        self.engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.engine.detail = True

    def render_instruction(self, addr: int, size: int) -> str | None:
        record = self.render_instruction_record(addr, size)
        if record is None:
            return None
        return self.format_instruction_record(record)

    def render_instruction_record(self, addr: int, size: int) -> dict[str, Any] | None:
        try:
            insn = next(self.engine.disasm(self.emu.mem_read(addr, size), addr, count=1))
        except Exception:
            return None
        if insn.mnemonic == "nop":
            return None

        resolved_ops: list[dict[str, Any]] = []
        context: list[str] = []
        for op in insn.operands:
            resolved = self._resolve_operand(insn, op)
            resolved_ops.append(resolved)
            context.extend(part for part in resolved["context"] if isinstance(part, str))
        context.extend(self._get_instruction_annotations(insn, resolved_ops))

        pseudocode = self._to_pseudocode(insn, resolved_ops)
        asm = f"{insn.mnemonic} {insn.op_str}".strip()
        filtered = pseudocode is None
        if filtered and not self.keep_filtered_jumps_in_comments:
            return None
        target_symbol = self._first_resolved_value(resolved_ops, "target_symbol")
        string_value = self._first_resolved_value(resolved_ops, "string_value")
        object_display = self._first_resolved_value(resolved_ops, "object_display")
        variable_aliases = self._collect_variable_aliases(resolved_ops)
        register_values = self._collect_register_values(resolved_ops)
        return {
            "address": f"0x{addr:x}",
            "pseudocode": pseudocode,
            "assembly": asm,
            "context": self._unique(context),
            "filtered": filtered,
            "target_symbol": target_symbol,
            "string_value": string_value,
            "object_display": object_display,
            "variable_aliases": variable_aliases,
            "register_values": register_values,
        }

    def format_instruction_record(self, record: dict[str, Any]) -> str | None:
        address = str(record.get("address") or "")
        pseudocode = record.get("pseudocode")
        assembly = str(record.get("assembly") or "")
        context = [str(item) for item in record.get("context", []) if isinstance(item, str)]
        register_values = record.get("register_values", {})
        register_context = []
        if isinstance(register_values, dict):
            register_context = [f"{key}={value}" for key, value in register_values.items()]
        filtered = bool(record.get("filtered"))
        if filtered:
            if not (self.include_comments and self.keep_filtered_jumps_in_comments):
                return None
            line = f"{address}: // filtered jump: {assembly}"
            if context:
                line = f"{line} | {' | '.join(context)}"
            if register_context:
                line = f"{line} | {' | '.join(register_context)}"
            return line
        line = f"{address}: {pseudocode}"
        if self.include_comments:
            line = f"{line} // {assembly}"
        if context and self.include_comments:
            line = f"{line} | {' | '.join(context)}"
        if register_context and self.include_comments:
            line = f"{line} | {' | '.join(register_context)}"
        return line

    def compact_instruction_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        records = self._prune_noise_records(records)
        if not self.enable_heuristics:
            return records
        records = self._recover_function_aliases(records)
        records = self._recover_global_aliases(records)
        compacted: list[dict[str, Any]] = []
        index = 0
        while index < len(records):
            record = records[index]
            family = self._classify_repeated_block(record)
            if not family:
                compacted.append(record)
                index += 1
                continue
            end = index + 1
            while end < len(records) and self._classify_repeated_block(records[end]) == family:
                end += 1
            if end - index < 2:
                compacted.append(record)
                index += 1
                continue
            compacted.append(self._fold_repeated_block(records[index:end], family))
            index = end
        compacted = self._fold_handwritten_loop_blocks(compacted)
        compacted = self._recover_while_loops(compacted)
        compacted = self._fold_repeated_summary_records(compacted)
        compacted = self._fold_repeated_normalized_windows(compacted)
        compacted = self._fold_repeated_while_chains(compacted)
        return self._fold_repeated_scalar_records(compacted)

    def _resolve_operand(self, insn, operand) -> dict[str, Any]:
        if operand.type == x86_const.X86_OP_REG:
            reg_name = insn.reg_name(operand.reg)
            reg_value_int = self._safe_reg_read(reg_name)
            reg_value = self._format_int(reg_value_int)
            target_symbol = self._resolve_target_symbol(reg_value_int)
            string_value = self._read_string_at(reg_value_int)
            is_this = reg_name in ("ecx", "rcx")
            object_display = self._describe_object_pointer(reg_value_int, prefer_this=is_this)
            variable_alias = self._get_register_alias(reg_name, string_value, object_display, target_symbol)
            context: list[str] = []
            if target_symbol:
                context.append(f"{reg_name}->{target_symbol}")
            if object_display:
                context.append(f"{reg_name}.object={object_display}")
                if is_this:
                    context.append(f"{reg_name}.this={object_display}")
            if string_value:
                context.append(f'{reg_name}.{self._string_label()}="{self._escape_string(string_value)}"')
            if variable_alias and self.enable_heuristics:
                context.append(f"{reg_name}.alias={variable_alias}")
            return {
                "kind": "reg",
                "expr": reg_name,
                "value": reg_value,
                "address": None,
                "dereferenced_value": None,
                "target_symbol": target_symbol,
                "object_display": object_display,
                "variable_alias": variable_alias,
                "register_name": reg_name,
                "string_value": string_value,
                "context": context,
            }

        if operand.type == x86_const.X86_OP_IMM:
            imm_value_int = int(operand.imm)
            imm_value = self._format_int(imm_value_int)
            target_symbol = self._resolve_target_symbol(imm_value_int)
            string_value = self._read_string_at(imm_value_int)
            context: list[str] = []
            if target_symbol:
                context.append(f"{imm_value}->{target_symbol}")
            if string_value:
                context.append(f'{imm_value}.{self._string_label()}="{self._escape_string(string_value)}"')
            return {
                "kind": "imm",
                "expr": imm_value,
                "value": imm_value,
                "address": None,
                "dereferenced_value": None,
                "target_symbol": target_symbol,
                "object_display": None,
                "variable_alias": None,
                "register_name": None,
                "string_value": string_value,
                "context": context,
            }

        if operand.type == x86_const.X86_OP_MEM:
            address, reg_context = self._resolve_memory_address(insn, operand.mem)
            base_reg_name = insn.reg_name(operand.mem.base) if operand.mem.base else ""
            base_reg_value = self._safe_reg_read(base_reg_name) if base_reg_name else 0
            expr = "[mem]"
            value = "?"
            context = list(reg_context)
            target_symbol = None
            string_value = None
            object_display = None
            memory_alias = None
            if address is not None:
                expr = f"[{self._format_int(address)}]"
                read_size = operand.size or self.emu.get_ptr_size()
                data = self._safe_mem_read(address, read_size)
                if data is not None:
                    value = self._format_memory_value(data)
                    context.append(f"{expr}={value}")
                    preview = self._format_string_preview(data)
                    if preview:
                        context.append(f"{expr}.{self._string_label()}={preview}")
                string_value = self._read_string_at(address)
                if string_value:
                    context.append(f'{expr}.{self._string_label()}="{self._escape_string(string_value)}"')
                ptr_data = self._safe_mem_read(address, self.emu.get_ptr_size())
                if ptr_data is not None and len(ptr_data) == self.emu.get_ptr_size():
                    ptr_value = int.from_bytes(ptr_data, "little")
                    pointed_string = self._read_string_at(ptr_value) if not string_value else string_value
                    target_symbol = self._resolve_indirect_target(address, ptr_value, base_reg_name, base_reg_value)
                    object_display = self._describe_object_slot(
                        address,
                        ptr_value,
                        base_reg_name=base_reg_name,
                        base_reg_value=base_reg_value,
                    )
                    memory_alias = self._get_memory_alias(
                        base_reg_name,
                        operand.mem.disp,
                        address,
                        pointed_string,
                        object_display,
                    )
                    if target_symbol:
                        context.append(f"{expr}->{target_symbol}")
                    if object_display:
                        context.append(f"{expr}.object={object_display}")
                    if memory_alias and self.enable_heuristics:
                        context.append(f"{expr}.alias={memory_alias}")
                    if not string_value and pointed_string:
                        string_value = pointed_string
                        context.append(f'{expr}->{self._string_label()}="{self._escape_string(pointed_string)}"')
                if not memory_alias:
                    memory_alias = self._get_memory_alias(
                        base_reg_name,
                        operand.mem.disp,
                        address,
                        string_value,
                        object_display,
                    )
            return {
                "kind": "mem",
                "expr": expr,
                "value": value,
                "address": self._format_int(address) if address is not None else None,
                "dereferenced_value": value,
                "target_symbol": target_symbol,
                "object_display": object_display,
                "memory_alias": memory_alias,
                "variable_alias": memory_alias,
                "register_name": None,
                "string_value": string_value,
                "context": context,
            }

        return {
            "kind": "other",
            "expr": "?",
            "value": "?",
            "address": None,
            "dereferenced_value": None,
            "target_symbol": None,
            "object_display": None,
            "memory_alias": None,
            "variable_alias": None,
            "register_name": None,
            "string_value": None,
            "context": [],
        }

    def _resolve_memory_address(self, insn, mem) -> tuple[int | None, list[str]]:
        parts: list[str] = []
        address = mem.disp

        if mem.base:
            base_name = insn.reg_name(mem.base)
            if base_name == "rip":
                base_value = insn.address + insn.size
            else:
                base_value = self._safe_reg_read(base_name)
            address += base_value
            if self.show_register_values:
                parts.append(f"{base_name}={self._format_int(base_value)}")

        if mem.index:
            index_name = insn.reg_name(mem.index)
            index_value = self._safe_reg_read(index_name)
            address += index_value * mem.scale
            if self.show_register_values:
                parts.append(f"{index_name}={self._format_int(index_value)}")

        if mem.segment:
            segment_name = insn.reg_name(mem.segment)
            segment_value = self._safe_reg_read(segment_name)
            if self.show_register_values:
                parts.append(f"{segment_name}={self._format_int(segment_value)}")

        return address, parts

    def _to_pseudocode(self, insn, operands: list[dict[str, Any]]) -> str | None:
        mnemonic = insn.mnemonic
        if mnemonic == "nop":
            return None
        if mnemonic in {"cmp", "test"}:
            exprs = [self._render_expr(op) for op in operands]
            if len(exprs) == 2:
                self.pending_compare = {
                    "mnemonic": mnemonic,
                    "left": exprs[0],
                    "right": exprs[1],
                }
        elif mnemonic.startswith("j"):
            if self.enable_heuristics and self.pending_compare:
                condition = self._render_compare_condition(mnemonic, self.pending_compare)
                self.pending_compare = None
                return f"if ({condition})"
            return None
        else:
            self.pending_compare = None
        if mnemonic.startswith("j"):
            return None
        exprs = [self._render_expr(op) for op in operands]
        raw_exprs = [str(op["expr"]) for op in operands]
        lvalues = [self._render_lvalue(op) for op in operands]

        if mnemonic in {"push", "pop"}:
            return None
        if mnemonic in {"add", "sub"} and lvalues and lvalues[0] in {"rsp", "esp"}:
            return None
        if mnemonic == "mov" and len(exprs) == 2 and lvalues[0] in {"rbp", "ebp"} and exprs[1] in {"rsp", "esp"}:
            return None
        if mnemonic == "mov" and self._is_stack_spill_move(insn):
            return None

        if mnemonic == "mov" and len(exprs) == 2:
            return f"{lvalues[0]} = {exprs[1]}"
        if mnemonic == "lea" and len(exprs) == 2:
            string_value = operands[1].get("string_value")
            if isinstance(string_value, str) and string_value:
                return f'{lvalues[0]} = &"{self._escape_string(string_value)}"'
            target_symbol = operands[1].get("target_symbol")
            if isinstance(target_symbol, str) and target_symbol:
                return f"{lvalues[0]} = &{target_symbol}"
            src = operands[1].get("address") or exprs[1]
            return f"{lvalues[0]} = &{src}"
        if mnemonic == "call" and len(exprs) == 1:
            return f"call {exprs[0]}"
        if mnemonic == "ret":
            return "return"
        if mnemonic == "cmp" and len(exprs) == 2:
            return f"compare({exprs[0]}, {exprs[1]})"
        if mnemonic == "test" and len(exprs) == 2:
            return f"test({exprs[0]}, {exprs[1]})"
        if mnemonic == "jmp" and len(exprs) == 1:
            return f"goto {exprs[0]}"
        if mnemonic in {"je", "jz"} and len(exprs) == 1:
            return f"if ZF goto {exprs[0]}"
        if mnemonic in {"jne", "jnz"} and len(exprs) == 1:
            return f"if !ZF goto {exprs[0]}"
        if mnemonic in {"ja", "jnbe"} and len(exprs) == 1:
            return f"if above goto {exprs[0]}"
        if mnemonic in {"jae", "jnb", "jnc"} and len(exprs) == 1:
            return f"if above_or_equal goto {exprs[0]}"
        if mnemonic in {"jb", "jnae", "jc"} and len(exprs) == 1:
            return f"if below goto {exprs[0]}"
        if mnemonic in {"jbe", "jna"} and len(exprs) == 1:
            return f"if below_or_equal goto {exprs[0]}"
        if mnemonic in {"jg", "jnle"} and len(exprs) == 1:
            return f"if greater goto {exprs[0]}"
        if mnemonic in {"jge", "jnl"} and len(exprs) == 1:
            return f"if greater_or_equal goto {exprs[0]}"
        if mnemonic in {"jl", "jnge"} and len(exprs) == 1:
            return f"if less goto {exprs[0]}"
        if mnemonic in {"jle", "jng"} and len(exprs) == 1:
            return f"if less_or_equal goto {exprs[0]}"
        if mnemonic == "xor" and len(exprs) == 2 and lvalues[0] == self._render_lvalue(operands[1]):
            return f"{lvalues[0]} = 0"
        if mnemonic in {"add", "sub", "xor", "and", "or", "shl", "shr", "ror", "rol"} and len(exprs) == 2:
            operator = {
                "add": "+",
                "sub": "-",
                "xor": "^",
                "and": "&",
                "or": "|",
                "shl": "<<",
                "shr": ">>",
                "ror": "ror",
                "rol": "rol",
            }[mnemonic]
            if mnemonic in {"ror", "rol"}:
                return f"{lvalues[0]} = {operator}({lvalues[0]}, {exprs[1]})"
            return f"{lvalues[0]} = {lvalues[0]} {operator} {exprs[1]}"
        if mnemonic == "inc" and len(exprs) == 1:
            return f"{lvalues[0]} = {lvalues[0]} + 1"
        if mnemonic == "dec" and len(exprs) == 1:
            return f"{lvalues[0]} = {lvalues[0]} - 1"
        if mnemonic == "neg" and len(exprs) == 1:
            return f"{lvalues[0]} = -{lvalues[0]}"
        if mnemonic == "not" and len(exprs) == 1:
            return f"{lvalues[0]} = ~{lvalues[0]}"
        joined = ", ".join(exprs)
        return f"{mnemonic}({joined})" if joined else mnemonic

    def _render_expr(self, operand: dict[str, Any]) -> str:
        target_symbol = operand.get("target_symbol")
        if isinstance(target_symbol, str) and target_symbol:
            return self._get_function_alias(target_symbol)
        object_display = operand.get("object_display")
        if isinstance(object_display, str) and object_display:
            return object_display
        variable_alias = operand.get("variable_alias")
        if self.enable_heuristics and isinstance(variable_alias, str) and variable_alias:
            return variable_alias
        string_value = operand.get("string_value")
        if isinstance(string_value, str) and string_value:
            return f'"{self._escape_string(string_value)}"'
        return str(operand["expr"])

    def _render_lvalue(self, operand: dict[str, Any]) -> str:
        variable_alias = operand.get("variable_alias")
        if self.enable_heuristics and isinstance(variable_alias, str) and variable_alias:
            return variable_alias
        object_display = operand.get("object_display")
        if isinstance(object_display, str) and object_display and str(operand.get("kind")) == "mem":
            return object_display
        return str(operand["expr"])

    def _resolve_target_symbol(self, address: int | None) -> str | None:
        if address is None or address <= 0:
            return None
        try:
            symbol = self.emu.get_symbol_from_address(address)
        except Exception:
            symbol = None
        if symbol:
            return symbol
        import_entry = getattr(self.emu, "import_table", {}).get(address)
        if import_entry:
            return "{}.{}".format(*import_entry)
        curr_mod = getattr(self.emu, "curr_mod", None)
        if curr_mod and hasattr(curr_mod, "import_table"):
            mod_import_entry = curr_mod.import_table.get(address)
            if mod_import_entry:
                return "{}.{}".format(*mod_import_entry)
        return None

    def _resolve_indirect_target(
        self,
        operand_address: int,
        ptr_value: int,
        base_reg_name: str = "",
        base_reg_value: int = 0,
    ) -> str | None:
        target_symbol = self._resolve_target_symbol(ptr_value)
        if target_symbol:
            return target_symbol
        if base_reg_name in ("ecx", "rcx"):
            this_vtable = self._describe_vtable_pointer(self._safe_read_ptr(base_reg_value))
            if this_vtable:
                slot_offset = max(0, operand_address - base_reg_value)
                return f"{this_vtable}+0x{slot_offset:x}"
        target_symbol = self._resolve_target_symbol(operand_address)
        if target_symbol:
            return target_symbol
        vtable_slot = self._describe_vtable_slot(operand_address, ptr_value, base_reg_name, base_reg_value)
        if vtable_slot:
            return vtable_slot
        tag = self._safe_address_tag(operand_address)
        if not tag:
            return None
        if not any(name in tag.lower() for name in ("com", "callback", "vtable")):
            return None
        base_offset = operand_address - self._safe_module_base(operand_address)
        return f"{tag}+0x{base_offset:x}"

    def _describe_object_pointer(self, address: int, prefer_this: bool = False) -> str | None:
        if address <= 0:
            return None
        tag = self._safe_address_tag(address)
        if tag and any(name in tag.lower() for name in ("obj", "this", "com", "callback")):
            vtable_ptr = self._safe_read_ptr(address)
            if vtable_ptr:
                vtable_name = self._describe_vtable_pointer(vtable_ptr)
                if vtable_name:
                    return f"{tag}(vtable={vtable_name})"
            return "this" if prefer_this else tag
        vtable_ptr = self._safe_read_ptr(address)
        vtable_name = self._describe_vtable_pointer(vtable_ptr)
        if vtable_name:
            return f"this(vtable={vtable_name})" if prefer_this else f"object(vtable={vtable_name})"
        return None

    def _describe_object_slot(
        self,
        slot_address: int,
        ptr_value: int,
        base_reg_name: str = "",
        base_reg_value: int = 0,
    ) -> str | None:
        if base_reg_name in ("ecx", "rcx"):
            this_vtable = self._describe_vtable_pointer(ptr_value)
            if this_vtable:
                return f"this.vtable({this_vtable})"
            return "this.vtable"
        slot_tag = self._safe_address_tag(slot_address)
        if slot_tag and any(name in slot_tag.lower() for name in ("obj", "this", "com", "callback")):
            vtable_name = self._describe_vtable_pointer(ptr_value)
            if vtable_name:
                return f"{slot_tag}.vtable({vtable_name})"
            return f"{slot_tag}.vtable"
        return self._describe_vtable_pointer(ptr_value)

    def _describe_vtable_pointer(self, address: int) -> str | None:
        if address <= 0:
            return None
        target_symbol = self._resolve_target_symbol(address)
        if target_symbol:
            return target_symbol
        tag = self._safe_address_tag(address)
        if tag and any(name in tag.lower() for name in ("vtable", "com", "callback")):
            return tag
        method_ptr = self._safe_read_ptr(address)
        method_symbol = self._resolve_target_symbol(method_ptr)
        if method_symbol:
            return f"vtable({method_symbol})"
        return None

    def _describe_vtable_slot(
        self,
        slot_address: int,
        ptr_value: int,
        base_reg_name: str = "",
        base_reg_value: int = 0,
    ) -> str | None:
        if base_reg_name in ("ecx", "rcx") and base_reg_value:
            this_vtable = self._safe_read_ptr(base_reg_value)
            this_vtable_name = self._describe_vtable_pointer(this_vtable)
            if this_vtable_name:
                return f"{this_vtable_name}+0x{slot_address - base_reg_value:x}"
        slot_tag = self._safe_address_tag(slot_address)
        if slot_tag and any(name in slot_tag.lower() for name in ("vtable", "com", "callback")):
            return f"{slot_tag}+0x{slot_address - self._safe_module_base(slot_address):x}"
        ptr_symbol = self._resolve_target_symbol(ptr_value)
        if ptr_symbol:
            return ptr_symbol
        vtable_base = slot_address - (slot_address % self.emu.get_ptr_size())
        vtable_name = self._describe_vtable_pointer(vtable_base)
        if vtable_name:
            return f"{vtable_name}+0x{slot_address - vtable_base:x}"
        return None

    def _read_string_at(self, address: int | None, min_chars: int = 4, max_chars: int = 64) -> str | None:
        if address is None or address <= 0:
            return None
        try:
            width = 2 if self.string_encoding == "utf16" else 1
            string_value = self.emu.read_mem_string(address, width=width, max_chars=max_chars)
        except Exception:
            return None
        if not isinstance(string_value, str):
            return None
        string_value = string_value.strip("\x00")
        if len(string_value) < min_chars:
            return None
        if any(ch not in string.printable or ch in "\r\n\t\x0b\x0c" for ch in string_value):
            return None
        return string_value

    def _safe_reg_read(self, reg_name: str) -> int:
        try:
            return int(self.emu.reg_read(reg_name))
        except Exception:
            return 0

    def _safe_mem_read(self, address: int, size: int) -> bytes | None:
        try:
            return self.emu.mem_read(address, size)
        except Exception:
            return None

    def _safe_read_ptr(self, address: int) -> int:
        data = self._safe_mem_read(address, self.emu.get_ptr_size())
        if not data or len(data) != self.emu.get_ptr_size():
            return 0
        return int.from_bytes(data, "little")

    def _format_memory_value(self, data: bytes) -> str:
        if len(data) <= 8:
            return self._format_int(int.from_bytes(data, "little"))
        hex_data = data.hex()
        if len(hex_data) > 32:
            hex_data = f"{hex_data[:32]}..."
        return f"0x{hex_data}"

    def _format_string_preview(self, data: bytes) -> str | None:
        if self.string_encoding == "utf16":
            preview = data[:48]
            try:
                decoded = preview.decode("utf-16le", errors="ignore").split("\x00", 1)[0][:24]
            except Exception:
                return None
            if len(decoded) < 4:
                return None
            if any(ch not in string.printable or ch in "\r\n\t\x0b\x0c" for ch in decoded):
                return None
            return repr(decoded)
        preview = data.split(b"\x00", 1)[0][:24]
        if len(preview) < 4:
            return None
        if any(chr(byte) not in string.printable or chr(byte) in "\r\n\t\x0b\x0c" for byte in preview):
            return None
        return repr(preview.decode("ascii", errors="ignore"))

    def _escape_string(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _safe_address_tag(self, address: int) -> str | None:
        try:
            return self.emu.get_address_tag(address)
        except Exception:
            return None

    def _safe_module_base(self, address: int) -> int:
        try:
            mod = self.emu.get_mod_from_addr(address)
        except Exception:
            mod = None
        if mod and hasattr(mod, "base"):
            return int(mod.base)
        return address

    def _string_label(self) -> str:
        return "utf16" if self.string_encoding == "utf16" else "utf8"

    def _collect_variable_aliases(self, operands: list[dict[str, Any]]) -> dict[str, str]:
        if not self.enable_heuristics:
            return {}
        aliases: dict[str, str] = {}
        for operand in operands:
            register_name = operand.get("register_name")
            variable_alias = operand.get("variable_alias")
            if isinstance(register_name, str) and isinstance(variable_alias, str) and variable_alias:
                aliases[register_name] = variable_alias
        return aliases

    def _collect_register_values(self, operands: list[dict[str, Any]]) -> dict[str, str]:
        if not self.show_register_values:
            return {}
        values: dict[str, str] = {}
        for operand in operands:
            register_name = operand.get("register_name")
            value = operand.get("value")
            if isinstance(register_name, str) and isinstance(value, str):
                values[register_name] = value
        return values

    def _first_resolved_value(self, operands: list[dict[str, Any]], key: str) -> str | None:
        for operand in operands:
            value = operand.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def _get_register_alias(
        self,
        reg_name: str,
        string_value: str | None,
        object_display: str | None,
        target_symbol: str | None,
    ) -> str | None:
        if not self.enable_heuristics:
            return None
        if reg_name in self.register_aliases:
            return self.register_aliases[reg_name]
        alias = None
        if reg_name in ("ecx", "rcx") and self._is_this_object_display(object_display):
            alias = "thisObj"
        elif string_value:
            lower_string = string_value.lower()
            if "\\" in string_value or "/" in string_value:
                alias = "filePath"
            elif ".exe" in lower_string or ".dll" in lower_string:
                alias = "modulePath"
            else:
                alias = "localPath"
        elif target_symbol:
            alias = target_symbol.rsplit(".", 1)[-1]
        elif reg_name in ("eax", "rax"):
            alias = "retVal"
        elif reg_name in ("edx", "rdx"):
            alias = "arg_2"
        elif reg_name in ("ecx", "rcx"):
            alias = "arg_1"
        if alias:
            self.register_aliases[reg_name] = alias
        return alias

    def _get_memory_alias(
        self,
        base_reg_name: str,
        disp: int,
        address: int | None,
        string_value: str | None,
        object_display: str | None,
    ) -> str | None:
        if not self.enable_heuristics or address is None:
            return None
        address_key = self._format_int(address)
        if address_key in self.memory_aliases:
            return self.memory_aliases[address_key]
        alias = None
        if base_reg_name in ("rbp", "ebp"):
            if disp < 0:
                alias = self._allocate_local_alias(string_value)
            else:
                alias = f"arg_{max(1, disp // max(self.emu.get_ptr_size(), 1))}"
        elif base_reg_name in ("rsp", "esp"):
            alias = self._allocate_local_alias(string_value)
        elif base_reg_name in ("rcx", "ecx") and self._is_this_object_display(object_display):
            alias = f"thisObj.member_{abs(disp):x}"
        else:
            tag = self._safe_address_tag(address)
            if tag:
                alias = self._normalize_tag_alias(tag, address)
            else:
                alias = self._allocate_global_alias(address)
        if alias:
            self.memory_aliases[address_key] = alias
        return alias

    def _allocate_local_alias(self, string_value: str | None) -> str:
        self.local_index += 1
        if string_value:
            lower_string = string_value.lower()
            if "\\" in string_value or "/" in string_value:
                return "localPath"
            if ".exe" in lower_string or ".dll" in lower_string:
                return "localModulePath"
        return f"local_var_{self.local_index}"

    def _allocate_global_alias(self, address: int | None = None) -> str:
        if isinstance(address, int) and address > 0:
            return f"global_{address:x}"
        self.global_index += 1
        return f"global_var_{self.global_index}"

    def _normalize_tag_alias(self, tag: str, address: int) -> str:
        normalized_tag = tag.strip()
        if normalized_tag.lower().startswith("emu.module."):
            return self._build_module_alias(normalized_tag, address)
        sanitized = self._sanitize_alias_text(normalized_tag, max_parts=8, max_length=40)
        if sanitized:
            return sanitized
        return self._allocate_global_alias(address)

    def _build_module_alias(self, tag: str, address: int) -> str:
        module_name = re.sub(r"^emu\.module\.", "", tag, flags=re.IGNORECASE)
        module_name = re.sub(r"\.0x[0-9a-f]+$", "", module_name, flags=re.IGNORECASE)
        alias_root = self._sanitize_alias_text(module_name, max_parts=6, max_length=24) or "module"
        module_base = self._safe_module_base(address)
        offset = address - module_base if module_base <= address else address
        if offset <= 0:
            return f"g_{alias_root}"
        return f"g_{alias_root}_{offset:x}"

    def _sanitize_alias_text(self, value: str, max_parts: int = 8, max_length: int = 40) -> str:
        parts = re.findall(r"[A-Za-z0-9]+", value)
        if not parts:
            return ""
        sanitized = "_".join(parts[:max_parts]).strip("_")
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length].rstrip("_")
        if sanitized and sanitized[0].isdigit():
            sanitized = f"v_{sanitized}"
        return sanitized

    def _render_compare_condition(self, mnemonic: str, compare_info: dict[str, str]) -> str:
        left = compare_info.get("left", "?")
        right = compare_info.get("right", "?")
        operator_map = {
            "je": "==",
            "jz": "==",
            "jne": "!=",
            "jnz": "!=",
            "ja": ">",
            "jnbe": ">",
            "jae": ">=",
            "jnb": ">=",
            "jnc": ">=",
            "jb": "<",
            "jnae": "<",
            "jc": "<",
            "jbe": "<=",
            "jna": "<=",
            "jg": ">",
            "jnle": ">",
            "jge": ">=",
            "jnl": ">=",
            "jl": "<",
            "jnge": "<",
            "jle": "<=",
            "jng": "<=",
        }
        operator = operator_map.get(mnemonic, "!=")
        if compare_info.get("mnemonic") == "test" and right == left:
            right = "0"
            operator = "!=" if mnemonic in {"jne", "jnz"} else "=="
        return f"{left} {operator} {right}"

    def _get_function_alias(self, target_symbol: str) -> str:
        if not self.enable_heuristics:
            return target_symbol
        if "." in target_symbol:
            return self._normalize_import_name(target_symbol)
        if target_symbol.startswith("sub_") or target_symbol.startswith("loc_"):
            self.function_index += 1
            return f"function_{self.function_index}"
        if target_symbol.startswith("0x"):
            self.function_index += 1
            return f"function_{self.function_index}"
        return target_symbol

    def _recover_function_aliases(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        alias_map: dict[str, str] = {}
        recovered: list[dict[str, Any]] = [dict(record) for record in records]
        for index, record in enumerate(recovered):
            pseudocode = str(record.get("pseudocode") or "")
            assembly = str(record.get("assembly") or "")
            if not pseudocode.startswith("call "):
                continue
            call_target = pseudocode[5:].strip()
            assembly_target = self._extract_call_operand(assembly)
            if call_target in alias_map:
                record["pseudocode"] = f"call {alias_map[call_target]}"
                record["target_symbol"] = alias_map[call_target]
                continue
            if assembly_target in alias_map:
                record["pseudocode"] = f"call {alias_map[assembly_target]}"
                record["target_symbol"] = alias_map[assembly_target]
                continue
            if not self._is_synthetic_function_target(call_target, assembly_target):
                continue
            inferred_alias = self._infer_function_alias_from_context(recovered, index)
            if not inferred_alias:
                continue
            if call_target:
                alias_map[call_target] = inferred_alias
            if assembly_target:
                alias_map[assembly_target] = inferred_alias
            record["pseudocode"] = f"call {inferred_alias}"
            record["target_symbol"] = inferred_alias
        return recovered

    def _recover_global_aliases(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        alias_scores: dict[str, dict[str, int]] = {}
        recovered: list[dict[str, Any]] = [dict(record) for record in records]
        for index, record in enumerate(recovered):
            pseudocode = str(record.get("pseudocode") or "")
            if not pseudocode:
                continue
            for global_alias, candidate, score in self._extract_global_alias_candidates(recovered, index, pseudocode):
                if not candidate:
                    continue
                alias_scores.setdefault(global_alias, {})
                alias_scores[global_alias][candidate] = alias_scores[global_alias].get(candidate, 0) + score
        rename_map: dict[str, str] = {}
        for global_alias, candidates in alias_scores.items():
            best = sorted(candidates.items(), key=lambda item: (-item[1], item[0]))[0][0]
            usage_name = self._to_global_usage_candidate(best)
            renamed = f"g_{self._sanitize_alias_text(usage_name, max_parts=4, max_length=28)}"
            if renamed and renamed != global_alias:
                rename_map[global_alias] = renamed
        for global_alias in self._extract_unknown_global_aliases(recovered):
            classified_alias = self._classify_unknown_global_alias(recovered, global_alias)
            if not classified_alias or classified_alias == global_alias:
                continue
            if global_alias in rename_map and not self._should_override_global_alias(rename_map[global_alias], classified_alias):
                continue
            if classified_alias and classified_alias != global_alias:
                rename_map[global_alias] = classified_alias
        if not rename_map:
            return recovered
        return [self._apply_alias_renames(record, rename_map) for record in recovered]

    def _extract_global_alias_candidates(
        self,
        records: list[dict[str, Any]],
        index: int,
        pseudocode: str,
    ) -> list[tuple[str, str, int]]:
        patterns = [
            (r"xchg\((g_[A-Za-z0-9_]+), ([A-Za-z_][A-Za-z0-9_]*)\)", 6),
            (r"xchg\(([A-Za-z_][A-Za-z0-9_]*), (g_[A-Za-z0-9_]+)\)", 6),
            (r"(g_[A-Za-z0-9_]+)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", 4),
            (r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(g_[A-Za-z0-9_]+)", 3),
        ]
        candidates: list[tuple[str, str, int]] = []
        for pattern, score in patterns:
            for left, right in re.findall(pattern, pseudocode):
                if left.startswith("g_"):
                    global_alias = left
                    candidate = right
                else:
                    global_alias = right
                    candidate = left
                if self._is_low_value_alias_name(candidate):
                    continue
                candidates.append((global_alias, candidate, score))
        explicit_api_assign = self._extract_explicit_api_assignment_candidate(pseudocode)
        if explicit_api_assign:
            candidates.append(explicit_api_assign)
        api_assign = re.match(r"(g_[A-Za-z0-9_]+)\s*=\s*api\.[^.]+\.[^.]+\.([A-Za-z_][A-Za-z0-9_]*)", pseudocode)
        if api_assign:
            global_alias, api_name = api_assign.groups()
            normalized_name = self._to_global_usage_candidate(api_name)
            if not self._is_low_value_alias_name(normalized_name):
                candidates.append((global_alias, normalized_name, 8))
        for global_alias in self._extract_retval_global_aliases(pseudocode):
            contextual_name = self._get_recent_call_candidate(records, index)
            if contextual_name and not self._is_low_value_alias_name(contextual_name):
                candidates.append((global_alias, contextual_name, 5))
        return candidates

    def _extract_explicit_api_assignment_candidate(self, pseudocode: str) -> tuple[str, str, int] | None:
        mappings = {
            ".GetCommandLineA.": "CommandLineA",
            ".GetCommandLineW.": "CommandLineW",
            ".LoadLibraryExA.": "LoadedModule",
            ".LoadLibraryExW.": "LoadedModule",
            ".LoadLibraryEx.": "LoadedModule",
            ".LoadLibraryA.": "LoadedModule",
            ".LoadLibraryW.": "LoadedModule",
            ".FlsAlloc.": "FlsIndex",
            ".FlsGetValue2.": "FlsGetValue",
        }
        alias_match = re.match(r"(g_[A-Za-z0-9_]+)\s*=\s*api\.", pseudocode)
        if not alias_match:
            return None
        global_alias = alias_match.group(1)
        for marker, candidate in mappings.items():
            if marker in pseudocode:
                return global_alias, candidate, 12
        return None

    def _extract_retval_global_aliases(self, pseudocode: str) -> list[str]:
        patterns = [
            r"(g_[A-Za-z0-9_]+)\s*=\s*retVal",
            r"xchg\((g_[A-Za-z0-9_]+), retVal\)",
            r"xchg\(retVal, (g_[A-Za-z0-9_]+)\)",
        ]
        aliases: list[str] = []
        for pattern in patterns:
            aliases.extend(re.findall(pattern, pseudocode))
        return aliases

    def _get_recent_call_candidate(self, records: list[dict[str, Any]], index: int) -> str | None:
        window_start = max(0, index - 4)
        for cursor in range(index - 1, window_start - 1, -1):
            pseudocode = str(records[cursor].get("pseudocode") or "")
            if not pseudocode.startswith("call "):
                continue
            target = pseudocode[5:].strip()
            if not target:
                continue
            target = target.rsplit(".", 1)[-1]
            if target.startswith("function_") or target.startswith("sub_") or target.startswith("0x"):
                continue
            return self._to_global_usage_candidate(target)
        return None

    def _to_global_usage_candidate(self, value: str) -> str:
        normalized = self._normalize_import_name(value)
        usage_map = {
            "CommandLineA": "CommandLineBufferA",
            "CommandLineW": "CommandLineBufferW",
            "CommandLine": "CommandLineBuffer",
            "LoadedModule": "LoadedModuleHandle",
            "FlsIndex": "FlsSlotIndex",
            "FlsGetValue": "FlsGetValueFn",
            "GetCommandLineA": "CommandLineBufferA",
            "GetCommandLineW": "CommandLineBufferW",
            "GetCommandLine": "CommandLineBuffer",
            "LoadLibraryEx": "LoadedModuleHandle",
            "LoadLibrary": "LoadedModuleHandle",
            "LoadLibraryA": "LoadedModuleHandle",
            "LoadLibraryW": "LoadedModuleHandle",
            "FlsAlloc": "FlsSlotIndex",
            "FlsGetValue2": "FlsGetValueFn",
        }
        if value in usage_map:
            return usage_map[value]
        if normalized in usage_map:
            return usage_map[normalized]
        return normalized

    def _is_low_value_alias_name(self, value: str) -> bool:
        lowered = value.lower()
        if lowered.startswith(("g_", "global_", "arg_", "local_var_", "function_")):
            return True
        if lowered in {"retval", "localpath", "filepath", "modulepath", "thisobj", "this", "void", "api"}:
            return True
        return False

    def _should_override_global_alias(self, current_alias: str, classified_alias: str) -> bool:
        if current_alias == "g_TlsAccess" and classified_alias.startswith(("g_table_", "g_tls_slot_", "g_slot_")):
            return True
        return False

    def _extract_unknown_global_aliases(self, records: list[dict[str, Any]]) -> list[str]:
        aliases: set[str] = set()
        pattern = r"\bg_vhdx_backup_[0-9a-f]+\b"
        for record in records:
            texts = [
                str(record.get("pseudocode") or ""),
                str(record.get("assembly") or ""),
                str(record.get("target_symbol") or ""),
            ]
            texts.extend(str(item) for item in record.get("context", []) if isinstance(item, str))
            for text in texts:
                aliases.update(re.findall(pattern, text))
        return sorted(aliases)

    def _classify_unknown_global_alias(self, records: list[dict[str, Any]], global_alias: str) -> str | None:
        suffix_match = re.search(r"_([0-9a-f]+)$", global_alias)
        suffix = suffix_match.group(1) if suffix_match else "var"
        usage_texts: list[str] = []
        wide_usage_texts: list[str] = []
        for index, record in enumerate(records):
            pseudocode = str(record.get("pseudocode") or "")
            assembly = str(record.get("assembly") or "")
            if global_alias in pseudocode or global_alias in assembly:
                start = max(0, index - 2)
                end = min(len(records), index + 3)
                for neighbor in records[start:end]:
                    usage_texts.append(str(neighbor.get("pseudocode") or ""))
                usage_texts.append(assembly)
                wide_start = max(0, index - 24)
                wide_end = min(len(records), index + 31)
                for neighbor in records[wide_start:wide_end]:
                    wide_usage_texts.append(str(neighbor.get("pseudocode") or ""))
        joined = "\n".join(usage_texts)
        wide_joined = "\n".join(wide_usage_texts) if wide_usage_texts else joined
        small_values = {
            int(match, 16)
            for match in re.findall(rf"{re.escape(global_alias)}\s*=\s*0x([0-9a-f]+)", joined)
            if len(match) <= 4
        }
        if re.search(rf"(localPath|filePath|modulePath)\s*=\s*{re.escape(global_alias)}", joined):
            return f"g_path_{suffix}"
        if re.search(rf"{re.escape(global_alias)}\s*=\s*(localPath|filePath|modulePath)", joined):
            return f"g_path_ptr_{suffix}"
        if "LoadLibrary" in joined and any(
            re.search(pattern, joined)
            for pattern in (
                rf"{re.escape(global_alias)}\s*=\s*retVal",
                rf"xchg\({re.escape(global_alias)}, retVal\)",
                rf"xchg\(retVal, {re.escape(global_alias)}\)",
            )
        ):
            return f"g_module_handle_{suffix}"
        if "GetProcAddress" in wide_joined and any(
            re.search(pattern, wide_joined)
            for pattern in (
                rf"{re.escape(global_alias)}\s*=\s*retVal",
                rf"xchg\({re.escape(global_alias)}, retVal\)",
            )
        ):
            return f"g_proc_cache_{suffix}"
        if "GetProcessHeap" in joined and any(
            re.search(pattern, joined)
            for pattern in (
                rf"{re.escape(global_alias)}\s*=\s*retVal",
                rf"retVal\s*=\s*{re.escape(global_alias)}",
            )
        ):
            return f"g_heap_handle_{suffix}"
        if any(token in joined for token in ("lock inc(", "xadd(")) or re.search(
            rf"{re.escape(global_alias)}\s*=\s*{re.escape(global_alias)}\s*[\+\-]\s*1\b",
            joined,
        ):
            return f"g_counter_{suffix}"
        if any(token in joined for token in ("movups(", "movdqa(", "movdqu(")):
            return f"g_vector_{suffix}"
        if re.search(rf"(compare|test)\({re.escape(global_alias)}, 0x0\)", joined) and small_values.issubset({0, 1}):
            return f"g_flag_{suffix}"
        if len(small_values) >= 2 or any(value > 1 for value in small_values):
            return f"g_state_{suffix}"
        if re.search(rf"arg_\d+\s*=\s*{re.escape(global_alias)}", wide_joined):
            slot_compares = re.findall(r"compare\(g_slot_[A-Za-z0-9_]+,\s*arg_\d+\)", wide_joined)
            static_arg_sources = re.findall(r"arg_\d+\s*=\s*&0x140[0-9a-f]+", wide_joined)
            if len(slot_compares) >= 2:
                return f"g_slot_table_{suffix}"
            if len(static_arg_sources) >= 2:
                return f"g_descriptor_table_{suffix}"
        if re.search(rf"{re.escape(global_alias)}\s*=\s*arg_\d+", wide_joined):
            static_arg_sources = re.findall(r"arg_\d+\s*=\s*&0x140[0-9a-f]+", wide_joined)
            if len(static_arg_sources) >= 2:
                return f"g_descriptor_table_{suffix}"
        if "TlsAccess" in wide_joined and (
            re.search(rf"arg_1\s*=\s*{re.escape(global_alias)}", wide_joined)
            or re.search(rf"{re.escape(global_alias)}\s*=\s*retVal", wide_joined)
            or re.search(rf"compare\({re.escape(global_alias)}, -0x1\)", wide_joined)
        ):
            return f"g_tls_slot_{suffix}"
        if re.search(rf"compare\([^,]+,\s*{re.escape(global_alias)}\)|compare\({re.escape(global_alias)},", joined):
            return f"g_slot_{suffix}"
        if re.search(rf"xchg\({re.escape(global_alias)}, retVal\)|xchg\(retVal, {re.escape(global_alias)}\)", joined):
            return f"g_cache_{suffix}"
        if re.search(rf"{re.escape(global_alias)}\s*=\s*arg_\d+|arg_\d+\s*=\s*{re.escape(global_alias)}", joined):
            return f"g_context_{suffix}"
        if any(
            re.search(pattern, joined)
            for pattern in (
                rf"{re.escape(global_alias)}\s*=\s*retVal",
                rf"retVal\s*=\s*{re.escape(global_alias)}",
                rf"{re.escape(global_alias)}\s*=\s*arg_\d+",
                rf"xchg\({re.escape(global_alias)},",
            )
        ):
            return f"g_ptr_{suffix}"
        return None

    def _apply_alias_renames(self, record: dict[str, Any], rename_map: dict[str, str]) -> dict[str, Any]:
        updated = dict(record)
        pseudocode = str(updated.get("pseudocode") or "")
        assembly = str(updated.get("assembly") or "")
        target_symbol = str(updated.get("target_symbol") or "")
        if pseudocode:
            updated["pseudocode"] = self._rename_alias_text(pseudocode, rename_map)
        if target_symbol:
            updated["target_symbol"] = self._rename_alias_text(target_symbol, rename_map)
        updated["context"] = [
            self._rename_alias_text(str(item), rename_map) if isinstance(item, str) else item
            for item in updated.get("context", [])
        ]
        register_values = {}
        for key, value in (updated.get("register_values") or {}).items():
            register_values[str(key)] = self._rename_alias_text(str(value), rename_map)
        updated["register_values"] = register_values
        variable_aliases = {}
        for key, value in (updated.get("variable_aliases") or {}).items():
            variable_aliases[str(key)] = self._rename_alias_text(str(value), rename_map)
        updated["variable_aliases"] = variable_aliases
        if assembly:
            updated["assembly"] = assembly
        return updated

    def _rename_alias_text(self, text: str, rename_map: dict[str, str]) -> str:
        renamed = text
        for old, new in rename_map.items():
            renamed = re.sub(rf"\b{re.escape(old)}\b", new, renamed)
        return renamed

    def _classify_repeated_block(self, record: dict[str, Any]) -> str | None:
        assembly = str(record.get("assembly") or "").lower()
        if assembly.startswith("rep movs") or assembly.startswith("movs"):
            return "memcpy"
        if assembly.startswith("rep cmps") or assembly.startswith("cmps"):
            return "strcmp"
        if assembly.startswith("rep stos") or assembly.startswith("stos"):
            return "memset"
        return None

    def _fold_repeated_block(self, records: list[dict[str, Any]], family: str) -> dict[str, Any]:
        first = dict(records[0])
        count = len(records)
        first["pseudocode"] = f"{family}(/* repeated block x{count} */)"
        first["assembly"] = f"{family}_fold x{count}"
        first["target_symbol"] = family
        merged_context: list[str] = []
        merged_register_values: dict[str, str] = {}
        merged_variable_aliases: dict[str, str] = {}
        for record in records:
            for item in record.get("context", []):
                if isinstance(item, str):
                    merged_context.append(item)
            for key, value in (record.get("register_values") or {}).items():
                merged_register_values[str(key)] = str(value)
            for key, value in (record.get("variable_aliases") or {}).items():
                merged_variable_aliases[str(key)] = str(value)
        first["context"] = self._unique(merged_context)
        first["register_values"] = merged_register_values
        first["variable_aliases"] = merged_variable_aliases
        first["filtered"] = False
        return first

    def _fold_handwritten_loop_blocks(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        max_window = 6
        while index < len(records):
            matched = False
            for window in range(max_window, 1, -1):
                if index + window * 2 > len(records):
                    continue
                left = records[index : index + window]
                right = records[index + window : index + window * 2]
                left_tokens = [self._loop_token(record) for record in left]
                right_tokens = [self._loop_token(record) for record in right]
                if not all(left_tokens) or left_tokens != right_tokens:
                    continue
                family = self._classify_loop_token_family(left_tokens)
                if not family:
                    continue
                folded.append(self._fold_repeated_block(records[index : index + window * 2], family))
                index += window * 2
                matched = True
                break
            if not matched:
                folded.append(records[index])
                index += 1
        return folded

    def _recover_while_loops(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        max_window = 10
        while index < len(records):
            matched = False
            for window in range(max_window, 2, -1):
                if index + window * 2 > len(records):
                    continue
                left = records[index : index + window]
                right = records[index + window : index + window * 2]
                if not self._same_record_shape(left, right):
                    continue
                condition = self._extract_loop_condition(left)
                if not condition:
                    continue
                loop_record = self._fold_repeated_block(left + right, "loop")
                loop_record["pseudocode"] = f"while ({condition})"
                loop_record["assembly"] = f"while_fold x{window * 2}"
                loop_record["target_symbol"] = "while"
                folded.append(loop_record)
                index += window * 2
                matched = True
                break
            if not matched:
                folded.append(records[index])
                index += 1
        return self._recover_backward_jump_loops(folded)

    def _loop_token(self, record: dict[str, Any]) -> str | None:
        assembly = str(record.get("assembly") or "").lower()
        pseudocode = str(record.get("pseudocode") or "")
        if assembly.startswith("mov "):
            if "[" in assembly.split(",", 1)[0]:
                return "store_mem"
            if "[" in assembly.split(",", 1)[1]:
                return "load_mem"
        if assembly.startswith("movzx "):
            if "[" in assembly:
                return "load_mem"
        if assembly.startswith("cmp "):
            if "[" in assembly:
                return "compare_mem"
            return "compare_reg"
        if assembly.startswith("inc ") or pseudocode.endswith("+ 1"):
            return "inc"
        if assembly.startswith("dec ") or pseudocode.endswith("- 1"):
            return "dec"
        if assembly.startswith("add ") and ", 1" in assembly:
            return "inc"
        if assembly.startswith("add ") and ", -1" in assembly:
            return "dec"
        if assembly.startswith("sub ") and ", 1" in assembly:
            return "dec"
        if assembly.startswith("sub ") and ", -1" in assembly:
            return "inc"
        return None

    def _classify_loop_token_family(self, tokens: list[str | None]) -> str | None:
        token_set = {token for token in tokens if token}
        if {"load_mem", "store_mem"}.issubset(token_set) and token_set.issubset(
            {"load_mem", "store_mem", "inc", "dec", "compare_reg"}
        ):
            return "memcpy"
        if "compare_mem" in token_set and token_set.issubset(
            {"load_mem", "compare_mem", "compare_reg", "inc", "dec"}
        ):
            return "strcmp"
        return None

    def _extract_call_operand(self, assembly: str) -> str:
        lower = assembly.lower()
        if not lower.startswith("call "):
            return ""
        return assembly.split(" ", 1)[1].strip()

    def _is_synthetic_function_target(self, call_target: str, assembly_target: str) -> bool:
        candidates = [call_target, assembly_target]
        for candidate in candidates:
            if not candidate:
                continue
            lower = candidate.lower()
            if lower.startswith("function_") or lower.startswith("sub_") or lower.startswith("loc_") or lower.startswith("0x"):
                return True
        return False

    def _infer_function_alias_from_context(self, records: list[dict[str, Any]], index: int) -> str | None:
        window = records[index + 1 : index + 9]
        imported_calls: list[str] = []
        string_values: list[str] = []
        variable_aliases: list[str] = []
        return_values: list[str] = []
        for record in window:
            pseudocode = str(record.get("pseudocode") or "")
            if pseudocode == "return":
                break
            target_symbol = record.get("target_symbol")
            if isinstance(target_symbol, str) and "." in target_symbol:
                imported_calls.append(target_symbol.rsplit(".", 1)[-1])
            string_value = record.get("string_value")
            if isinstance(string_value, str) and string_value:
                string_values.append(string_value)
            for value in (record.get("variable_aliases") or {}).values():
                if isinstance(value, str) and value:
                    variable_aliases.append(value)
            if pseudocode.startswith("retVal = "):
                return_values.append(pseudocode.split("=", 1)[1].strip())
        contextual_alias = self._score_function_alias(imported_calls, string_values, variable_aliases, return_values)
        if contextual_alias:
            return contextual_alias
        if not imported_calls:
            return None
        first_call = self._normalize_import_name(imported_calls[0])
        if len(imported_calls) == 1:
            return first_call
        suffix = "Wrapper"
        if any(name.lower().startswith("parse") for name in imported_calls):
            suffix = "Handler"
        return f"{first_call}{suffix}"

    def _score_function_alias(
        self,
        imported_calls: list[str],
        string_values: list[str],
        variable_aliases: list[str],
        return_values: list[str],
    ) -> str | None:
        joined_aliases = " ".join(variable_aliases).lower()
        lowered_strings = [value.lower() for value in string_values]
        scores: dict[str, int] = {}

        def add_score(name: str, score: int) -> None:
            scores[name] = scores.get(name, 0) + score

        if "filepath" in joined_aliases or "localpath" in joined_aliases or any(
            ("\\" in value or "/" in value) and (".exe" in value or ".dll" in value or "." in value)
            for value in lowered_strings
        ):
            add_score("OpenFile", 4)
        if "commandline" in joined_aliases or any(
            value.startswith("-") or " /" in value or "--" in value or "cmd" in value for value in lowered_strings
        ):
            add_score("ParseCommandLine", 4)
        normalized_imports = [self._normalize_import_name(name) for name in imported_calls]
        for name in normalized_imports:
            add_score(name, 2)
            lower_name = name.lower()
            if "virtualprotect" in lower_name:
                add_score("ProtectMemory", 3)
            if "loadlibrary" in lower_name or "getprocaddress" in lower_name:
                add_score("ResolveImports", 3)
            if "flsgetvalue" in lower_name or "flssetvalue" in lower_name or "flsalloc" in lower_name:
                add_score("TlsAccess", 3)
            if "getprocessheap" in lower_name or "heapalloc" in lower_name:
                add_score("HeapAccess", 3)
        for value in return_values:
            lower_value = value.lower()
            if "heap" in lower_value:
                add_score("HeapAccess", 2)
            if "filepath" in lower_value or "localpath" in lower_value:
                add_score("OpenFile", 2)
        if not scores:
            return None
        return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[0][0]

    def _same_record_shape(self, left: list[dict[str, Any]], right: list[dict[str, Any]]) -> bool:
        if len(left) != len(right):
            return False
        for left_record, right_record in zip(left, right):
            left_code = str(left_record.get("pseudocode") or "")
            right_code = str(right_record.get("pseudocode") or "")
            if left_code != right_code:
                return False
        return True

    def _extract_loop_condition(self, records: list[dict[str, Any]]) -> str | None:
        for record in reversed(records):
            pseudocode = str(record.get("pseudocode") or "")
            if pseudocode.startswith("if (") and pseudocode.endswith(")"):
                return pseudocode[4:-1]
        return None

    def _prune_noise_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pruned: list[dict[str, Any]] = []
        for record in records:
            if self._is_stack_noise_record(record):
                continue
            pruned.append(record)
        return pruned

    def _is_stack_noise_record(self, record: dict[str, Any]) -> bool:
        assembly = str(record.get("assembly") or "").lower()
        if not assembly:
            return False
        if assembly.startswith("push ") or assembly.startswith("pop "):
            return True
        if assembly.startswith("sub rsp,") or assembly.startswith("sub esp,"):
            return True
        if assembly.startswith("add rsp,") or assembly.startswith("add esp,"):
            return True
        if assembly in {"mov rbp, rsp", "mov ebp, esp"}:
            return True
        return False

    def _is_stack_spill_move(self, insn) -> bool:
        if len(insn.operands) != 2:
            return False
        callee_saved = {
            "rbx",
            "rbp",
            "rsi",
            "rdi",
            "r12",
            "r13",
            "r14",
            "r15",
            "ebx",
            "ebp",
            "esi",
            "edi",
        }

        def is_stack_slot(operand) -> bool:
            if operand.type != x86_const.X86_OP_MEM:
                return False
            base_reg_name = insn.reg_name(operand.mem.base) if operand.mem.base else ""
            return base_reg_name in {"rsp", "esp"} and not operand.mem.index and operand.mem.disp >= 0

        def is_callee_saved_reg(operand) -> bool:
            if operand.type != x86_const.X86_OP_REG:
                return False
            return insn.reg_name(operand.reg) in callee_saved

        left = insn.operands[0]
        right = insn.operands[1]
        return (is_stack_slot(left) and is_callee_saved_reg(right)) or (
            is_callee_saved_reg(left) and is_stack_slot(right)
        )

    def _is_this_object_display(self, object_display: str | None) -> bool:
        if not isinstance(object_display, str) or not object_display:
            return False
        return object_display == "this" or object_display.startswith("this(") or object_display.startswith("this.")

    def _recover_backward_jump_loops(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        while index < len(records):
            match = self._match_backward_jump_loop(records, index)
            if not match:
                folded.append(records[index])
                index += 1
                continue
            size, loop_record = match
            folded.append(loop_record)
            index += size
        return folded

    def _fold_repeated_summary_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        while index < len(records):
            family = self._summary_record_family(records[index])
            if not family:
                folded.append(records[index])
                index += 1
                continue
            end = index + 1
            while end < len(records) and self._same_summary_record(records[index], records[end], family):
                end += 1
            if end - index == 1:
                folded.append(records[index])
                index = end
                continue
            summary_record = self._merge_summary_records(records[index:end], family)
            folded.append(summary_record)
            index = end
        return folded

    def _summary_record_family(self, record: dict[str, Any]) -> str | None:
        target_symbol = str(record.get("target_symbol") or "")
        assembly = str(record.get("assembly") or "").lower()
        if target_symbol in {"while", "memcpy", "strcmp", "memset"}:
            return target_symbol
        if assembly.startswith("while_"):
            return "while"
        if assembly.startswith("memcpy_"):
            return "memcpy"
        if assembly.startswith("strcmp_"):
            return "strcmp"
        if assembly.startswith("memset_"):
            return "memset"
        return None

    def _same_summary_record(self, left: dict[str, Any], right: dict[str, Any], family: str) -> bool:
        if self._summary_record_family(right) != family:
            return False
        return str(left.get("pseudocode") or "") == str(right.get("pseudocode") or "")

    def _merge_summary_records(self, records: list[dict[str, Any]], family: str) -> dict[str, Any]:
        merged = dict(records[0])
        count = len(records)
        merged["assembly"] = f"{family}_repeat x{count}"
        merged_context: list[str] = []
        merged_register_values: dict[str, str] = {}
        merged_variable_aliases: dict[str, str] = {}
        for record in records:
            for item in record.get("context", []):
                if isinstance(item, str):
                    merged_context.append(item)
            for key, value in (record.get("register_values") or {}).items():
                merged_register_values[str(key)] = str(value)
            for key, value in (record.get("variable_aliases") or {}).items():
                merged_variable_aliases[str(key)] = str(value)
        merged_context.append(f"repeated x{count}")
        merged["context"] = self._unique(merged_context)
        merged["register_values"] = merged_register_values
        merged["variable_aliases"] = merged_variable_aliases
        merged["target_symbol"] = family
        merged["filtered"] = False
        return merged

    def _fold_repeated_normalized_windows(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        max_window = 18
        min_window = 8
        min_repeats = 3
        while index < len(records):
            match = self._match_repeated_normalized_window(records, index, max_window, min_window, min_repeats)
            if not match:
                folded.append(records[index])
                index += 1
                continue
            window, repeats = match
            folded.extend(records[index : index + window])
            folded.append(self._build_repeated_window_record(records[index : index + window], repeats - 1, window))
            index += window * repeats
        return folded

    def _match_repeated_normalized_window(
        self,
        records: list[dict[str, Any]],
        index: int,
        max_window: int,
        min_window: int,
        min_repeats: int,
    ) -> tuple[int, int] | None:
        for window in range(max_window, min_window - 1, -1):
            if index + window * min_repeats > len(records):
                continue
            base = self._normalized_window_signature(records[index : index + window])
            if not base:
                continue
            repeats = 1
            cursor = index + window
            while cursor + window <= len(records):
                current = self._normalized_window_signature(records[cursor : cursor + window])
                if current != base:
                    break
                repeats += 1
                cursor += window
            if repeats >= min_repeats:
                return window, repeats
        return None

    def _normalized_window_signature(self, records: list[dict[str, Any]]) -> tuple[str, ...]:
        signature = tuple(self._normalize_window_text(str(record.get("pseudocode") or "")) for record in records)
        if not any("while (" in item or "call " in item for item in signature):
            return ()
        return signature

    def _normalize_window_text(self, value: str) -> str:
        normalized = value
        normalized = re.sub(r"0x[0-9a-fA-F]+", "0xN", normalized)
        normalized = re.sub(r"\bg_[A-Za-z0-9_]+\b", "g_ALIAS", normalized)
        normalized = re.sub(r"\bglobal_[0-9a-fA-F]+\b", "g_ALIAS", normalized)
        normalized = re.sub(r"\blocal_var_\d+\b", "local_var_N", normalized)
        normalized = re.sub(r"\barg_\d+\b", "arg_N", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def _build_repeated_window_record(
        self,
        records: list[dict[str, Any]],
        repeated_count: int,
        window_size: int,
    ) -> dict[str, Any]:
        summary = dict(records[0])
        summary["pseudocode"] = self._describe_repeated_window(records, repeated_count)
        summary["assembly"] = f"repeat_window size={window_size} x{repeated_count}"
        summary["target_symbol"] = "repeat_window"
        summary["filtered"] = False
        context = [str(item) for item in summary.get("context", []) if isinstance(item, str)]
        context.append(f"similar_window_size={window_size}")
        context.append(f"repeated_windows={repeated_count}")
        summary["context"] = self._unique(context)
        return summary

    def _describe_repeated_window(self, records: list[dict[str, Any]], repeated_count: int) -> str:
        while_conditions: list[str] = []
        call_targets: list[str] = []
        for record in records:
            pseudocode = str(record.get("pseudocode") or "")
            if pseudocode.startswith("while (") and pseudocode.endswith(")"):
                while_conditions.append(pseudocode)
            if pseudocode.startswith("call "):
                call_targets.append(pseudocode[5:].strip())
        if while_conditions:
            return f"repeat_window({while_conditions[0]}, x{repeated_count})"
        if call_targets:
            return f"repeat_window(call {call_targets[0]}, x{repeated_count})"
        return f"repeat_window(x{repeated_count})"

    def _fold_repeated_while_chains(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        while index < len(records):
            match = self._match_repeated_while_chain(records, index)
            if not match:
                folded.append(records[index])
                index += 1
                continue
            size, merged = match
            folded.append(merged)
            index += size
        return folded

    def _match_repeated_while_chain(self, records: list[dict[str, Any]], index: int) -> tuple[int, dict[str, Any]] | None:
        if not self._is_while_chain_record(records[index]):
            return None
        end = index
        while_count = 0
        family_signatures: list[tuple[str, str] | None] = []
        while end < len(records) and self._is_while_chain_record(records[end]):
            pseudocode = str(records[end].get("pseudocode") or "")
            if pseudocode.startswith("while (") and pseudocode.endswith(")"):
                while_count += 1
                family_signatures.append(self._while_family_signature(pseudocode))
            end += 1
        if while_count < 4 or end - index < 6:
            return None
        unique_families = {signature for signature in family_signatures if signature}
        if len(unique_families) > 2:
            return None
        return end - index, self._merge_while_chain_records(records[index:end], while_count)

    def _is_while_chain_record(self, record: dict[str, Any]) -> bool:
        pseudocode = str(record.get("pseudocode") or "")
        if pseudocode.startswith("while (") and pseudocode.endswith(")"):
            return True
        if re.match(r"([A-Za-z_][A-Za-z0-9_\.]*) = \1 [\+\-] 1$", pseudocode):
            return True
        return False

    def _while_family_signature(self, pseudocode: str) -> tuple[str, str] | None:
        match = re.match(r"while \((.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)\)$", pseudocode)
        if not match:
            return None
        _, operator, right = match.groups()
        return operator, self._normalize_window_text(right)

    def _merge_while_chain_records(self, records: list[dict[str, Any]], while_count: int) -> dict[str, Any]:
        merged = dict(records[0])
        merged["pseudocode"] = self._describe_while_chain(records, while_count)
        merged["assembly"] = f"while_chain x{while_count}"
        merged["target_symbol"] = "while_chain"
        merged["filtered"] = False
        context = [str(item) for item in merged.get("context", []) if isinstance(item, str)]
        context.append(f"while_chain_count={while_count}")
        merged["context"] = self._unique(context)
        return merged

    def _describe_while_chain(self, records: list[dict[str, Any]], while_count: int) -> str:
        conditions = [
            str(record.get("pseudocode") or "")
            for record in records
            if str(record.get("pseudocode") or "").startswith("while (")
        ]
        if not conditions:
            return f"while_chain(x{while_count})"
        first_condition = conditions[0]
        unique_conditions = list(dict.fromkeys(conditions))
        if len(unique_conditions) == 1:
            return f"while_chain({first_condition}, x{while_count})"
        family = self._while_family_signature(first_condition)
        if family:
            operator, right = family
            role = self._infer_while_chain_role(unique_conditions)
            return f"while_chain({role} {operator} {right}, x{while_count})"
        return f"while_chain({first_condition}, x{while_count})"

    def _infer_while_chain_role(self, conditions: list[str]) -> str:
        joined = "\n".join(conditions)
        member_offsets = re.findall(r"thisObj\.member_([0-9a-f]+)", joined)
        if member_offsets:
            offsets = sorted({int(offset, 16) for offset in member_offsets})
            if len(offsets) > 1:
                steps = {offsets[index + 1] - offsets[index] for index in range(len(offsets) - 1)}
                if len(steps) == 1 and next(iter(steps)) in {8, 16, 24, 32}:
                    return "object_slot_traversal"
                return "slot_scan"
            return "member_check"
        if "api_heap_" in joined:
            return "buffer_scan"
        if any(token in joined for token in ("local_var_", "arg_")):
            return "value_scan"
        return "*"

    def _fold_repeated_scalar_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        folded: list[dict[str, Any]] = []
        index = 0
        while index < len(records):
            if not self._is_scalar_repeat_candidate(records[index]):
                folded.append(records[index])
                index += 1
                continue
            end = index + 1
            base_signature = self._scalar_repeat_signature(records[index])
            while end < len(records) and self._scalar_repeat_signature(records[end]) == base_signature:
                end += 1
            if end - index < 3:
                folded.append(records[index])
                index += 1
                continue
            folded.append(self._merge_scalar_repeat_records(records[index:end]))
            index = end
        return folded

    def _is_scalar_repeat_candidate(self, record: dict[str, Any]) -> bool:
        if self._summary_record_family(record):
            return False
        pseudocode = str(record.get("pseudocode") or "")
        if not pseudocode or pseudocode.startswith("call ") or pseudocode.startswith("if (") or pseudocode.startswith("while ("):
            return False
        if any(token in pseudocode for token in (" = ", "compare(", "test(")):
            return True
        return False

    def _scalar_repeat_signature(self, record: dict[str, Any]) -> tuple[str, str] | None:
        if not self._is_scalar_repeat_candidate(record):
            return None
        pseudocode = str(record.get("pseudocode") or "")
        assembly = str(record.get("assembly") or "").split()[0].lower() if record.get("assembly") else ""
        return assembly, self._normalize_window_text(pseudocode)

    def _merge_scalar_repeat_records(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        merged = dict(records[0])
        count = len(records)
        merged["pseudocode"] = self._describe_scalar_repeat(records[0], count)
        merged["assembly"] = f"scalar_repeat x{count}"
        context = [str(item) for item in merged.get("context", []) if isinstance(item, str)]
        context.append(f"repeated x{count}")
        merged["context"] = self._unique(context)
        merged["target_symbol"] = str(merged.get("target_symbol") or "repeat_scalar")
        merged["filtered"] = False
        return merged

    def _describe_scalar_repeat(self, record: dict[str, Any], count: int) -> str:
        pseudocode = str(record.get("pseudocode") or "")
        increment = re.match(r"([A-Za-z_][A-Za-z0-9_\.]*) = \1 \+ 1$", pseudocode)
        if increment:
            return f"increment({increment.group(1)}, repeated x{count})"
        decrement = re.match(r"([A-Za-z_][A-Za-z0-9_\.]*) = \1 - 1$", pseudocode)
        if decrement:
            return f"decrement({decrement.group(1)}, repeated x{count})"
        compare_match = re.match(r"(compare\(.+\)|test\(.+\))$", pseudocode)
        if compare_match:
            return f"{compare_match.group(1)} repeated x{count}"
        return f"{pseudocode} /* repeated x{count} */"

    def _match_backward_jump_loop(self, records: list[dict[str, Any]], index: int) -> tuple[int, dict[str, Any]] | None:
        for size in (3, 2):
            end = index + size - 1
            if end >= len(records):
                continue
            group = records[index : end + 1]
            condition_record = group[-1]
            if not self._is_backward_jump_record(condition_record):
                continue
            if size == 3 and not self._is_loop_step_record(group[0], condition_record):
                continue
            if size == 2 and not self._is_compare_record(group[0]):
                continue
            condition = self._extract_loop_condition(group)
            if not condition:
                continue
            loop_record = self._fold_repeated_block(group, "loop")
            loop_record["pseudocode"] = f"while ({condition})"
            loop_record["assembly"] = f"while_backedge x{size}"
            loop_record["target_symbol"] = "while"
            return size, loop_record
        return None

    def _is_backward_jump_record(self, record: dict[str, Any]) -> bool:
        pseudocode = str(record.get("pseudocode") or "")
        assembly = str(record.get("assembly") or "")
        current_address = self._parse_hex_address(record.get("address"))
        target_address = self._extract_branch_target(assembly)
        if not (pseudocode.startswith("if (") and pseudocode.endswith(")")):
            return False
        if current_address is None or target_address is None:
            return False
        return target_address < current_address

    def _is_compare_record(self, record: dict[str, Any]) -> bool:
        pseudocode = str(record.get("pseudocode") or "")
        return pseudocode.startswith("compare(") or pseudocode.startswith("test(")

    def _is_loop_step_record(self, record: dict[str, Any], condition_record: dict[str, Any]) -> bool:
        pseudocode = str(record.get("pseudocode") or "")
        if "=" not in pseudocode:
            return False
        condition = self._extract_loop_condition([condition_record]) or ""
        step_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", pseudocode))
        condition_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition))
        return bool(step_tokens and condition_tokens and step_tokens.intersection(condition_tokens))

    def _parse_hex_address(self, value: Any) -> int | None:
        if isinstance(value, str) and value.startswith("0x"):
            try:
                return int(value, 16)
            except ValueError:
                return None
        return None

    def _extract_branch_target(self, assembly: str) -> int | None:
        parts = assembly.strip().split()
        if len(parts) != 2 or not parts[0].lower().startswith("j"):
            return None
        target = parts[1].strip()
        if not target.startswith("0x"):
            return None
        try:
            return int(target, 16)
        except ValueError:
            return None

    def _normalize_import_name(self, target_symbol: str) -> str:
        name = target_symbol.rsplit(".", 1)[-1]
        if name.endswith("Ex"):
            return name[:-2]
        if len(name) > 1 and name[-1] in {"A", "W"} and name[-2].islower():
            return name[:-1]
        return name

    def _get_instruction_annotations(self, insn, operands: list[dict[str, Any]]) -> list[str]:
        annotations: list[str] = []
        mnemonic = insn.mnemonic.lower()
        if mnemonic in {"ror", "rol"}:
            annotations.append("possible hash or decrypt bit-mixing logic")
        if mnemonic == "xor" and len(operands) == 2 and operands[0].get("expr") != operands[1].get("expr"):
            annotations.append("possible xor-based transform")
        for operand in operands:
            value = operand.get("value")
            if not isinstance(value, str):
                continue
            magic_comment = self._describe_magic_value(value)
            if magic_comment:
                annotations.append(magic_comment)
        return annotations

    def _describe_magic_value(self, value: str) -> str | None:
        magic_values = {
            "0x5a4d": "magic value MZ header",
            "0x4550": "magic value PE header",
            "0x9e3779b9": "magic value TEA-style constant",
            "0xdeadbeef": "magic debug sentinel",
        }
        return magic_values.get(value.lower())

    def _format_int(self, value: int | None) -> str:
        if value is None:
            return "?"
        if value < 0:
            return f"-0x{abs(value):x}"
        return f"0x{value:x}"

    def _unique(self, values: list[str]) -> list[str]:
        unique_values: list[str] = []
        seen: set[str] = set()
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            unique_values.append(value)
        return unique_values
