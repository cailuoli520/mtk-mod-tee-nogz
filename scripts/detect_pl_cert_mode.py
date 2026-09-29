#!/usr/bin/env python3
"""Conservative, offline detection of MTK CERT2 traversal mode.

Recognize the tag reader and the SEQUENCE/SEQUENCE/BIT STRING certificate
path. The first SEQUENCE call's fifth argument distinguishes the known
layouts: 0 = tag-aware traversal; 1 = enter-value traversal (legacy wrapper).
Neither the device name nor the existence of a retry loop selects the mode.
Unsupported or ambiguous code returns NEED_MANUAL and exits nonzero.
"""

import argparse
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import (
    Cs, CsError, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB,
    CS_GRP_JUMP, CS_GRP_CALL,
)

MAGIC_PART = 0x58881688
NEW_PARSER = "NEW_PARSER"
LEGACY = "LEGACY"
NEED_MANUAL = "NEED_MANUAL"
MAX_INPUT_SIZE = 32 * 1024 * 1024
MAX_CODE_SIZE = 4 * 1024 * 1024
MAX_FUNCTION_BYTES = 0x4000
MAX_FUNCTION_INSNS = 2048
MAX_CALL_DEPTH = 4
REG, IMM, MEM = 1, 2, 3


@dataclass
class DetectionResult:
    path: str
    status: str = NEED_MANUAL
    reason: str = ""
    sha256: str = ""
    isa: str = ""
    evidence: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)

    def as_dict(self):
        return vars(self)


def parse_hdr(data):
    offset = 0x1000 if data.startswith((b"EMMC_BOOT", b"UFS_BOOT", b"COMBO_BOOT", b"AND_ROMINFO_v")) else 0
    if len(data) < offset + 0x34:
        raise ValueError("truncated GFH header")
    if data[offset:offset + 4] not in (b"MMM\x01", b"\x01MMM"):
        raise ValueError("unsupported preloader header magic")
    load = struct.unpack_from("<I", data, offset + 0x1C)[0]
    size = struct.unpack_from("<I", data, offset + 0x20)[0]
    header = struct.unpack_from("<I", data, offset + 0x28)[0]
    ida = struct.unpack_from("<I", data, offset + 0x30)[0]
    if not 0x34 <= header < size or offset + size > len(data):
        raise ValueError("invalid or truncated GFH data extent")
    base = load + ida
    if base > 0xFFFFFFFF or base + size - header > 0x100000000:
        raise ValueError("GFH load extent exceeds the supported address space")
    return base, offset + header, size - header


def detect_isa(code):
    n64 = sum(
        (struct.unpack_from("<I", code, off)[0] & 0xFFC07FFF) in (0xA9807BFD, 0xA9007BFD)
        for off in range(0, len(code) - 3, 4)
    )
    thumb = sum(
        (struct.unpack_from("<H", code, off)[0] & 0xFF00) == 0xB500
        or struct.unpack_from("<H", code, off)[0] == 0xE92D
        for off in range(0, len(code) - 1, 2)
    )
    if max(n64, thumb) < 8 or max(n64, thumb) < 3 * min(n64, thumb):
        return "unknown", n64, thumb
    return ("arm64" if n64 > thumb else "thumb"), n64, thumb


def get_md(isa):
    if isa not in ("arm64", "thumb"):
        raise ValueError("unsupported instruction set")
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if isa == "arm64" else Cs(
        CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN
    )
    md.skipdata = True
    md.detail = True
    return md


def register(item, number, isa):
    name = item.reg_name(number)
    if isa == "arm64":
        name = {"fp": "x29", "lr": "x30"}.get(name, name)
        return "x" + name[1:] if name.startswith("w") and name != "wsp" else name
    return {"fp": "r11", "ip": "r12", "sb": "r9", "sl": "r10", "lr": "r14"}.get(name, name)


def arg(index):
    return ("arg", index)


def stack(offset):
    return ("stack", offset)


def expression(operation, left, right):
    if left is None or right is None:
        return None
    if isinstance(left, int) and isinstance(right, int):
        if operation == "lsl" and not 0 <= right <= 63:
            return None
        return {
            "add": lambda: left + right, "sub": lambda: left - right,
            "and": lambda: left & right, "orr": lambda: left | right,
            "lsl": lambda: left << right,
        }[operation]()
    if operation in ("add", "sub") and isinstance(right, int):
        if isinstance(left, tuple) and left[0] == "stack":
            return stack(left[1] + (right if operation == "add" else -right))
        if right == 0:
            return left
    value = (operation, left, right)
    return value if len(repr(value)) < 180 else None


def is_byte(value):
    return isinstance(value, tuple) and value[0:2] == ("load", 1)


def is_tag(value):
    return value == arg(0) or value == ("and", arg(0), 0xFF)


@dataclass
class State:
    regs: dict = field(default_factory=dict)
    slots: dict = field(default_factory=dict)

    def copy(self):
        return State(self.regs.copy(), self.slots.copy())

    def merge(self, other):
        return State(
            {k: v for k, v in self.regs.items() if other.regs.get(k) == v},
            {k: v for k, v in self.slots.items() if other.slots.get(k) == v},
        )


@dataclass
class Function:
    entry: int
    items: dict
    successors: dict
    complete: bool
    states: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)
    tails: list = field(default_factory=list)


class Program:
    def __init__(self, data):
        self.base, self.offset, size = parse_hdr(data)
        if size > MAX_CODE_SIZE:
            raise ValueError(f"GFH code extent exceeds {MAX_CODE_SIZE} bytes")
        self.code = data[self.offset:self.offset + size]
        self.isa, a64, thumb = detect_isa(self.code)
        self.isa_counts = {"arm64": a64, "thumb": thumb}
        if self.isa == "unknown":
            raise ValueError(f"ambiguous ISA evidence: {self.isa_counts}")
        self.instructions = list(get_md(self.isa).disasm(self.code, self.base))
        self.items = {item.address: item for item in self.instructions if item.id}
        self.starts = set()
        self.functions = {}
        for idx, item in enumerate(self.instructions):
            if not item.id:
                continue
            if self.is_call(item):
                target = self.target(item)
                if target in self.items:
                    self.starts.add(target)
            if self.isa == "thumb":
                prologue = item.mnemonic in ("push", "push.w") and "lr" in item.op_str
            else:
                prologue = item.mnemonic == "stp" and "x29, x30, [sp" in item.op_str
                if prologue and "#-" not in item.op_str:
                    prologue = idx > 0 and self.instructions[idx - 1].mnemonic == "sub"
            if not prologue:
                continue
            start = idx
            if self.isa == "arm64":
                if idx and self.instructions[idx - 1].mnemonic == "sub":
                    prev = self.instructions[idx - 1]
                    if prev.op_str.startswith("sp, sp,") and prev.address + prev.size == item.address:
                        start -= 1
                while start and self.instructions[start - 1].mnemonic in ("paciasp", "pacibsp", "bti"):
                    start -= 1
            self.starts.add(self.instructions[start].address)
        self.sorted_starts = sorted(self.starts)

    @staticmethod
    def is_call(item):
        return item.group(CS_GRP_CALL)

    def target(self, item):
        for operand in reversed(item.operands):
            if operand.type == IMM:
                return operand.imm & ~1 if self.isa == "thumb" else operand.imm
        return None

    @staticmethod
    def is_return(item):
        return (
            item.mnemonic in ("ret", "retaa", "retab")
            or item.mnemonic.startswith("pop") and "pc" in item.op_str
            or item.mnemonic == "bx" and item.op_str == "lr"
        )

    def containing(self, address):
        idx = bisect_right(self.sorted_starts, address) - 1
        return self.sorted_starts[idx] if idx >= 0 else None

    def function(self, entry):
        if entry in self.functions:
            return self.functions[entry]
        items, successors, complete = {}, {}, True
        function = Function(entry, items, successors, False)
        self.functions[entry] = function
        todo = [entry]
        while todo:
            address = todo.pop()
            if address in items:
                continue
            item = self.items.get(address)
            if item is None or not entry <= address < entry + MAX_FUNCTION_BYTES:
                complete = False
                continue
            if address != entry and address in self.starts:
                complete = False
                continue
            if len(items) >= MAX_FUNCTION_INSNS:
                complete = False
                break
            items[address] = item
            edges = []
            if not self.is_return(item):
                if item.group(CS_GRP_JUMP) and not self.is_call(item):
                    target = self.target(item)
                    if target is None:
                        complete = False
                    elif target in self.starts and target != entry:
                        function.tails.append(target)
                    else:
                        edges.append(target)
                    if item.mnemonic not in ("b", "b.w", "bx", "br"):
                        edges.append(address + item.size)
                else:
                    next_address = address + item.size
                    if not (
                        self.is_call(item) and next_address in self.starts
                        and self.no_return(self.target(item))
                    ):
                        edges.append(next_address)
            successors[address] = edges
            todo.extend(edges)
        function.complete = complete
        self.propagate(function)
        return function

    def no_return(self, entry, seen=None):
        if entry not in self.items:
            return False
        seen = set() if seen is None else seen
        if entry in seen:
            return False
        function = self.function(entry)
        if not function.complete or any(self.is_return(item) for item in function.items.values()):
            return False
        return all(self.no_return(target, seen | {entry}) for target in function.tails)

    def read(self, item, operand, state):
        if operand.type == IMM:
            return operand.imm
        if operand.type != REG:
            return None
        name = register(item, operand.reg, self.isa)
        if name in ("xzr", "wzr"):
            return 0
        value = state.regs.get(name)
        shift = getattr(operand, "shift", None)
        if shift and shift.value:
            return expression("lsl", value, shift.value) if shift.type == 1 else None
        return value

    def address(self, item, operand, state):
        base = state.regs.get(register(item, operand.mem.base, self.isa))
        if operand.mem.index:
            return None
        return expression("add", base, operand.mem.disp)

    def arguments(self, state):
        prefix = "x" if self.isa == "arm64" else "r"
        values = [state.regs.get(f"{prefix}{idx}") for idx in range(4)]
        values.append(state.regs.get("x4") if self.isa == "arm64" else state.slots.get(state.regs.get("sp")))
        return tuple(values)

    def transfer(self, item, before):
        state = before.copy()
        operands = item.operands
        mnemonic = item.mnemonic.removesuffix(".w")
        mnemonic = {"addw": "add", "subw": "sub"}.get(mnemonic, mnemonic)
        try:
            _, writes = item.regs_access()
        except Exception:
            writes = []
        # Capstone 5 ARM64 CMP aliases incorrectly report the compared GPR as
        # written. These instructions only change flags.
        if mnemonic in ("cmp", "cmn", "tst", "teq"):
            writes = []
        for number in writes:
            state.regs.pop(register(item, number, self.isa), None)

        def put(index, value):
            if value is not None and operands[index].type == REG:
                name = item.reg_name(operands[index].reg)
                if isinstance(value, int) and (
                    self.isa == "thumb" and name != "sp" or name.startswith("w")
                ):
                    value &= 0xFFFFFFFF
                state.regs[register(item, operands[index].reg, self.isa)] = value

        if self.is_call(item):
            names = [f"x{i}" for i in range(19)] + ["x30"] if self.isa == "arm64" else ["r0", "r1", "r2", "r3", "r12", "r14"]
            for name in names:
                state.regs.pop(name, None)
            state.slots.clear()
            return state
        conditional = self.isa == "thumb" and getattr(item, "cc", 15) not in (0, 15)
        if conditional and not item.group(CS_GRP_JUMP):
            if mnemonic.startswith(("str", "stm", "stp")):
                state.slots.clear()
            return state
        if mnemonic.startswith(("push", "pop")):
            old_sp = before.regs.get("sp")
            count = sum(op.type == REG for op in operands)
            state.regs["sp"] = expression("add", old_sp, (-4 if mnemonic == "push" else 4) * count)
            return state
        if mnemonic in ("mov", "movs", "movw") and len(operands) == 2:
            put(0, self.read(item, operands[1], before))
        elif mnemonic in ("adr", "adrp"):
            put(0, operands[1].imm)
        elif mnemonic in ("movt", "movk"):
            old = self.read(item, operands[0], before)
            shift = 16 if mnemonic == "movt" else operands[1].shift.value
            if isinstance(old, int):
                put(0, (old & ~(0xFFFF << shift)) | (operands[1].imm << shift))
        elif mnemonic in ("add", "adds", "sub", "subs", "and", "ands", "orr", "lsl", "lsls"):
            operation = mnemonic.removesuffix("s")
            left = self.read(item, operands[1 if len(operands) == 3 else 0], before)
            right = self.read(item, operands[-1], before)
            put(0, expression(operation, left, right))
        elif mnemonic.startswith(("ldr", "str", "ldp", "stp")):
            memory = next((op for op in operands if op.type == MEM), None)
            if memory is not None:
                location = self.address(item, memory, before)
                pair = mnemonic in ("ldp", "stp", "ldrd", "strd")
                load = mnemonic.startswith("ld")
                width = 1 if mnemonic.startswith(("ldrb", "ldrsb", "strb")) else 4
                if self.isa == "arm64" and item.reg_name(operands[0].reg).startswith("x"):
                    width = 8
                if not load and (
                    location is None or width < 4
                    or isinstance(location, tuple) and location[0] != "stack"
                ):
                    state.slots.clear()
                for idx in range(2 if pair else 1):
                    at = expression("add", location, idx * width)
                    if load:
                        value = before.slots.get(at) if isinstance(at, tuple) and at[0] == "stack" else (
                            ("load", width, at) if at is not None else None
                        )
                        put(idx, value)
                    elif width >= 4 and at is not None and isinstance(at, tuple) and at[0] == "stack":
                        value = self.read(item, operands[idx], before)
                        if value is None:
                            state.slots.pop(at, None)
                        else:
                            state.slots[at] = value
                if item.writeback:
                    value = location
                    if operands[-1].type == IMM:
                        base = before.regs.get(register(item, memory.mem.base, self.isa))
                        value = expression("add", base, operands[-1].imm)
                    if value is not None:
                        state.regs[register(item, memory.mem.base, self.isa)] = value
        return state

    def propagate(self, function):
        prefix = "x" if self.isa == "arm64" else "r"
        initial = State({"sp": stack(0), **{f"{prefix}{i}": arg(i) for i in range(8 if self.isa == "arm64" else 4)}})
        if self.isa == "thumb":
            initial.slots[stack(0)] = arg(4)
        function.states[function.entry] = initial
        todo = deque([function.entry])
        budget = MAX_FUNCTION_INSNS * 20
        while todo and budget:
            budget -= 1
            address = todo.popleft()
            if address not in function.items:
                continue
            after = self.transfer(function.items[address], function.states[address])
            for target in function.successors[address]:
                if target not in function.items:
                    continue
                previous = function.states.get(target)
                joined = after if previous is None else previous.merge(after)
                if previous != joined:
                    function.states[target] = joined
                    todo.append(target)
        if todo:
            function.complete = False
        for address, item in sorted(function.items.items()):
            if self.is_call(item) and address in function.states:
                function.calls.append((address, self.target(item), self.arguments(function.states[address])))

    def tag_reader(self, function):
        features = {}
        tag_bytes, traversal_bytes = set(), set()
        for address, item in function.items.items():
            state = function.states.get(address)
            if state is None:
                continue
            mnemonic = item.mnemonic.removesuffix(".w")
            values = [self.read(item, op, state) for op in item.operands]
            if mnemonic in ("cmp", "subs") and len(values) >= 2:
                left, right = values[-2:]
                if (is_byte(left) and is_tag(right)) or (is_byte(right) and is_tag(left)):
                    features["tag_vs_arg0"] = address
                    tag_bytes.add(left if is_byte(left) else right)
                if left == arg(4) and right in (1, 2):
                    features[f"mode{right}"] = address
                if is_byte(left) and right == 3:
                    features["bit_string"] = address
                    traversal_bytes.add(left)
            if mnemonic in ("tbz", "tbnz") and len(values) >= 2 and is_byte(values[0]) and values[1] == 5:
                features["constructed_bit"] = address
                traversal_bytes.add(values[0])
            if mnemonic == "lsls" and len(values) == 3 and is_byte(values[1]) and values[2] == 26:
                features["constructed_bit"] = address
                traversal_bytes.add(values[1])
        for site, target, arguments in function.calls:
            if arguments[1:3] == (arg(2), arg(3)) and target in self.items:
                helper = self.function(target)
                has_length_mask = any(
                    item.mnemonic.removesuffix(".w") in ("and", "ands")
                    and any(op.type == IMM and op.imm == 0x7F for op in item.operands)
                    for item in helper.items.values()
                )
                has_length_byte = any(
                    item.mnemonic.startswith(("ldrb", "ldrsb"))
                    and helper.states.get(item.address) is not None
                    and any(
                        op.type == MEM
                        and self.address(item, op, helper.states[item.address]) == ("add", arg(0), 1)
                        for op in item.operands
                    )
                    for item in helper.items.values()
                )
                if helper.complete and has_length_mask and has_length_byte:
                    features["der_length_call"] = site
        required = {"tag_vs_arg0", "mode1", "mode2", "bit_string", "constructed_bit", "der_length_call"}
        if not required <= features.keys() or len(tag_bytes) != 1 or traversal_bytes != tag_bytes:
            return {}
        expected = {
            0: {"constructed_bit"},
            1: {"bit_string"},
            2: set(),
        }
        for mode, wanted in expected.items():
            reached = self.mode_features(function, features, mode)
            if reached != wanted:
                return {}
        return features

    def mode_features(self, function, features, mode):
        """Check which tag-dependent traversal block each arg4 value can reach."""
        wanted = {features[key]: key for key in ("constructed_bit", "bit_string")}
        reached, visited = set(), set()
        todo = [(function.entry, None)]
        while todo:
            address, compared = todo.pop()
            if (address, compared) in visited or address not in function.states:
                continue
            visited.add((address, compared))
            item = function.items[address]
            state = function.states[address]
            values = [self.read(item, op, state) for op in item.operands]
            if address in wanted:
                reached.add(wanted[address])
            mnemonic = item.mnemonic.removesuffix(".w")
            edges = function.successors[address]
            if mnemonic == "cmp":
                compared = (mode == values[1]) if values[0] == arg(4) and isinstance(values[1], int) else None
            elif mnemonic in ("b.eq", "beq", "b.ne", "bne") and compared is not None:
                taken = compared if mnemonic in ("b.eq", "beq") else not compared
                edges = [self.target(item) if taken else address + item.size]
            elif mnemonic in ("cbz", "cbnz") and values[0] == arg(4):
                taken = mode == 0 if mnemonic == "cbz" else mode != 0
                edges = [self.target(item) if taken else address + item.size]
            elif self.is_call(item):
                compared = None
            elif any(item.reg_name(number) in ("nzcv", "cpsr") for number in item.regs_access()[1]):
                compared = None
            todo.extend((target, compared) for target in edges)
        return reached

    def magic_roots(self):
        roots = set()
        for item in self.instructions:
            if item.id and item.mnemonic in ("movk", "movt") and any(
                op.type == IMM and op.imm == 0x5888 for op in item.operands
            ):
                entry = self.containing(item.address)
                if entry is None:
                    continue
                function = self.function(entry)
                for address, instruction in function.items.items():
                    if instruction.mnemonic.removesuffix(".w") != "cmp":
                        continue
                    state = function.states.get(address)
                    if state and MAGIC_PART in [self.read(instruction, op, state) for op in instruction.operands]:
                        roots.add(entry)
        return roots

    def family(self, roots):
        found = set()
        todo = deque((entry, 0) for entry in roots)
        while todo:
            entry, depth = todo.popleft()
            if entry in found or entry not in self.items:
                continue
            found.add(entry)
            function = self.function(entry)
            if depth < MAX_CALL_DEPTH:
                todo.extend((target, depth + 1) for _, target, _ in function.calls if target in self.items)
        return found

    def direct_success_path(self, function, first, second):
        """Require a short path from a successful first call to the second call."""
        item = function.items[first]
        address = first + item.size
        return_name = "x0" if self.isa == "arm64" else "r0"
        status_live, checked = True, False
        for _ in range(16):
            if address == second:
                return checked
            item = function.items.get(address)
            if item is None or self.is_call(item) or self.is_return(item):
                return False
            if item.group(CS_GRP_JUMP):
                if item.mnemonic not in ("cbz", "cbnz"):
                    return False
                if register(item, item.operands[0].reg, self.isa) != return_name:
                    return False
                if not status_live:
                    return False
                checked = True
                address = self.target(item) if item.mnemonic == "cbz" else address + item.size
            else:
                if any(register(item, reg, self.isa) == return_name for reg in item.regs_access()[1]):
                    if not (
                        item.mnemonic in ("mov", "movs")
                        and len(item.operands) == 2 and item.operands[1].type == IMM
                        and item.operands[1].imm == 0x30
                    ):
                        return False
                    status_live = False
                address += item.size
        return False

    def disassembly(self, function):
        return [
            f"0x{item.address:08x}  {item.bytes.hex():<10} {item.mnemonic:<9} {item.op_str}"
            for _, item in sorted(function.items.items())
        ]


def detect(path):
    path = Path(path)
    result = DetectionResult(str(path.resolve()))
    try:
        if path.stat().st_size > MAX_INPUT_SIZE:
            raise ValueError(f"input exceeds {MAX_INPUT_SIZE} bytes")
        data = path.read_bytes()
        result.sha256 = hashlib.sha256(data).hexdigest()
        program = Program(data)
        result.isa = program.isa
        roots = program.magic_roots()
        result.diagnostics.append(f"PART_MAGIC checked roots: {len(roots)}")
        if not roots:
            result.reason = "no proven part-header validation root"
            return result
        family = program.family(roots)
        readers = {}
        for entry in sorted(family):
            function = program.function(entry)
            if function.complete:
                features = program.tag_reader(function)
                if features:
                    readers[entry] = features
        result.diagnostics.append(f"semantic tag readers: {len(readers)}; functions: {len(family)}")
        uncertain = False
        for entry in sorted(family):
            function = program.function(entry)
            calls = function.calls
            for idx, (first, target, arguments) in enumerate(calls[:-1]):
                if target not in readers or arguments[0] != 0x30 or arguments[4] == 2:
                    continue
                second, next_target, next_arguments = calls[idx + 1]
                if next_target != target or next_arguments[0] != 0x30 or next_arguments[4] != 2:
                    continue
                has_signature = any(t == target and a[0] == 3 and a[4] == 0 for _, t, a in calls[idx + 2:])
                if not has_signature or not program.direct_success_path(function, first, second):
                    continue
                if arguments[1:4] != next_arguments[1:4] or any(v is None for v in arguments[1:4]):
                    uncertain = True
                    continue
                if arguments[4] not in (0, 1) or not function.complete:
                    uncertain = True
                    continue
                result.evidence.append({
                    "certificate_function": hex(entry),
                    "tag_reader": hex(target),
                    "first_sequence_call": hex(first),
                    "first_sequence_mode": arguments[4],
                    "second_sequence_call": hex(second),
                    "second_sequence_mode": 2,
                    "tag_reader_features": {key: hex(value) for key, value in readers[target].items()},
                    "certificate_disassembly": program.disassembly(function),
                    "tag_reader_disassembly": program.disassembly(program.function(target)),
                })
        modes = {item["first_sequence_mode"] for item in result.evidence}
        if uncertain or len(modes) != 1:
            result.reason = "incomplete, conflicting or absent certificate traversal evidence"
        else:
            mode = modes.pop()
            result.status = LEGACY if mode == 1 else NEW_PARSER
            result.reason = (
                "certificate entry uses enter-value traversal (arg4=1); legacy BIT STRING wrapper required"
                if mode else "certificate entry uses tag-aware traversal (arg4=0); modern wrapper layout"
            )
    except (OSError, ValueError, struct.error, CsError) as exc:
        result.reason = str(exc)
    return result


def format_report(results):
    lines = [
        "MTK CERT2 traversal-mode analysis",
        "Static evidence only. This is NOT an efuse, vulnerability or device boot verification.",
    ]
    for result in results:
        lines += ["", f"Input: {result.path}", f"SHA256: {result.sha256}", f"ISA: {result.isa}",
                  f"Result: {result.status}", f"Reason: {result.reason}", *result.diagnostics]
        for evidence in result.evidence:
            lines += [
                f"Certificate entry {evidence['certificate_function']}; reader {evidence['tag_reader']}",
                f"SEQUENCE modes: {evidence['first_sequence_mode']} -> 2",
                "===DISASM certificate caller===",
                *evidence["certificate_disassembly"],
                "===DISASM tag reader===",
                *evidence["tag_reader_disassembly"],
                "===END===",
            ]
    return "\n".join(lines) + "\n"


def write_report(results, path=None):
    if path is None:
        directory = Path.cwd() / "logs"
        directory.mkdir(exist_ok=True)
        path = directory / f"cert_mode_{datetime.now():%Y%m%d_%H%M%S_%f}.txt"
    path = Path(path)
    if path.resolve() in {Path(result.path).resolve() for result in results}:
        raise ValueError("report must not overwrite an input preloader")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(format_report(results))
    return path


def analyze(path):
    result = detect(path)
    print(format_report([result]), end="")
    return result.status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", help="target preloader image(s), including GFH or boot-container format")
    parser.add_argument("--report", help="new evidence report file (never overwritten)")
    parser.add_argument("--json", action="store_true", help="print structured results")
    parser.add_argument("--regress", action="store_true", help="expect NEW_PARSER then LEGACY on two supplied inputs")
    args = parser.parse_args(argv)
    if args.regress and len(args.images) != 2:
        parser.error("--regress requires exactly two inputs")
    results = [detect(path) for path in args.images]
    try:
        report = write_report(results, args.report)
    except (OSError, ValueError) as exc:
        print(f"Cannot save evidence: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"results": [result.as_dict() for result in results], "report": str(report)}, ensure_ascii=True))
    else:
        for result in results:
            print(f"{result.path}: {result.status}\n  {result.reason}")
        print(f"Evidence: {report}")
    if any(result.status == NEED_MANUAL for result in results):
        return 3
    if args.regress and [result.status for result in results] != [NEW_PARSER, LEGACY]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
