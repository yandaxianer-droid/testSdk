"""Minimal, dependency-free DEX (Dalvik Executable) reader.

Only the parts required for code-similarity analysis are implemented:

* the list of string constants,
* the list of class descriptors,
* the opcode sequence of every method body.

Parsing deliberately favours robustness over completeness: anything that cannot
be decoded is skipped rather than raising, so that an obfuscated or slightly
malformed APK still yields a usable (partial) feature set.

References: Android "Dalvik Executable format" and "Dalvik bytecode" docs.
"""

from __future__ import annotations

import struct
import sys
from array import array
from dataclasses import dataclass, field
from typing import List


def _build_instruction_size_table() -> List[int]:
    """Width (in 16-bit code units) of each Dalvik instruction, by opcode.

    Variable-length payloads (packed/sparse switch, fill-array-data) start with
    opcode 0x00 but a non-zero high byte and are handled separately by the
    walker, so their entry here is irrelevant.
    """
    size = [1] * 256

    def fill(lo: int, hi: int, value: int) -> None:
        for op in range(lo, hi + 1):
            size[op] = value

    size[0x02] = 2
    size[0x03] = 3
    size[0x05] = 2
    size[0x06] = 3
    size[0x08] = 2
    size[0x09] = 3
    size[0x13] = 2
    size[0x14] = 3
    size[0x15] = 2
    size[0x16] = 2
    size[0x17] = 3
    size[0x18] = 5
    size[0x19] = 2
    size[0x1A] = 2
    size[0x1B] = 3
    size[0x1C] = 2
    size[0x1F] = 2
    size[0x20] = 2
    size[0x22] = 2
    size[0x23] = 2
    size[0x24] = 3
    size[0x25] = 3
    size[0x26] = 3
    size[0x29] = 2
    size[0x2A] = 3
    size[0x2B] = 3
    size[0x2C] = 3
    fill(0x2D, 0x31, 2)   # cmp*
    fill(0x32, 0x37, 2)   # if-test
    fill(0x38, 0x3D, 2)   # if-testz
    fill(0x44, 0x51, 2)   # aget/aput
    fill(0x52, 0x5F, 2)   # iget/iput
    fill(0x60, 0x6D, 2)   # sget/sput
    fill(0x6E, 0x72, 3)   # invoke-kind
    fill(0x74, 0x78, 3)   # invoke-kind/range
    fill(0x90, 0xAF, 2)   # binop
    fill(0xD0, 0xD7, 2)   # binop/lit16
    fill(0xD8, 0xE2, 2)   # binop/lit8
    size[0xFA] = 4        # invoke-polymorphic
    size[0xFB] = 4        # invoke-polymorphic/range
    size[0xFC] = 3        # invoke-custom
    size[0xFD] = 3        # invoke-custom/range
    size[0xFE] = 2        # const-method-handle
    size[0xFF] = 2        # const-method-type
    return size


_SIZE_TABLE = _build_instruction_size_table()


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 value; return (value, new_position)."""
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    return result, pos


def _walk_opcodes(units: array, start: int, count: int) -> List[int]:
    """Return the opcodes of a method body.

    ``units`` is the whole DEX as little-endian u16 code units; the method's
    ``insns`` array spans ``[start, start + count)``. nops and switch/array
    payloads are skipped so that only real instructions contribute.
    """
    opcodes: List[int] = []
    i = start
    end = start + count
    while i < end:
        unit = units[i]
        op = unit & 0xFF
        high = unit >> 8
        if op == 0x00:
            if high == 0x00:          # nop
                i += 1
                continue
            if high == 0x01:          # packed-switch-payload
                length = 4 + 2 * units[i + 1]
            elif high == 0x02:        # sparse-switch-payload
                length = 2 + 4 * units[i + 1]
            elif high == 0x03:        # fill-array-data-payload
                element_width = units[i + 1]
                size_val = units[i + 2] | (units[i + 3] << 16)
                length = 4 + (size_val * element_width + 1) // 2
            else:
                break                  # unknown pseudo-op: stop this method
            i += length
            continue
        opcodes.append(op)
        i += _SIZE_TABLE[op]
    return opcodes


@dataclass
class DexFeatures:
    strings: List[bytes] = field(default_factory=list)
    class_descriptors: List[bytes] = field(default_factory=list)
    # One opcode list per method body that has code.
    methods: List[List[int]] = field(default_factory=list)


class DexFile:
    """Parses a single classes*.dex blob into similarity features."""

    def __init__(self, data: bytes):
        if data[:4] != b"dex\n":
            raise ValueError("not a DEX file (bad magic)")
        self.data = data
        units = array("H")
        units.frombytes(data[: (len(data) // 2) * 2])
        if sys.byteorder == "big":
            units.byteswap()
        self.units = units

        (
            self.string_ids_size,
            self.string_ids_off,
            self.type_ids_size,
            self.type_ids_off,
        ) = struct.unpack_from("<IIII", data, 0x38)
        (
            self.class_defs_size,
            self.class_defs_off,
        ) = struct.unpack_from("<II", data, 0x60)

    def _string_at(self, index: int) -> bytes:
        off = struct.unpack_from("<I", self.data, self.string_ids_off + index * 4)[0]
        _, off = _read_uleb128(self.data, off)  # utf16 length, unused
        end = self.data.index(b"\x00", off)
        return self.data[off:end]

    def _type_descriptor(self, type_index: int) -> bytes:
        string_index = struct.unpack_from(
            "<I", self.data, self.type_ids_off + type_index * 4
        )[0]
        return self._string_at(string_index)

    def parse(self) -> DexFeatures:
        features = DexFeatures()

        for i in range(self.string_ids_size):
            try:
                features.strings.append(self._string_at(i))
            except (IndexError, ValueError):
                continue

        for i in range(self.class_defs_size):
            base = self.class_defs_off + i * 32
            class_idx = struct.unpack_from("<I", self.data, base)[0]
            class_data_off = struct.unpack_from("<I", self.data, base + 24)[0]
            try:
                features.class_descriptors.append(self._type_descriptor(class_idx))
            except (IndexError, ValueError):
                pass
            if class_data_off:
                try:
                    self._parse_class_data(class_data_off, features)
                except (IndexError, ValueError):
                    continue

        return features

    def _parse_class_data(self, off: int, features: DexFeatures) -> None:
        data = self.data
        static_fields, off = _read_uleb128(data, off)
        instance_fields, off = _read_uleb128(data, off)
        direct_methods, off = _read_uleb128(data, off)
        virtual_methods, off = _read_uleb128(data, off)

        for _ in range(static_fields + instance_fields):
            _, off = _read_uleb128(data, off)   # field_idx_diff
            _, off = _read_uleb128(data, off)   # access_flags

        for _ in range(direct_methods + virtual_methods):
            _, off = _read_uleb128(data, off)       # method_idx_diff
            _, off = _read_uleb128(data, off)       # access_flags
            code_off, off = _read_uleb128(data, off)
            if not code_off:
                continue
            insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
            if insns_size == 0:
                continue
            start_unit = (code_off + 16) // 2
            opcodes = _walk_opcodes(self.units, start_unit, insns_size)
            if opcodes:
                features.methods.append(opcodes)
