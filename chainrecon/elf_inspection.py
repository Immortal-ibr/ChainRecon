"""Bounded, data-only ELF metadata inspection for extracted firmware files."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


_MAX_TABLE_ENTRIES = 512
_MAX_STRING_TABLE = 2_000_000


def inspect_elf(path: Path) -> dict[str, Any] | None:
    """Return loader, dependencies, and hardening metadata without executing code.

    Malformed offsets are reported as a partial parse. Only ELF headers and
    bounded table regions are read; section data is not loaded wholesale.
    """
    size = path.stat().st_size
    if size < 52:
        return None
    with path.open("rb") as handle:
        header = handle.read(64)
        if header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] not in (1, 2):
            return None
        bits = 32 if header[4] == 1 else 64
        prefix = "<" if header[5] == 1 else ">"
        elf_type = struct.unpack_from(prefix + "H", header, 16)[0]
        if bits == 32:
            phoff, shoff = struct.unpack_from(prefix + "II", header, 28)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(prefix + "HHHH", header, 42)
            ph_min, sh_min = 32, 40
        else:
            phoff, shoff = struct.unpack_from(prefix + "QQ", header, 32)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(prefix + "HHHH", header, 54)
            ph_min, sh_min = 56, 64
        result: dict[str, Any] = {
            "interpreter": None, "needed": [], "pie": False,
            "nx_stack": None, "relro": "none", "parse_status": "complete",
        }

        def table_ok(offset: int, count: int, entry_size: int, minimum: int) -> bool:
            return (0 <= count <= _MAX_TABLE_ENTRIES and entry_size >= minimum
                    and offset >= 0 and offset + count * entry_size <= size)

        if phnum and not table_ok(phoff, phnum, phentsize, ph_min):
            result["parse_status"] = "partial"
            return result
        has_relro = False
        for index in range(phnum):
            handle.seek(phoff + index * phentsize)
            entry = handle.read(ph_min)
            if bits == 32:
                p_type, p_offset, _, _, p_filesz, _, p_flags, _ = struct.unpack(prefix + "IIIIIIII", entry)
            else:
                p_type, p_flags, p_offset, _, _, p_filesz, _, _ = struct.unpack(prefix + "IIQQQQQQ", entry)
            if p_type == 3 and 0 < p_filesz <= 4096 and p_offset + p_filesz <= size:
                handle.seek(p_offset)
                result["interpreter"] = handle.read(p_filesz).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            elif p_type == 0x6474E551:
                result["nx_stack"] = not bool(p_flags & 1)
            elif p_type == 0x6474E552:
                has_relro = True
        result["pie"] = elf_type == 3 and bool(result["interpreter"])

        if shnum and not table_ok(shoff, shnum, shentsize, sh_min):
            result["parse_status"] = "partial"
            result["relro"] = "partial" if has_relro else "none"
            return result
        sections: list[tuple[int, int, int, int, int]] = []
        for index in range(shnum):
            handle.seek(shoff + index * shentsize)
            entry = handle.read(sh_min)
            if bits == 32:
                _, section_type, _, _, offset, length, link, _, _, entry_size = struct.unpack(prefix + "IIIIIIIIII", entry)
            else:
                _, section_type, _, _, offset, length, link, _, _, entry_size = struct.unpack(prefix + "IIQQQQIIQQ", entry)
            sections.append((section_type, offset, length, link, entry_size))
        bind_now = False
        for section_type, offset, length, link, entry_size in sections:
            if section_type != 6:
                continue
            if link >= len(sections) or offset + length > size or length > _MAX_STRING_TABLE:
                result["parse_status"] = "partial"
                continue
            _, string_offset, string_length, _, _ = sections[link]
            if string_length > _MAX_STRING_TABLE or string_offset + string_length > size:
                result["parse_status"] = "partial"
                continue
            handle.seek(string_offset)
            strings = handle.read(string_length)
            width = 8 if bits == 32 else 16
            if entry_size < width:
                result["parse_status"] = "partial"
                continue
            for index in range(min(length // entry_size, _MAX_TABLE_ENTRIES)):
                handle.seek(offset + index * entry_size)
                tag, value = struct.unpack(prefix + ("II" if bits == 32 else "QQ"), handle.read(width))
                if tag == 0:
                    break
                if tag == 1 and value < len(strings):
                    name = strings[value:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    if name and name not in result["needed"]:
                        result["needed"].append(name)
                elif tag == 24 or (tag == 30 and value & 8) or (tag == 0x6FFFFFFB and value & 1):
                    bind_now = True
        result["relro"] = "full" if has_relro and bind_now else "partial" if has_relro else "none"
        return result
