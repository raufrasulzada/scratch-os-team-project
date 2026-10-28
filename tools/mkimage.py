#!/usr/bin/env python3
"""Pack standalone ELF programs into a Scratch-OS IMG1 image."""

import argparse
import re
import struct
from pathlib import Path

MAX_IMAGE_SIZE = 0x200000
MAX_PROGRAMS = 32
HEADER_SIZE = 20
ENTRY_SIZE = 24

ELF_HEADER = struct.Struct("<16sHHIIIIIHHHHHH")
ELF_PROGRAM_HEADER = struct.Struct("<IIIIIIII")
ELF_SECTION_HEADER = struct.Struct("<IIIIIIIIII")
IMG_HEADER = struct.Struct("<4sIIII")
IMG_ENTRY = struct.Struct("<16sII")

NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,15}\Z")


def check_elf(data, filename, parser):
    """Check basic ELF identity, tables, and loadable segment ranges."""

    if len(data) < 52:
        parser.error(f"{filename}: ELF file is too small")

    fields = ELF_HEADER.unpack_from(data)
    (
        ident, elf_type, machine, version, entry,
        phoff, shoff, _flags, ehsize,
        phentsize, phnum, shentsize, shnum, shstrndx,
    ) = fields

    if ident[:4] != b"\x7fELF":
        parser.error(f"{filename}: not an ELF file")
    if ident[4] != 1 or ident[5] != 1 or ident[6] != 1:
        parser.error(f"{filename}: expected ELF32 little-endian version 1")
    if elf_type != 2 or machine != 40 or version != 1:
        parser.error(f"{filename}: expected an ARM ET_EXEC ELF")
    if ehsize != 52:
        parser.error(f"{filename}: invalid ELF header size")
    if phnum == 0 or phentsize != 32:
        parser.error(f"{filename}: invalid program-header table")
    if phoff > len(data) or phnum > (len(data) - phoff) // 32:
        parser.error(f"{filename}: program-header table is outside the file")
    if shnum == 0 or shentsize != 40:
        parser.error(f"{filename}: invalid section-header table")
    if shoff > len(data) or shnum > (len(data) - shoff) // 40:
        parser.error(f"{filename}: section-header table is outside the file")
    if shstrndx != 0 and shstrndx >= shnum:
        parser.error(f"{filename}: invalid section-name table index")

    found_loadable = False
    entry_valid = False

    for index in range(phnum):
        pos = phoff + index * 32
        (
            p_type, p_offset, p_vaddr, _p_paddr,
            p_filesz, p_memsz, p_flags, _p_align,
        ) = ELF_PROGRAM_HEADER.unpack_from(data, pos)

        if p_type != 1:  # PT_LOAD
            continue

        found_loadable = True

        if p_filesz > p_memsz:
            parser.error(f"{filename}: loadable segment filesz exceeds memsz")
        if p_offset > len(data) or p_filesz > len(data) - p_offset:
            parser.error(f"{filename}: loadable segment is outside the file")
        if p_vaddr + p_memsz > 0x100000000:
            parser.error(f"{filename}: loadable segment address overflows")

        if (
            p_flags & 1
            and p_vaddr <= (entry & ~1) < p_vaddr + p_memsz
        ):
            entry_valid = True

    if not found_loadable:
        parser.error(f"{filename}: no PT_LOAD segment")
    if not (entry & 1) or not entry_valid:
        parser.error(f"{filename}: invalid Thumb entry point")

    # Check that every section record is in the file and that sections
    # containing file bytes stay inside it. SHT_NOBITS has no file contents.
    for index in range(shnum):
        pos = shoff + index * 40
        (
            _name, sh_type, _flags, _addr, sh_offset, sh_size,
            _link, _info, _align, _entsize,
        ) = ELF_SECTION_HEADER.unpack_from(data, pos)

        if sh_type != 8:  # SHT_NOBITS
            if sh_offset > len(data) or sh_size > len(data) - sh_offset:
                parser.error(f"{filename}: section is outside the file")


def build_image(program_specs, parser):
    """Validate inputs and construct the complete image in memory."""

    if not 1 <= len(program_specs) <= MAX_PROGRAMS:
        parser.error("image requires between 1 and 32 programs")

    programs = []
    seen_names = set()

    # Validate every input before constructing or writing the output image.
    for spec in program_specs:
        if "=" not in spec:
            parser.error(f"invalid program argument {spec!r}; expected NAME=FILE")

        name, filename = spec.split("=", 1)

        if not NAME_PATTERN.fullmatch(name):
            parser.error(f"invalid program name {name!r}")
        if name in seen_names:
            parser.error(f"duplicate program name {name!r}")
        if not filename:
            parser.error(f"missing file for program {name!r}")

        try:
            data = Path(filename).read_bytes()
        except OSError as exc:
            parser.error(f"cannot read {filename!r}: {exc}")

        check_elf(data, filename, parser)
        programs.append((name, data))
        seen_names.add(name)

    # The 20-byte header and 24-byte entries are both word-aligned.
    directory_end = HEADER_SIZE + ENTRY_SIZE * len(programs)
    image = bytearray(directory_end)
    directory_entries = []

    # Keep the input order and align each file's starting offset to 4 bytes.
    for name, data in programs:
        padding = (-len(image)) % 4
        image.extend(b"\x00" * padding)

        offset = len(image)
        image.extend(data)
        directory_entries.append((name, offset, len(data)))

        if len(image) > MAX_IMAGE_SIZE:
            parser.error("image exceeds the 2 MiB size limit")

    image_size = len(image)

    # Fill the IMG1 header.
    IMG_HEADER.pack_into(
        image, 0, b"IMG1", 1, image_size, len(programs), HEADER_SIZE
    )

    # Fill the fixed-size directory entries.
    for index, (name, offset, size) in enumerate(directory_entries):
        entry_offset = HEADER_SIZE + index * ENTRY_SIZE
        encoded_name = name.encode("ascii").ljust(16, b"\x00")
        IMG_ENTRY.pack_into(image, entry_offset, encoded_name, offset, size)

    return bytes(image), len(programs)


def main():
    parser = argparse.ArgumentParser(prog="mkimage.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    image_parser = subparsers.add_parser(
        "image", help="pack ELF programs into an IMG1 image"
    )
    image_parser.add_argument("output", help="output image path")
    image_parser.add_argument(
        "programs", nargs="+", metavar="NAME=PROGRAM.elf"
    )

    args = parser.parse_args()

    if args.command == "image":
        image, count = build_image(args.programs, parser)

        try:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(image)
        except OSError as exc:
            parser.error(f"cannot write {args.output!r}: {exc}")

        print(f"IMG1: {args.output} ({len(image)} bytes, {count} programs)")


if __name__ == "__main__":
    main()
