#!/usr/bin/env python3
"""Generate a .def file exporting symbols from static libraries.

Used on Windows to selectively export HILTI/Spicy runtime symbols from
zeek.exe so that JIT-compiled HLTO DLLs can import them at load time.

Usage: python generate-jit-export-def.py <dumpbin_exe> <output.def> <lib1.lib> [lib2.lib ...] [-- <backing_lib1> ...]

Libraries before '--' are "primary": all their defined external symbols are
exported.  Libraries after '--' are "backing": only symbols that are
*referenced but undefined* in the primary set are exported from the backing
set.  This resolves transitive dependencies (e.g. core Zeek APIs called by
inline runtime code) without exporting the entire Zeek symbol table.
"""

import subprocess
import sys


def _parse_symbols(dumpbin, lib_path):
    """Return (defined, undefined) sets of external symbols."""
    result = subprocess.run(
        [dumpbin, "/SYMBOLS", lib_path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        print(
            f"Warning: dumpbin failed on {lib_path}: {result.stderr}", file=sys.stderr
        )
        return set(), set()

    defined = set()
    undefined = set()
    for line in result.stdout.splitlines():
        if "External" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) < 2:
            continue
        sym = parts[1].strip()
        if not sym:
            continue
        paren_idx = sym.find(" (")
        if paren_idx > 0:
            sym = sym[:paren_idx].strip()
        if not sym:
            continue
        if sym.startswith("@") or sym.startswith("$") or sym.startswith("__@@_"):
            continue
        if sym.startswith(".") or sym == "@comp.id" or sym == "@feat.00":
            continue
        if "UNDEF" in line:
            undefined.add(sym)
        else:
            defined.add(sym)
    return defined, undefined


def extract_defined_externals(dumpbin, lib_path):
    """Extract defined external symbols from a static library using dumpbin."""
    defined, _ = _parse_symbols(dumpbin, lib_path)
    return defined


def main():
    if len(sys.argv) < 4:
        print(
            f"Usage: {sys.argv[0]} <dumpbin> <output.def> <lib1> [lib2 ...] [-- <backing1> ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    dumpbin = sys.argv[1]
    output_def = sys.argv[2]
    rest = sys.argv[3:]

    # Split on '--' separator
    if "--" in rest:
        sep = rest.index("--")
        primary_files = rest[:sep]
        backing_files = rest[sep + 1 :]
    else:
        primary_files = rest
        backing_files = []

    # Phase 1: collect all defined + undefined symbols from primary libs.
    all_symbols = set()
    all_undefs = set()
    for lib in primary_files:
        defined, undefined = _parse_symbols(dumpbin, lib)
        print(
            f"  {lib}: {len(defined)} defined, {len(undefined)} undefined",
            file=sys.stderr,
        )
        all_symbols.update(defined)
        all_undefs.update(undefined)

    # Remove symbols that are already satisfied by the primary set.
    unresolved = all_undefs - all_symbols

    # Phase 2: from backing libs, export only symbols needed by primary libs.
    if backing_files and unresolved:
        backing_exported = 0
        for lib in backing_files:
            defined, undefined = _parse_symbols(dumpbin, lib)
            resolved = defined & unresolved
            if resolved:
                all_symbols.update(resolved)
                unresolved -= resolved
                # Also pull in the backing libs' own undefined deps (one more level).
                all_undefs.update(undefined)
                backing_exported += len(resolved)
        print(
            f"  Backing libs resolved {backing_exported} additional symbols",
            file=sys.stderr,
        )

    # Force-export C++ allocation functions so JIT DLLs (compiled with /MT)
    # use the EXE's heap for all allocations/deallocations, avoiding cross-module
    # heap mismatches.
    crt_alloc_symbols = [
        "??2@YAPEAX_K@Z",  # operator new(size_t)
        "??_U@YAPEAX_K@Z",  # operator new[](size_t)
        "??3@YAXPEAX@Z",  # operator delete(void*)
        "??3@YAXPEAX_K@Z",  # operator delete(void*, size_t)
        "??_V@YAXPEAX@Z",  # operator delete[](void*)
        "??_V@YAXPEAX_K@Z",  # operator delete[](void*, size_t)
    ]
    for sym in crt_alloc_symbols:
        all_symbols.add(sym)

    # Filter out symbols that should never be exported to JIT DLLs.
    excluded = set()
    for sym in all_symbols:
        # MSVC string literals (??_C@) are internal to their translation unit;
        # JIT DLLs compile their own copies and never import these.
        if sym.startswith("??_C@"):
            excluded.add(sym)
            continue
        # main() and hilti::main() are default entry points for standalone
        # HILTI programs (from hilti-rt's main.cc).  zeek.exe provides its
        # own main(), so these objects are never pulled from the static
        # library and must not appear in the export list.
        if sym.startswith("?main@@") or sym.startswith("?main@hilti@@"):
            excluded.add(sym)

    if excluded:
        all_symbols -= excluded
        print(f"  Excluded {len(excluded)} non-exportable symbols", file=sys.stderr)

    print(f"  Total unique symbols: {len(all_symbols)}", file=sys.stderr)

    if len(all_symbols) > 65000:
        print(
            f"WARNING: {len(all_symbols)} symbols may exceed COFF limit of 65535",
            file=sys.stderr,
        )

    with open(output_def, "w") as f:
        f.write("EXPORTS\n")
        for sym in sorted(all_symbols):
            f.write(f"    {sym}\n")

    print(f"  Wrote {output_def}", file=sys.stderr)


if __name__ == "__main__":
    main()
