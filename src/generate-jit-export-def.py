#!/usr/bin/env python3
"""Generate a .def file exporting symbols from static libraries.

Used on Windows to selectively export symbols from zeek.exe so that
JIT-compiled HLTO DLLs and dynamic plugins can import them at load time.

Usage: python generate-jit-export-def.py <dumpbin_exe> <output.def> <lib1.lib> [lib2.lib ...]
       [--scan-dir <dir>]  [-- <backing_lib1> ...]

Libraries before '--' are "primary": all their defined external symbols are
exported.  Libraries after '--' are "backing": only symbols that are
*referenced but undefined* in the primary set are exported from the backing
set.  This resolves transitive dependencies (e.g. core Zeek APIs called by
inline runtime code) without exporting the entire Zeek symbol table.

--scan-dir <dir> scans for zeek_* and plugin-* obj files under <dir>,
adding them to the primary set. Uses os.walk to avoid symlink loops.
"""

import os
import re
import subprocess
import sys


def _parse_symbols(dumpbin, lib_path):
    """Return (defined, undefined, data_syms) sets of external symbols.

    data_syms contains names of symbols that are data (not functions).
    """
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
        return set(), set(), set()

    defined = set()
    undefined = set()
    data_syms = set()
    for line in result.stdout.splitlines():
        if "External" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) < 2:
            continue
        # Check if this is a function ("notype ()") or data ("notype" only).
        is_function = "notype ()" in parts[0]
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
            if not is_function:
                data_syms.add(sym)
    return defined, undefined, data_syms


def extract_defined_externals(dumpbin, lib_path):
    """Extract defined external symbols from a static library using dumpbin."""
    defined, _, _ = _parse_symbols(dumpbin, lib_path)
    return defined


# Regex matching CMakeFiles directories for Zeek build targets.
_TARGET_DIR_RE = re.compile(r"(zeek_[\w-]+|plugin-[\w-]+)\.dir$")


def _scan_obj_files(scan_dir):
    """Find all .obj files under zeek_* and plugin-* CMakeFiles target dirs.

    Uses os.walk with followlinks=False to avoid infinite recursion from
    symlinks (e.g. the scripts -> source symlink created by the plugin build).
    """
    result = []
    for dirpath, dirnames, filenames in os.walk(scan_dir, followlinks=False):
        # Check if any path component matches a target dir pattern.
        parts = os.path.normpath(dirpath).split(os.sep)
        if any(_TARGET_DIR_RE.match(p) for p in parts):
            for fn in filenames:
                if fn.endswith(".obj"):
                    result.append(os.path.join(dirpath, fn))
    return result


def _should_export(sym):
    """Return True if a symbol should be exported to plugins/JIT DLLs.

    Uses a whitelist approach: only export symbols in namespaces that
    plugins actually use, plus a few special categories.
    """
    # Always exclude MSVC string literals.
    if sym.startswith("??_C@"):
        return False

    # Exclude main() entry points.
    if sym.startswith("?main@@") or sym.startswith("?main@hilti@@"):
        return False

    # Exclude scalar/vector deleting destructors (compiler-generated, LNK4102).
    if sym.startswith("??_G") or sym.startswith("??_E"):
        return False

    # Whitelist: export symbols in Zeek-related namespaces.
    # MSVC mangles namespace::symbol as ?symbol@namespace@@...
    # We check for @zeek@@, @plugin@@, @hilti@@, @spicy@@, @doctest@@ etc.
    whitelisted_ns = [
        "@zeek@@",
        "@plugin@@",
        "@hilti@@",
        "@spicy@@",
        "@doctest@@",
        "@binpac@@",
    ]

    # Also whitelist unmangled C symbols (zeek_version_*, spicy_version_*, etc.)
    if (
        sym.startswith("zeek_")
        or sym.startswith("version")
        or sym.startswith("spicy_")
        or sym.startswith("hilti_")
    ):
        return True

    # Check if the symbol belongs to a whitelisted namespace.
    if any(ns in sym for ns in whitelisted_ns):
        # Exclude ZAM/compiler internals even in zeek namespace.
        if "ZInst" in sym or "ZBody" in sym or "ZAMCompiler" in sym:
            return False
        # Exclude protocol analyzer internals that external plugins never need.
        # These are built-in analyzer implementations, not public API.
        if any(
            ns in sym
            for ns in [
                "@SNMP@@",
                "@DNS@@",
                "@HTTP@@",
                "@FTP@@",
                "@SMTP@@",
                "@SSH@@",
                "@SSL@@",
                "@SMB@@",
                "@NTP@@",
                "@MQTT@@",
                "@Modbus@@",
                "@MySQL@@",
                "@IMAP@@",
                "@IRC@@",
                "@KRB@@",
                "@Ident@@",
                "@SOCKS@@",
                "@RDP@@",
                "@SIP@@",
                "@RADIUS@@",
                "@POP3@@",
                "@XMPP@@",
                "@GTPv1@@",
                "@NetBIOS@@",
                "@Teredo@@",
                "@VXLAN@@",
                "@SteppingStone@@",
                "@BackDoor@@",
                "@InterConn@@",
                "@ARP@@",
                "@DCE_RPC@@",
                "@Login@@",
                "@Rlogin@@",
                "@RSH@@",
                "@DHCP@@",
                "@DNP3@@",
                "@NCP@@",
                "@BitTorrent@@",
            ]
        ):
            return False
        # Exclude std:: template instantiations (??$) - these are
        # compiler-generated and each DLL gets its own copies. Only keep
        # non-template zeek symbols.
        if sym.startswith("??$"):
            return False
        return True

    # RTTI (??_R) and vtables (??_7) for whitelisted namespaces are
    # already handled above. Exclude all others.
    if sym.startswith("??_R") or sym.startswith("??_7"):
        return False

    # Exclude everything else (third-party libs, std:: internals, etc.)
    return False


def main():
    if len(sys.argv) < 4:
        print(
            f"Usage: {sys.argv[0]} <dumpbin> <output.def> <lib1> [lib2 ...] "
            f"[--scan-dir <dir>] [-- <backing1> ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    dumpbin = sys.argv[1]
    output_def = sys.argv[2]
    rest = sys.argv[3:]

    # Parse --scan-dir options.
    scan_dirs = []
    filtered_rest = []
    i = 0
    while i < len(rest):
        if rest[i] == "--scan-dir" and i + 1 < len(rest):
            scan_dirs.append(rest[i + 1])
            i += 2
        else:
            filtered_rest.append(rest[i])
            i += 1
    rest = filtered_rest

    # Expand scan directories into obj file lists.
    extra_files = []
    if scan_dirs:
        for scan_dir in scan_dirs:
            extra_files.extend(_scan_obj_files(scan_dir))
        print(
            f"  Scanned {len(extra_files)} obj files from {len(scan_dirs)} directories",
            file=sys.stderr,
        )

    # Split on '--' separator.
    if "--" in rest:
        sep = rest.index("--")
        primary_files = rest[:sep] + extra_files
        backing_files = rest[sep + 1 :]
    else:
        primary_files = rest + extra_files
        backing_files = []

    # Phase 1: collect all defined + undefined symbols from primary libs.
    all_symbols = set()
    all_undefs = set()
    all_data_syms = set()
    for lib in primary_files:
        defined, undefined, data_syms = _parse_symbols(dumpbin, lib)
        print(
            f"  {lib}: {len(defined)} defined, {len(undefined)} undefined",
            file=sys.stderr,
        )
        all_symbols.update(defined)
        all_undefs.update(undefined)
        all_data_syms.update(data_syms)

    # Remove symbols that are already satisfied by the primary set.
    unresolved = all_undefs - all_symbols

    # Phase 2: from backing libs, export only symbols needed by primary libs.
    if backing_files and unresolved:
        backing_exported = 0
        for lib in backing_files:
            defined, undefined, data_syms = _parse_symbols(dumpbin, lib)
            resolved = defined & unresolved
            if resolved:
                all_symbols.update(resolved)
                all_data_syms.update(data_syms & resolved)
                unresolved -= resolved
                # Also pull in the backing libs' own undefined deps (one more level).
                all_undefs.update(undefined)
                backing_exported += len(resolved)
        print(
            f"  Backing libs resolved {backing_exported} additional symbols",
            file=sys.stderr,
        )

    # Apply whitelist filter.
    exported = {sym for sym in all_symbols if _should_export(sym)}
    exported_data = all_data_syms & exported

    # Force-add CRT allocation functions. With static CRT (/MT), each
    # module gets its own heap. By exporting these from zeek.exe and
    # forcing plugins to import them (via /INCLUDE linker directives),
    # all new/delete operations use the same heap.
    crt_alloc_symbols = [
        "??2@YAPEAX_K@Z",  # operator new(size_t)
        "??_U@YAPEAX_K@Z",  # operator new[](size_t)
        "??3@YAXPEAX@Z",  # operator delete(void*)
        "??3@YAXPEAX_K@Z",  # operator delete(void*, size_t)
        "??_V@YAXPEAX@Z",  # operator delete[](void*)
        "??_V@YAXPEAX_K@Z",  # operator delete[](void*, size_t)
    ]
    exported.update(crt_alloc_symbols)

    excluded_count = len(all_symbols) - len(exported)
    print(f"  Excluded {excluded_count} non-exportable symbols", file=sys.stderr)
    print(
        f"  Total unique symbols: {len(exported)} ({len(exported_data)} data)",
        file=sys.stderr,
    )

    if len(exported) > 65000:
        print(
            f"WARNING: {len(exported)} symbols may exceed COFF limit of 65535",
            file=sys.stderr,
        )

    with open(output_def, "w") as f:
        f.write("EXPORTS\n")
        for sym in sorted(exported):
            f.write(f"    {sym}\n")

    print(f"  Wrote {output_def}", file=sys.stderr)


if __name__ == "__main__":
    main()
