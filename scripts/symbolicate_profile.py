#!/usr/bin/env python3
"""Post-process a samply-generated Firefox Profiler profile to add DWARF source
info (file:line, demangled names) using `addr2line`.

samply 0.13.1 with `import --save-only` only extracts the symbol table from
local binaries; the saved profile.json.gz reaches Firefox Profiler with
mangled names and no source file/line info. This script fills those in.

Speed comes from three things:
  1. Globally dedupe (lib, addr) pairs across all threads.
  2. One addr2line process per binary, fed all addresses via stdin (the 600 MB
     openvm-reth-benchmark binary's DWARF index gets built exactly once).
  3. Per-binary jobs run in parallel.
"""

import argparse
import gzip
import json
import os
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor


def resolve_with_addr2line(lib_path, addrs):
    """Resolve every address in `addrs` for `lib_path` in one addr2line call.

    Returns {addr: (func_name, file, line)}.

    Uses ``-i`` so addr2line emits the full inlined chain (innermost-first).
    We pick the LAST pair, i.e. the outermost (physical) containing function,
    so flamegraph parents enclose children even when the body was inlined.
    """
    if not addrs:
        return {}
    addrs = sorted(addrs)
    stdin = "\n".join(hex(a) for a in addrs) + "\n"
    try:
        proc = subprocess.run(
            ["addr2line", "-e", lib_path, "-a", "-f", "-C", "-i"],
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("addr2line not found on PATH", file=sys.stderr)
        return {}
    if proc.returncode != 0:
        print(f"addr2line failed on {lib_path}: {proc.stderr.strip()}", file=sys.stderr)
        return {}

    def parse_file_line(s):
        file_part, _, line_part = s.rpartition(":")
        line_part = line_part.split(" ", 1)[0]  # strip " (discriminator N)"
        try:
            return file_part, int(line_part)
        except ValueError:
            return file_part, 0

    result = {}
    lines = proc.stdout.splitlines()
    n = len(lines)
    i = 0
    cur_addr = None
    cur_pairs = []  # list of (func, file, line), innermost-first

    def flush():
        if cur_addr is None or not cur_pairs:
            return
        # Outermost is the last entry — that's the physical function
        # whose address range contains this PC.
        func, file_path, line_no = cur_pairs[-1]
        result[cur_addr] = (func, file_path, line_no)

    while i < n:
        line = lines[i]
        if line.startswith("0x"):
            flush()
            cur_addr = int(line, 16)
            cur_pairs = []
            i += 1
            continue
        if cur_addr is None or i + 1 >= n:
            i += 1
            continue
        func = line
        file_path, line_no = parse_file_line(lines[i + 1])
        cur_pairs.append((func, file_path, line_no))
        i += 2
    flush()
    return result


def collect_global_addrs(d):
    """Walk every thread once and collect {lib_path: set(addrs)}."""
    libs = d["libs"]
    lib_addrs = defaultdict(set)
    lib_path_cache = {}

    def lib_path_for(li):
        if li in lib_path_cache:
            return lib_path_cache[li]
        lib = libs[li]
        path = lib.get("debugPath") or lib.get("path")
        path = path if path and os.path.isfile(path) else None
        lib_path_cache[li] = path
        return path

    for thread in d["threads"]:
        frames = thread["frameTable"]
        funcs = thread["funcTable"]
        resources = thread["resourceTable"]
        frame_func = frames["func"]
        frame_addr = frames["address"]
        func_resource = funcs["resource"]
        resource_lib = resources["lib"]
        for fi in range(frames["length"]):
            fc = frame_func[fi]
            if fc is None or fc < 0:
                continue
            r = func_resource[fc]
            if r is None or r < 0:
                continue
            li = resource_lib[r]
            if li is None or li < 0:
                continue
            path = lib_path_for(li)
            if path is None:
                continue
            addr = frame_addr[fi]
            if addr is None or addr < 0:
                continue
            lib_addrs[path].add(addr)
    return lib_addrs


def apply_resolutions(d, resolved):
    """Write resolved names / file / line into every thread's tables."""
    libs = d["libs"]
    total_names = total_lines = 0

    for thread in d["threads"]:
        frames = thread["frameTable"]
        funcs = thread["funcTable"]
        resources = thread["resourceTable"]
        strings = thread["stringArray"]

        intern_cache = {s: i for i, s in enumerate(strings)}

        def intern(s):
            idx = intern_cache.get(s)
            if idx is None:
                strings.append(s)
                idx = len(strings) - 1
                intern_cache[s] = idx
            return idx

        frame_func = frames["func"]
        frame_addr = frames["address"]
        frame_line = frames["line"]
        func_resource = funcs["resource"]
        func_name = funcs["name"]
        func_file = funcs["fileName"]
        func_line = funcs["lineNumber"]
        resource_lib = resources["lib"]

        for fi in range(frames["length"]):
            fc = frame_func[fi]
            if fc is None or fc < 0:
                continue
            r = func_resource[fc]
            if r is None or r < 0:
                continue
            li = resource_lib[r]
            if li is None or li < 0:
                continue
            lib = libs[li]
            lib_path = lib.get("debugPath") or lib.get("path")
            if not lib_path:
                continue
            info = resolved.get(lib_path, {}).get(frame_addr[fi])
            if info is None:
                continue
            name, file_path, line_no = info
            if name and name != "??":
                func_name[fc] = intern(name)
                total_names += 1
            if file_path and file_path != "??" and line_no > 0:
                func_file[fc] = intern(file_path)
                func_line[fc] = line_no
                frame_line[fi] = line_no
                total_lines += 1

    return total_names, total_lines


def process(profile_path, output_path, workers):
    with gzip.open(profile_path, "rt") as f:
        d = json.load(f)

    print("Collecting addresses...", file=sys.stderr)
    lib_addrs = collect_global_addrs(d)
    total_unique = sum(len(v) for v in lib_addrs.values())
    print(
        f"  {total_unique} unique (lib, addr) pairs across {len(lib_addrs)} libs",
        file=sys.stderr,
    )
    for lib_path, addrs in lib_addrs.items():
        print(f"    {len(addrs):6d}  {os.path.basename(lib_path)}", file=sys.stderr)

    print(f"Resolving with addr2line ({workers} workers)...", file=sys.stderr)
    resolved = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(resolve_with_addr2line, lib, addrs): lib
            for lib, addrs in lib_addrs.items()
        }
        for fut in futures:
            lib_path = futures[fut]
            resolved[lib_path] = fut.result()

    print("Writing back into profile...", file=sys.stderr)
    n_names, n_lines = apply_resolutions(d, resolved)
    print(
        f"  updated {n_names} func names, {n_lines} file:line entries", file=sys.stderr
    )

    with gzip.open(output_path, "wt") as f:
        json.dump(d, f, separators=(",", ":"))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", help="Input profile.json.gz")
    p.add_argument("-o", "--output", help="Output path (default: overwrite input)")
    p.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=os.cpu_count() or 4,
        help="Parallel addr2line workers (default: CPU count)",
    )
    args = p.parse_args()
    process(args.input, args.output or args.input, args.jobs)


if __name__ == "__main__":
    main()
