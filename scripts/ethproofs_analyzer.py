#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx", "hishel", "rich", "tenacity"]
# ///
"""
Fetches data from ethproofs.org API and analyzes proving times.

Finds top K blocks by:
- Gas used
- Proving time (max, median, avg, min across that block's provers)
- How far a single prover (default OpenVM 2.0 / Axiom) trails the fastest prover

Run it directly (uv installs the dependencies on first use):
    ./ethproofs_analyzer.py ...        # via the uv shebang
    uv run ethproofs_analyzer.py ...   # equivalent

Common recipes:
    # Blocks where OpenVM trailed the fastest prover by the most, over the last day / week:
    ./ethproofs_analyzer.py --last 1d --compare --top-k 20
    ./ethproofs_analyzer.py --last 1w --compare --top-k 20

    # Blocks that were hardest for EVERY prover (even the leader was slow), last day / week:
    ./ethproofs_analyzer.py --last 1d --metric min --top-k 20
    ./ethproofs_analyzer.py --last 1w --metric min --top-k 20

    # Compare a different prover against the field:
    ./ethproofs_analyzer.py --last 1w --compare --compare-zkvm pico --top-k 20

    # Follow up on a slow block — inspect its precompile load (needs an RPC with `debug`):
    ./precompile_analyzer.py <block_number>

Usage:
    ./ethproofs_analyzer.py                  # last 100 blocks, all metrics
    ./ethproofs_analyzer.py --last 6h        # last 6 hours (also: 30m, 1d, 1w, 45s)
    ./ethproofs_analyzer.py --last 500       # last 500 blocks
    ./ethproofs_analyzer.py --file data.json # Load from a JSON file
    ./ethproofs_analyzer.py --top-k 5        # Show top 5 blocks per metric
    ./ethproofs_analyzer.py --metric median  # Show only median proving time
    ./ethproofs_analyzer.py --metric min     # Blocks where even the fastest prover was slow
    ./ethproofs_analyzer.py --metric gas     # Show only gas used
    ./ethproofs_analyzer.py --cluster axiom  # Only proofs from the Axiom cluster
    ./ethproofs_analyzer.py --zkvm openvm2   # Only proofs from the OpenVM 2.0 zkVM
    ./ethproofs_analyzer.py --list-provers   # Print distinct provers in the data
    ./ethproofs_analyzer.py --compare        # Where OpenVM was slowest, absolute & vs fastest
    ./ethproofs_analyzer.py --no-cache       # Bypass the local page cache

Cached responses live in scripts/.cache (1h TTL); reruns serve from there.
"""

import argparse
import json
import os
import statistics
import sys
from datetime import datetime, timedelta

import hishel
import hishel.httpx
import httpx
import tenacity
from rich.console import Console
from rich.progress import Progress

API_URL = "https://ethproofs.org/api/blocks"

# Directory of cached API responses, reused across runs within CACHE_TTL.
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
CACHE_TTL = 3600  # seconds a cached response stays fresh

# Duration suffixes accepted by --last (e.g. "6h", "1w"), in seconds.
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# Column widths (chars).
COL_RANK, COL_BLOCK, COL_GAS, COL_TXS = 4, 10, 14, 5
COL_TIME, COL_TIMESTAMP, COL_RATIO, COL_ZKVM = 13, 19, 8, 18
ABS_BLOCK, ABS_TARGET_TIME, ABS_CLOSEST_TIME, ABS_CLOSEST_ZKVM = range(4)
REL_BLOCK, REL_TARGET_TIME, REL_FASTEST_TIME, REL_FASTEST_ZKVM, REL_SLOWDOWN = range(5)

# Statistics available as proving-time metrics, keyed by their CLI name.
STATS = {"min": min, "max": max, "median": statistics.median, "avg": statistics.mean}


# --- Formatting -------------------------------------------------------------


def fmt_time(ms: float) -> str:
    """Format milliseconds as seconds."""
    return f"{ms / 1000:.2f}s"


def fmt_gas(gas: int | None) -> str:
    """Format gas with thousands separators."""
    return f"{gas:,}" if gas else "N/A"


def fmt_timestamp(ts: str | None) -> str:
    """Trim a timestamp to YYYY-MM-DD HH:MM:SS."""
    return ts[:19] if ts else "N/A"


def parse_ts(ts: str | None) -> datetime | None:
    """Parse a block timestamp (e.g. '2026-06-20 21:58:23' or ISO 'T' form)."""
    if not ts:
        return None
    try:
        return datetime.strptime(ts.replace("T", " ")[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def print_table(columns: list[tuple[str, int, str]], rows: list[tuple]) -> None:
    """Print a markdown table.

    columns: (header, width, align) per column, align being '<' or '>'.
    rows:    row tuples whose cells line up positionally with columns.
    """
    cell = lambda value, width, align: f"{value:{align}{width}}"
    print("| " + " | ".join(cell(h, w, a) for h, w, a in columns) + " |")
    print("|" + "|".join("-" * (w + 2) for _, w, _ in columns) + "|")
    for row in rows:
        print("| " + " | ".join(cell(v, w, a) for v, (_, w, a) in zip(row, columns)) + " |")


def comparison_time_columns(target_zkvm: str, relationship: str) -> list[tuple[str, int, str]]:
    """Consistent target/competitor columns for comparison tables."""
    return [
        (f"{target_zkvm} Time", COL_TIME, "<"),
        (f"{relationship} Other", COL_TIME, "<"),
        (f"{relationship} zkVM", COL_ZKVM, "<"),
    ]


def comparison_time_cells(
    target_time: float,
    other_time: float | None,
    other_zkvm: str | None,
) -> tuple[str, str, str]:
    """Format the shared target/competitor cells, including missing competitors."""
    return (
        fmt_time(target_time),
        fmt_time(other_time) if other_time is not None else "N/A",
        other_zkvm or "N/A",
    )


# --- Data access ------------------------------------------------------------


def proof_prover_info(proof: dict) -> tuple[str | None, str | None, str | None, int | None]:
    """Extract (cluster_name, zkvm_slug, zkvm_name, num_gpus) from a proof."""
    cv = proof.get("cluster_version") or {}
    cluster = cv.get("cluster") or {}
    zkvm = (cv.get("zkvm_version") or {}).get("zkvm") or {}
    return cluster.get("name"), zkvm.get("slug"), zkvm.get("name"), cluster.get("num_gpus")


def proof_zkvm_label(proof: dict) -> str:
    """Short label for the zkVM that produced a proof."""
    _, zkvm_slug, zkvm_name, _ = proof_prover_info(proof)
    return zkvm_slug or zkvm_name or "N/A"


def proof_matches(proof: dict, cluster: str | None, zkvm: str | None) -> bool:
    """True if the proof's cluster/zkvm contain the given text (case-insensitive)."""
    cluster_name, zkvm_slug, zkvm_name, _ = proof_prover_info(proof)
    if cluster and (not cluster_name or cluster.lower() not in cluster_name.lower()):
        return False
    if zkvm:
        z = zkvm.lower()
        if not ((zkvm_slug and z in zkvm_slug.lower()) or (zkvm_name and z in zkvm_name.lower())):
            return False
    return True


def proving_times(proofs) -> list[float]:
    """Completed proving times (ms) from an iterable of proofs."""
    return [p["proving_time"] for p in proofs if p.get("proving_time") is not None]


# --- Fetching / loading -----------------------------------------------------


def parse_last(spec: str) -> tuple[str, float]:
    """Parse a --last value into ('seconds', n) for durations or ('blocks', n) for counts.

    Durations end in a unit (s/m/h/d/w), e.g. '6h' or '1w'; a bare number means blocks.
    """
    spec = spec.strip().lower()
    if spec and spec[-1] in UNITS:
        return "seconds", float(spec[:-1]) * UNITS[spec[-1]]
    return "blocks", int(spec)


class CacheEverything(hishel.BaseFilter):
    """Filter matching every request and response, so pages cache regardless of HTTP headers."""

    def needs_body(self) -> bool:
        return False

    def apply(self, item, body) -> bool:
        return True


def make_client(ttl: float) -> httpx.Client:
    """An HTTP client whose responses are cached on disk for ttl seconds (0 disables caching)."""
    if not ttl:
        return httpx.Client(timeout=30)
    os.makedirs(CACHE_DIR, exist_ok=True)
    storage = hishel.SyncSqliteStorage(
        database_path=os.path.join(CACHE_DIR, "pages.db"), default_ttl=ttl
    )
    policy = hishel.FilterPolicy(
        request_filters=[CacheEverything()], response_filters=[CacheEverything()]
    )
    return hishel.httpx.SyncCacheClient(storage=storage, policy=policy, timeout=30)


def is_transient(exc: BaseException) -> bool:
    """True for errors worth retrying: timeouts, connection drops, and 5xx responses."""
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return False


@tenacity.retry(
    retry=tenacity.retry_if_exception(is_transient),
    wait=tenacity.wait_exponential(multiplier=0.5, max=5),
    stop=tenacity.stop_after_attempt(4),
    reraise=True,
)
def fetch_blocks(client: httpx.Client, page_index: int, page_size: int, machine_type: str) -> dict:
    """Fetch one page of blocks, retrying transient errors with exponential backoff."""
    resp = client.get(
        API_URL,
        params={"page_index": page_index, "page_size": page_size, "machine_type": machine_type},
    )
    resp.raise_for_status()
    return resp.json()


def fetch_window(
    client: httpx.Client, mode: str, amount: float, page_size: int,
    machine_type: str, max_pages: int = 4000,
) -> dict:
    """Page through blocks (newest first) until `amount` blocks or seconds are covered.

    mode='blocks' keeps the most recent `amount` blocks; mode='seconds' keeps blocks
    within `amount` seconds of the newest block.
    """
    rows, anchor, cutoff, page, warning = [], None, None, 0, None
    total = int(amount)
    with Progress(console=Console(stderr=True), transient=True) as progress:
        task = progress.add_task("Fetching blocks", total=total)
        for page in range(max_pages):
            try:
                page_rows = fetch_blocks(client, page, page_size, machine_type).get("rows", [])
            except httpx.HTTPError as e:
                warning = f"stopped at page {page + 1} after a failed request ({e})"
                break
            if not page_rows:
                break
            rows.extend(page_rows)

            if mode == "blocks":
                progress.update(task, completed=min(len(rows), total))
                if len(rows) >= amount or len(page_rows) < page_size:
                    break
            else:
                times = [t for t in (parse_ts(b.get("timestamp")) for b in page_rows) if t]
                if times:
                    if anchor is None:
                        anchor = max(times)
                        cutoff = anchor - timedelta(seconds=amount)
                    progress.update(task, completed=min(int((anchor - min(times)).total_seconds()), total))
                if len(page_rows) < page_size or (cutoff and times and min(times) < cutoff):
                    break

    if mode == "blocks":
        rows = rows[:total]
    elif cutoff is not None:
        rows = [b for b in rows if (parse_ts(b.get("timestamp")) or cutoff) >= cutoff]
    if warning:
        print(f"  Warning: {warning}; keeping {len(rows):,} blocks fetched so far.")
        print("  Tip: a smaller --size (e.g. 200) often avoids large-page server errors.")
    print(f"  Fetched {len(rows):,} blocks ({page + 1} pages)")
    return {"rows": rows}


def load_from_file(filepath: str) -> dict:
    """Load JSON data from a file."""
    with open(filepath, "r") as f:
        return json.load(f)


# --- Analyses ---------------------------------------------------------------


def list_provers(data: dict) -> None:
    """Print distinct (zkvm, slug, cluster, num_gpus) combinations and their counts."""
    seen: dict[tuple, int] = {}
    for block in data.get("rows", []):
        for p in block.get("proofs", []):
            cluster_name, zkvm_slug, zkvm_name, num_gpus = proof_prover_info(p)
            key = (zkvm_name, zkvm_slug, cluster_name, num_gpus)
            seen[key] = seen.get(key, 0) + 1

    if not seen:
        print("No provers found in the data.")
        return

    print("## Provers seen\n")
    rows = [
        (zkvm_name or "N/A", slug or "N/A", cluster or "N/A",
         num_gpus if num_gpus is not None else "N/A", count)
        for (zkvm_name, slug, cluster, num_gpus), count in sorted(
            seen.items(), key=lambda kv: (-kv[1], kv[0][0] or "", kv[0][2] or "")
        )
    ]
    print_table(
        [("zkVM", 20, "<"), ("slug", 12, "<"), ("Cluster", 32, "<"),
         ("GPUs", 4, ">"), ("Proofs", 7, ">")],
        rows,
    )


def analyze_blocks(
    data: dict,
    top_k: int = 1,
    metric: str = "all",
    cluster_filter: str | None = None,
    zkvm_filter: str | None = None,
) -> None:
    """Show top blocks by gas used and by proving-time statistics across provers."""
    rows = data.get("rows", [])
    if not rows:
        print("No blocks found in the response.")
        return

    filter_active = bool(cluster_filter or zkvm_filter)

    # Select blocks (those with a matching proof, when a filter is active) and the
    # proving times of the proofs that count toward their stats.
    selected = []  # (block, times)
    for block in rows:
        proofs = block.get("proofs", [])
        if filter_active:
            proofs = [p for p in proofs if proof_matches(p, cluster_filter, zkvm_filter)]
            if not proofs:
                continue
        selected.append((block, proving_times(proofs)))

    with_gas = [(b, b["gas_used"]) for b, _ in selected if b.get("gas_used") is not None]
    timed = [(b, t) for b, t in selected if t]
    total_proofs = sum(len(t) for _, t in timed)

    if filter_active:
        parts = ([f"cluster~'{cluster_filter}'"] if cluster_filter else []) + (
            [f"zkvm~'{zkvm_filter}'"] if zkvm_filter else []
        )
        print(f"**Filter:** {', '.join(parts)}")
        print(f"Fetched {len(rows):,} blocks, {len(selected):,} match filter "
              f"({len(with_gas):,} with gas, {total_proofs:,} matching proofs)\n")
    else:
        print(f"Fetched {len(rows):,} blocks "
              f"({len(with_gas):,} with gas, {total_proofs:,} proofs)\n")

    if metric in ("all", "gas"):
        print(f"## Top {top_k} by Gas Used\n")
        if with_gas:
            top = sorted(with_gas, key=lambda bg: bg[1], reverse=True)[:top_k]
            print_table(
                [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"), ("Gas", COL_GAS, ">"),
                 ("Txs", COL_TXS, ">"), ("Timestamp", COL_TIMESTAMP, "<")],
                [(rank, b.get("block_number"), fmt_gas(gas),
                  b.get("transaction_count") or "N/A", fmt_timestamp(b.get("timestamp")))
                 for rank, (b, gas) in enumerate(top, 1)],
            )
        else:
            print("No blocks with gas data found")

    time_metrics = [m for m in STATS if metric in ("all", m)]
    if time_metrics and not timed:
        print("\nNo proofs with proving time data found")
        return

    for name in time_metrics:
        stat = STATS[name]
        top = sorted(timed, key=lambda bt: stat(bt[1]), reverse=True)[:top_k]
        print(f"\n## Top {top_k} by {name.upper()} Proving Time\n")
        print_table(
            [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"),
             (f"Time ({name})", COL_TIME, "<"), ("Gas", COL_GAS, ">"), ("Txs", COL_TXS, ">")],
            [(rank, b.get("block_number"), fmt_time(stat(t)), fmt_gas(b.get("gas_used")),
              b.get("transaction_count") or "N/A")
             for rank, (b, t) in enumerate(top, 1)],
        )


def analyze_comparison(
    data: dict,
    top_k: int = 10,
    target_zkvm: str = "openvm2",
    target_cluster: str | None = None,
) -> None:
    """Find blocks where the target prover (default OpenVM 2.0 / Axiom) was slow.

    Two tables:
      1. ABSOLUTE  - blocks where the target's own proving time was highest,
                     alongside the closest other completed proof.
      2. RELATIVE  - blocks where the target trailed the fastest *other* prover by
                     the largest ratio (target time / fastest competitor).
    """
    rows = data.get("rows", [])
    if not rows:
        print("No blocks found in the response.")
        return

    absolute = []  # (block, target_time, closest_other_time, closest_other_zkvm)
    relative = []  # (block, target_time, fastest_other_time, fastest_other_zkvm, ratio)
    for block in rows:
        proofs = block.get("proofs", [])
        target = proving_times(p for p in proofs if proof_matches(p, target_cluster, target_zkvm))
        others = [
            p for p in proofs
            if not proof_matches(p, target_cluster, target_zkvm)
            and p.get("proving_time") is not None
        ]
        if not target:
            continue
        t = min(target)  # target's fastest completed proof for this block
        if others:
            closest = min(others, key=lambda p: abs(p["proving_time"] - t))
            absolute.append((block, t, closest["proving_time"], proof_zkvm_label(closest)))
            fastest = min(others, key=lambda p: p["proving_time"])
            fastest_time = fastest["proving_time"]
            relative.append((block, t, fastest_time, proof_zkvm_label(fastest), t / fastest_time))
        else:
            absolute.append((block, t, None, None))

    label = target_zkvm + (f" / {target_cluster}" if target_cluster else "")
    print(f"**Target prover:** {label}")
    print(f"Fetched {len(rows):,} blocks, {len(absolute):,} with a completed {target_zkvm} "
          f"proof, {len(relative):,} comparable to other provers\n")

    if not absolute:
        print(f"No completed proofs found for {target_zkvm}.")
        return

    top_abs = sorted(absolute, key=lambda x: x[ABS_TARGET_TIME], reverse=True)[:top_k]
    print(f"## Top {top_k} blocks where {target_zkvm} was SLOWEST (absolute)\n")
    print_table(
        [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"),
         *comparison_time_columns(target_zkvm, "Closest"),
         ("Gas", COL_GAS, ">"), ("Txs", COL_TXS, ">")],
        [(rank, b.get("block_number"), *comparison_time_cells(t, closest_time, closest_zkvm),
          fmt_gas(b.get("gas_used")), b.get("transaction_count") or "N/A")
         for rank, (b, t, closest_time, closest_zkvm) in enumerate(top_abs, 1)],
    )

    if not relative:
        print(f"\nNo blocks have both a {target_zkvm} proof and another prover to compare.")
        return

    top_rel = sorted(relative, key=lambda x: x[REL_SLOWDOWN], reverse=True)[:top_k]
    print(f"\n## Top {top_k} blocks where {target_zkvm} trailed the FASTEST other prover\n")
    print_table(
        [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"),
         *comparison_time_columns(target_zkvm, "Fastest"), ("Slowdown", COL_RATIO, ">")],
        [(rank, b.get("block_number"), *comparison_time_cells(t, fastest, fastest_zkvm),
          f"{ratio:.2f}x")
         for rank, (b, t, fastest, fastest_zkvm, ratio) in enumerate(top_rel, 1)],
    )


# --- CLI --------------------------------------------------------------------


def load_data(args: argparse.Namespace) -> dict:
    """Load block data from a file or the ethproofs API per the parsed args."""
    if args.file:
        print(f"**Source:** {args.file}\n")
        return load_from_file(args.file)
    mode, amount = parse_last(args.last)
    ttl = 0 if args.no_cache else args.cache_ttl
    print(f"**Source:** {API_URL}  ")
    print(f"**Config:** last {args.last}, filter={args.machine_type}"
          f"{'' if ttl else ', cache off'}\n")
    data = fetch_window(make_client(ttl), mode, amount, args.size, args.machine_type)
    print()
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Analyze ethproofs.org block data: top blocks by gas, proving time, "
        "and how far one prover trails the fastest.",
    )
    parser.add_argument("--last", "-l", default="100",
                        help="How much recent data to fetch: a duration (6h, 1d, 1w) or a "
                        "block count (500). Default: 100")
    parser.add_argument("--file", "-f", type=str,
                        help="Load data from a JSON file instead of fetching")
    parser.add_argument("--machine-type", "-m", default="multi", choices=["multi", "single"],
                        help="Machine type filter (default: multi)")
    parser.add_argument("--size", "-s", type=int, default=100,
                        help="Blocks per API request, a fetch-tuning knob (default: 100)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass the local page cache and always hit the API")
    parser.add_argument("--cache-ttl", type=int, default=CACHE_TTL,
                        help=f"Seconds a cached page stays fresh (default: {CACHE_TTL})")
    parser.add_argument("--top-k", "-k", type=int, default=None,
                        help="Top blocks to show per metric (default: 1, or 10 with --compare)")
    parser.add_argument("--metric", default="all", choices=["all", "gas", *STATS],
                        help="Which metric to show (default: all)")
    parser.add_argument("--cluster", default=None,
                        help="Filter to proofs whose cluster name contains this text, e.g. 'axiom'")
    parser.add_argument("--zkvm", default=None,
                        help="Filter to proofs whose zkvm slug/name contains this text, e.g. 'openvm2'")
    parser.add_argument("--list-provers", action="store_true",
                        help="List distinct provers seen in the fetched data and exit")
    parser.add_argument("--compare", action="store_true",
                        help="Show where the target prover was slowest, absolute and vs the fastest other prover")
    parser.add_argument("--compare-zkvm", default="openvm2",
                        help="zkvm slug/name of the prover to compare in --compare mode (default: openvm2)")
    parser.add_argument("--compare-cluster", default=None,
                        help="Optional cluster substring to further pin the --compare target (e.g. 'axiom')")

    args = parser.parse_args()
    top_k = args.top_k if args.top_k is not None else (10 if args.compare else 1)

    print("\n# ETHPROOFS ANALYZER\n")

    try:
        data = load_data(args)
    except ValueError:
        print(f"Error: invalid --last value '{args.last}' (use e.g. 500, 6h, 1d, 1w)")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    except httpx.HTTPError as e:
        print(f"\nError fetching data: {e}")
        print("Try: ./ethproofs_analyzer.py --file data.json")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        sys.exit(1)

    if args.list_provers:
        list_provers(data)
    elif args.compare:
        analyze_comparison(data, top_k, args.compare_zkvm, args.compare_cluster)
    else:
        analyze_blocks(data, top_k, args.metric, args.cluster, args.zkvm)


if __name__ == "__main__":
    main()
