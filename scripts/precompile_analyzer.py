#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx", "tenacity", "rich", "python-dotenv"]
# ///
"""
Analyzes precompile calls in an Ethereum block via debug_traceBlockByNumber.

For a block it reports how many times each precompile (ecrecover, bn254_*, kzg, …)
was called, and the transactions that called them most. Needs an RPC endpoint with
the `debug` namespace enabled.

RPC endpoints are read from .env as RPC_1, RPC_2, … and tried in order until one
serves the trace (override with --rpc); public trace-capable fallbacks are tried
last. Run --check to see which support tracing.

Run it directly (uv installs the dependencies on first use):
    ./precompile_analyzer.py <block_number>
    uv run precompile_analyzer.py <block_number>   # equivalent

Typical workflow — find a slow block with ethproofs_analyzer, then inspect it here:
    ./ethproofs_analyzer.py --last 1d --metric min --top-k 20   # hardest blocks for every prover
    ./ethproofs_analyzer.py --last 1d --compare --top-k 20      # blocks where OpenVM trailed most
    ./precompile_analyzer.py <block_number>                     # why: that block's precompile load

Usage:
    ./precompile_analyzer.py 21000000                       # analyze a block
    ./precompile_analyzer.py 21000000 --rpc http://host:8545 # against a specific RPC
    ./precompile_analyzer.py 21000000 -v                    # also report tx and call-frame counts
    ./precompile_analyzer.py 21000000 --top-k 10            # top 10 transactions
    ./precompile_analyzer.py 21000000 --filter bn254_add,bn254_mul  # only these precompiles
    ./precompile_analyzer.py --check                        # verify the RPC supports tracing
"""

import argparse
import os
import re
import sys
from pathlib import Path

import httpx
import tenacity
from dotenv import dotenv_values
from rich.console import Console

# Endpoint used when no --rpc and no RPC_N in the environment or .env.
DEFAULT_RPC_URL = "http://localhost:8545"
# Public trace-capable endpoints, tried after the configured ones.
FALLBACK_RPCS = ["https://eth.drpc.org"]
DEFAULT_TOP_K = 5

# .env at the repository root (one level above scripts/).
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# Precompile address -> name, by hardfork.
PRECOMPILES = {
    # Frontier
    "0x0000000000000000000000000000000000000001": "ecrecover",
    "0x0000000000000000000000000000000000000002": "sha256",
    "0x0000000000000000000000000000000000000003": "ripemd160",
    "0x0000000000000000000000000000000000000004": "identity",
    # Byzantium
    "0x0000000000000000000000000000000000000005": "modexp",
    "0x0000000000000000000000000000000000000006": "bn254_add",
    "0x0000000000000000000000000000000000000007": "bn254_mul",
    "0x0000000000000000000000000000000000000008": "bn254_pairing",
    # Istanbul
    "0x0000000000000000000000000000000000000009": "blake2f",
    # Cancun
    "0x000000000000000000000000000000000000000a": "kzg_point_eval",
    # Prague
    "0x000000000000000000000000000000000000000b": "bls12_g1_add",
    "0x000000000000000000000000000000000000000c": "bls12_g1_msm",
    "0x000000000000000000000000000000000000000d": "bls12_g2_add",
    "0x000000000000000000000000000000000000000e": "bls12_g2_msm",
    "0x000000000000000000000000000000000000000f": "bls12_pairing",
    "0x0000000000000000000000000000000000000010": "bls12_map_fp_to_g1",
    "0x0000000000000000000000000000000000000011": "bls12_map_fp2_to_g2",
    # Osaka (RIP-7212)
    "0x0000000000000000000000000000000000000100": "p256_verify",
}

# Lower-cased precompile name -> canonical name, for case-insensitive --filter.
PRECOMPILE_NAMES = {name.lower(): name for name in PRECOMPILES.values()}

# Column widths (chars).
COL_RANK, COL_TX, COL_CALLS, COL_PRECOMPILE = 4, 66, 6, 22


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


# --- RPC --------------------------------------------------------------------


def resolve_rpcs(explicit: list[str] | None) -> list[tuple[str, str]]:
    """(label, url) endpoints to try in order: explicit --rpc, else RPC_1, RPC_2, … , else
    default — always followed by the public fallbacks.

    Labels are safe to print; URLs hold secrets and must not be logged.
    """
    if explicit:
        pairs = [(f"RPC #{i}", url) for i, url in enumerate(explicit, 1)]
    else:
        values = {**dotenv_values(ENV_PATH), **os.environ}
        keys = sorted((k for k in values if re.fullmatch(r"RPC_\d+", k)),
                      key=lambda k: int(k.split("_")[1]))
        pairs = [(k, values[k]) for k in keys if values[k]] or [("default", DEFAULT_RPC_URL)]
    urls = {url for _, url in pairs}
    pairs += [(f"fallback ({url})", url) for url in FALLBACK_RPCS if url not in urls]
    return pairs


def redact(text) -> str:
    """Strip the key-bearing path from any URL in text, leaving only scheme and host."""
    return re.sub(r"(https?://[^/\s]+)/[^\s'\"]*", r"\1/…", str(text))


def make_client(url: str) -> httpx.Client:
    """An httpx client targeting one RPC endpoint."""
    return httpx.Client(base_url=url, timeout=120, headers={"Content-Type": "application/json"})


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
def rpc_call(client: httpx.Client, method: str, params: list) -> dict:
    """Make a JSON-RPC call, retrying transient errors with exponential backoff."""
    resp = client.post("", json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
    if 400 <= resp.status_code < 500:
        try:
            error = resp.json()["error"]
        except (ValueError, KeyError):
            error = None
        if error:
            raise RuntimeError(f"RPC error: {error}")
    resp.raise_for_status()
    result = resp.json()
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    return result


# --- Tracing ----------------------------------------------------------------


def count_precompiles(call: dict, counts: dict[str, int]) -> None:
    """Tally precompile calls in a call frame and its subcalls (recursive)."""
    name = PRECOMPILES.get(call.get("to", "").lower())
    if name:
        counts[name] = counts.get(name, 0) + 1
    for subcall in call.get("calls", []):
        count_precompiles(subcall, counts)


def count_call_frames(call: dict) -> int:
    """Count the call frames in a call tree (recursive)."""
    return 1 + sum(count_call_frames(sub) for sub in call.get("calls", []))


def analyze_block(client: httpx.Client, block_number: int, verbose: bool = False) -> list:
    """Trace a block and return [(tx_hash, {precompile: count})] for txs that used any."""
    with Console(stderr=True).status(f"Tracing block {block_number}..."):
        result = rpc_call(client, "debug_traceBlockByNumber",
                          [hex(block_number), {"tracer": "callTracer"}])

    trace = result.get("result", [])
    if verbose:
        frames = sum(count_call_frames(tx["result"]) for tx in trace if "result" in tx)
        print(f"  Transactions: {len(trace)}, Call frames: {frames}")

    tx_stats = []
    for tx_trace in trace:
        counts: dict[str, int] = {}
        if "result" in tx_trace:
            count_precompiles(tx_trace["result"], counts)
        if counts:
            tx_stats.append((tx_trace.get("txHash", "unknown"), counts))
    return tx_stats


def check_rpc(client: httpx.Client) -> bool:
    """Report whether the RPC endpoint supports debug_traceBlockByNumber."""
    print("Checking for debug_traceBlockByNumber support...")
    try:
        block_num = int(rpc_call(client, "eth_blockNumber", [])["result"], 16)
        print(f"  eth_blockNumber: {block_num}")
        trace = rpc_call(client, "debug_traceBlockByNumber",
                         [hex(block_num - 100), {"tracer": "callTracer"}]).get("result", [])
        print(f"  debug_traceBlockByNumber: OK ({len(trace)} transactions)")
        return True
    except (httpx.HTTPError, RuntimeError, KeyError, ValueError) as e:
        print(f"  Error: {redact(e)}")
        return False


# --- Reporting --------------------------------------------------------------


def parse_filter(filter_arg: str) -> list[str]:
    """Parse a comma-separated --filter value into canonical precompile names."""
    names = []
    for part in (p.strip() for p in filter_arg.split(",")):
        if not part:
            continue
        canonical = PRECOMPILE_NAMES.get(part.lower())
        if canonical is None:
            valid = ", ".join(sorted(PRECOMPILES.values()))
            raise ValueError(f"Invalid precompile name: {part}\nValid names: {valid}")
        names.append(canonical)
    return names


def print_summary(tx_stats: list, block_number: int, filter_names: list[str] | None) -> None:
    """Print block-level precompile totals."""
    totals: dict[str, int] = {}
    for _, counts in tx_stats:
        for name, count in counts.items():
            if not filter_names or name in filter_names:
                totals[name] = totals.get(name, 0) + count

    suffix = f" (filtered: {', '.join(filter_names)})" if filter_names else ""
    print(f"## Block {block_number} Summary{suffix}\n")
    rows = [(name, count) for name, count in sorted(totals.items(), key=lambda x: -x[1]) if count]
    rows.append(("Total", sum(totals.values())))
    print_table([("Precompile", COL_PRECOMPILE, "<"), ("Calls", COL_CALLS, ">")], rows)


def print_top_transactions(tx_stats: list, top_k: int, filter_names: list[str] | None) -> None:
    """Print the transactions with the most precompile calls."""
    if filter_names:
        stats = [(h, {k: v for k, v in c.items() if k in filter_names}) for h, c in tx_stats]
        stats = [(h, c) for h, c in stats if c]
        heading = f"Transactions using {', '.join(filter_names)}"
    else:
        stats, heading = tx_stats, "Transactions by Precompile Calls"

    top = sorted(stats, key=lambda x: -sum(x[1].values()))[:top_k]
    print(f"\n## Top {len(top)} {heading}\n")
    print_table(
        [("Rank", COL_RANK, ">"), ("Transaction", COL_TX, "<"), ("Calls", COL_CALLS, ">")],
        [(rank, tx_hash, sum(counts.values())) for rank, (tx_hash, counts) in enumerate(top, 1)],
    )


# --- CLI --------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Analyze precompile calls in an Ethereum block via debug_traceBlockByNumber",
    )
    parser.add_argument("block", type=int, nargs="?", help="Block number to analyze")
    parser.add_argument("--rpc", nargs="+", metavar="URL",
                        help="One or more RPC URLs to try in order "
                        "(default: RPC_1, RPC_2, … from .env, then localhost)")
    parser.add_argument("--check", action="store_true",
                        help="Check whether the RPC endpoints support debug_traceBlockByNumber")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Also report transaction and call-frame counts")
    parser.add_argument("--top-k", "-k", type=int, default=DEFAULT_TOP_K,
                        help=f"Number of top transactions to show (default: {DEFAULT_TOP_K})")
    parser.add_argument("--filter", "-f",
                        help="Only these precompiles, comma-separated (e.g. bn254_add,bn254_mul)")

    args = parser.parse_args()
    rpcs = resolve_rpcs(args.rpc)

    if args.check:
        ok = False
        for label, url in rpcs:
            print(f"\n{label}")
            ok |= check_rpc(make_client(url))
        sys.exit(0 if ok else 1)

    if args.block is None:
        parser.error("block number is required (or use --check)")

    filter_names = None
    if args.filter:
        try:
            filter_names = parse_filter(args.filter)
        except ValueError as e:
            parser.error(str(e))

    print("\n# PRECOMPILE ANALYZER\n")
    print(f"**Block:** {args.block}\n")

    # Try each endpoint until one serves the trace.
    tx_stats, used = None, None
    for label, url in rpcs:
        try:
            tx_stats = analyze_block(make_client(url), args.block, args.verbose)
            used = label
            break
        except (httpx.HTTPError, RuntimeError) as e:
            print(f"  {label} unavailable: {redact(e)}")

    if used is None:
        print("\nError: no working RPC (set RPC_1, RPC_2, … in .env, or pass --rpc).")
        sys.exit(1)
    print(f"**RPC:** {used}\n")

    if not tx_stats:
        print("No precompile calls found in this block.")
        sys.exit(0)

    print_summary(tx_stats, args.block, filter_names)
    print_top_transactions(tx_stats, args.top_k, filter_names)


if __name__ == "__main__":
    main()
