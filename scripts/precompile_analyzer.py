#!/usr/bin/env python3
"""
Analyzes precompile calls in Ethereum blocks using debug_traceBlockByNumber.

Usage:
    python3 precompile_analyzer.py <block_number>
    python3 precompile_analyzer.py <block_number> --rpc <url>
    python3 precompile_analyzer.py <block_number> --rpc <url> --rpc <fallback_url>
    python3 precompile_analyzer.py <block_number> -v
    python3 precompile_analyzer.py <block_number> --top-k 10
    python3 precompile_analyzer.py <block_number> --filter bn254_add
    python3 precompile_analyzer.py <block_number> --filter bn254_add,bn254_mul
    python3 precompile_analyzer.py --check
"""

import argparse
import json
import sys
import time
import urllib.request

DEFAULT_RPC_URL = "http://localhost:8545"
DEFAULT_TOP_K = 5

# Public endpoints fail transiently (rate limits, free-plan request timeouts),
# so every RPC call makes up to this many passes over the endpoints.
RPC_ATTEMPTS = 3
RPC_RETRY_DELAY_SECS = 5

# Precompile addresses
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

# Case-insensitive lookup for filtering
PRECOMPILE_NAMES = {name.lower(): name for name in PRECOMPILES.values()}

# Table column widths
COL_RANK = 4
COL_TX = 66
COL_CALLS = 6
COL_PRECOMPILE = 22

# Table formatting
SUMMARY_HEADER = f"| {'Precompile':<{COL_PRECOMPILE}} | {'Calls':>{COL_CALLS}} |"
SUMMARY_SEP = f"|{'-' * (COL_PRECOMPILE + 2)}|{'-' * (COL_CALLS + 2)}|"

TX_HEADER = (
    f"| {'Rank':>{COL_RANK}} | {'Transaction':<{COL_TX}} | {'Calls':>{COL_CALLS}} |"
)
TX_SEP = f"|{'-' * (COL_RANK + 2)}|{'-' * (COL_TX + 2)}|{'-' * (COL_CALLS + 2)}|"


def rpc_call(urls: list[str], method: str, params: list):
    """Make a JSON-RPC call, trying the endpoints in order, and return its result."""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    error = None
    for attempt in range(RPC_ATTEMPTS):
        if attempt:
            time.sleep(RPC_RETRY_DELAY_SECS)
        for url in urls:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                # Some public endpoints reject urllib's default User-Agent.
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "precompile-analyzer",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as response:
                    body = json.loads(response.read().decode())
                if body.get("result") is not None:
                    return body["result"]
                error = body.get("error")
            except Exception as e:
                error = e
            print(f"  {method} via {url} failed: {error}", file=sys.stderr)
    raise Exception(f"{method} failed {RPC_ATTEMPTS} times on every endpoint: {error}")


def process_call_for_tx(call: dict, counts: dict[str, int]) -> None:
    """Process a single call and its subcalls, counting precompile calls for a tx."""
    to_addr = call.get("to", "").lower()
    if to_addr in PRECOMPILES:
        name = PRECOMPILES[to_addr]
        counts[name] = counts.get(name, 0) + 1

    for subcall in call.get("calls", []):
        process_call_for_tx(subcall, counts)


def count_call_frames(call: dict) -> int:
    """Count total call frames in a call tree."""
    n = 1
    for sub in call.get("calls", []):
        n += count_call_frames(sub)
    return n


def analyze_block(
    rpc_urls: list[str], block_number: int, verbose: bool = False
) -> list:
    """Analyze a single block and return per-transaction precompile counts."""
    block_hex = hex(block_number)
    tracer_config = {"tracer": "callTracer"}

    trace = rpc_call(rpc_urls, "debug_traceBlockByNumber", [block_hex, tracer_config])
    if verbose:
        total_calls = 0
        for tx in trace:
            if "result" in tx:
                total_calls += count_call_frames(tx["result"])
        print(f"  Transactions: {len(trace)}, Call frames: {total_calls}")

    # Build per-transaction stats
    tx_stats = []
    for tx_trace in trace:
        tx_hash = tx_trace.get("txHash", "unknown")
        counts: dict[str, int] = {}
        if "result" in tx_trace:
            process_call_for_tx(tx_trace["result"], counts)
        if counts:
            tx_stats.append((tx_hash, counts))

    return tx_stats


def check_rpc(rpc_urls: list[str]) -> bool:
    """Check if the RPC endpoints support debug_traceBlockByNumber."""
    print("Checking for debug_traceBlockByNumber support...")

    try:
        block_num = int(rpc_call(rpc_urls, "eth_blockNumber", []), 16)
        print(f"  eth_blockNumber: {block_num}")

        # Use an older block for testing (100 blocks back)
        test_block = block_num - 100
        tracer_config = {"tracer": "callTracer"}

        trace = rpc_call(
            rpc_urls, "debug_traceBlockByNumber", [hex(test_block), tracer_config]
        )
        print(f"  debug_traceBlockByNumber: OK ({len(trace)} transactions)")
        return True
    except Exception as e:
        print(f"  Error: {e}")
        return False


def normalize_precompile_name(name: str) -> str | None:
    """Normalize precompile name (case-insensitive). Returns None if invalid."""
    return PRECOMPILE_NAMES.get(name.lower())


def parse_filter(filter_arg: str) -> list[str]:
    """Parse comma-separated filter argument and normalize names."""
    names = []
    for part in filter_arg.split(","):
        part = part.strip()
        if not part:
            continue
        normalized = normalize_precompile_name(part)
        if normalized is None:
            valid = ", ".join(sorted(PRECOMPILES.values()))
            raise ValueError(f"Invalid precompile name: {part}\nValid names: {valid}")
        names.append(normalized)
    return names


def filter_tx_stats(
    tx_stats: list, filter_names: list[str]
) -> list[tuple[str, dict[str, int]]]:
    """Filter transaction stats to only include specified precompiles."""
    if not filter_names:
        return tx_stats

    filtered = []
    for tx_hash, counts in tx_stats:
        filtered_counts = {k: v for k, v in counts.items() if k in filter_names}
        if filtered_counts:
            filtered.append((tx_hash, filtered_counts))
    return filtered


def print_summary(
    tx_stats: list, block_number: int, filter_names: list[str] | None
) -> None:
    """Print block-level precompile summary."""
    # Aggregate counts across all transactions
    totals: dict[str, int] = {}
    for _, counts in tx_stats:
        for name, count in counts.items():
            if filter_names and name not in filter_names:
                continue
            totals[name] = totals.get(name, 0) + count

    total = sum(totals.values())

    if filter_names:
        filter_str = ", ".join(filter_names)
        print(f"## Block {block_number} Summary (filtered: {filter_str})\n")
    else:
        print(f"## Block {block_number} Summary\n")

    print(SUMMARY_HEADER)
    print(SUMMARY_SEP)

    for name, count in sorted(totals.items(), key=lambda x: -x[1]):
        if count > 0:
            print(f"| {name:<{COL_PRECOMPILE}} | {count:>{COL_CALLS}} |")

    print(SUMMARY_SEP)
    print(f"| {'Total':<{COL_PRECOMPILE}} | {total:>{COL_CALLS}} |")


def print_top_transactions(
    tx_stats: list, top_k: int, filter_names: list[str] | None
) -> None:
    """Print top transactions by precompile calls."""
    if filter_names:
        # Filter and sort by matching precompiles
        filtered = filter_tx_stats(tx_stats, filter_names)
        sorted_stats = sorted(filtered, key=lambda x: -sum(x[1].values()))
        top = sorted_stats[:top_k]

        filter_str = ", ".join(filter_names)
        print(f"\n## Top {len(top)} Transactions using {filter_str}\n")
    else:
        # Sort by total precompile calls
        sorted_stats = sorted(tx_stats, key=lambda x: -sum(x[1].values()))
        top = sorted_stats[:top_k]

        print(f"\n## Top {len(top)} Transactions by Precompile Calls\n")

    print(TX_HEADER)
    print(TX_SEP)

    for rank, (tx_hash, counts) in enumerate(top, 1):
        total = sum(counts.values())
        print(f"| {rank:>{COL_RANK}} | {tx_hash:<{COL_TX}} | {total:>{COL_CALLS}} |")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze precompile calls in Ethereum blocks using debug_traceBlockByNumber",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 21000000                              Analyze block 21000000
  %(prog)s 21000000 --rpc http://localhost:8545
  %(prog)s 21000000 -v                           Verbose output
  %(prog)s 21000000 --top-k 10                   Show top 10 transactions
  %(prog)s 21000000 --filter ecrecover           Filter by precompile
  %(prog)s 21000000 --filter bn254_add,bn254_mul Filter by multiple precompiles
  %(prog)s --check                               Check if RPC supports trace method
        """,
    )
    parser.add_argument(
        "block",
        type=int,
        nargs="?",
        help="Block number to analyze",
    )
    parser.add_argument(
        "--rpc",
        type=str,
        action="append",
        help=f"RPC endpoint URL; repeat to add fallbacks, tried in order (default: {DEFAULT_RPC_URL})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if RPC endpoint supports debug_traceBlockByNumber",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print debug information about the trace response",
    )
    parser.add_argument(
        "--top-k",
        "-k",
        type=int,
        default=DEFAULT_TOP_K,
        help=f"Number of top transactions to show (default: {DEFAULT_TOP_K})",
    )
    parser.add_argument(
        "--filter",
        "-f",
        type=str,
        help="Filter by precompile name(s), comma-separated (e.g., bn254_add,bn254_mul)",
    )

    args = parser.parse_args()
    rpc_urls = args.rpc or [DEFAULT_RPC_URL]

    if args.check:
        success = check_rpc(rpc_urls)
        sys.exit(0 if success else 1)

    if args.block is None:
        parser.error("block number is required (or use --check)")

    # Parse and validate filter if provided
    filter_names = None
    if args.filter:
        try:
            filter_names = parse_filter(args.filter)
        except ValueError as e:
            parser.error(str(e))

    print("\n# PRECOMPILE ANALYZER\n")
    print(f"**Block:** {args.block}\n")

    try:
        tx_stats = analyze_block(rpc_urls, args.block, args.verbose)

        if not tx_stats:
            print("No precompile calls found in this block.")
            sys.exit(0)

        print_summary(tx_stats, args.block, filter_names)
        print_top_transactions(tx_stats, args.top_k, filter_names)

    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
