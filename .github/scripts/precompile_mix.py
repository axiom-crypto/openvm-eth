#!/usr/bin/env python3
"""Measure a block's precompile mix via debug_traceBlockByNumber (callTracer).

Usage: precompile_mix.py <block_number>

Uses $RPC_URL if set (must support the debug namespace), with public
trace-capable endpoints as fallback. Prints a markdown summary suitable for
$GITHUB_STEP_SUMMARY. Exits non-zero if no endpoint could trace the block.
"""

import json
import os
import sys
import time
import urllib.request

FALLBACK_RPCS = ["https://eth.drpc.org"]

PRECOMPILES = {
    "0x0000000000000000000000000000000000000001": "ecRecover",
    "0x0000000000000000000000000000000000000002": "SHA2-256",
    "0x0000000000000000000000000000000000000003": "RIPEMD-160",
    "0x0000000000000000000000000000000000000004": "identity",
    "0x0000000000000000000000000000000000000005": "modexp",
    "0x0000000000000000000000000000000000000006": "bn254_add",
    "0x0000000000000000000000000000000000000007": "bn254_mul",
    "0x0000000000000000000000000000000000000008": "bn254_pairing",
    "0x0000000000000000000000000000000000000009": "blake2f",
    "0x000000000000000000000000000000000000000a": "kzg_point_eval",
    "0x000000000000000000000000000000000000000b": "bls_g1add",
    "0x000000000000000000000000000000000000000c": "bls_g1msm",
    "0x000000000000000000000000000000000000000d": "bls_g2add",
    "0x000000000000000000000000000000000000000e": "bls_g2msm",
    "0x000000000000000000000000000000000000000f": "bls_pairing",
    "0x0000000000000000000000000000000000000010": "bls_map_fp",
    "0x0000000000000000000000000000000000000011": "bls_map_fp2",
    "0x0000000000000000000000000000000000000100": "P256VERIFY",
}


def rpc_call(rpcs, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last_err = None
    for attempt in range(8):
        rpc = rpcs[attempt % len(rpcs)]
        req = urllib.request.Request(
            rpc,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "curl/8"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
            if data.get("result") is not None:
                return data["result"]
            last_err = data.get("error")
        except Exception as e:
            last_err = str(e)
        time.sleep(2)
    raise RuntimeError(f"all RPC attempts failed, last error: {last_err}")


def count_calls(node, counts):
    to = (node.get("to") or "").lower()
    if to in PRECOMPILES:
        counts[PRECOMPILES[to]] = counts.get(PRECOMPILES[to], 0) + 1
    for child in node.get("calls") or []:
        count_calls(child, counts)


def main():
    block = int(sys.argv[1])
    rpcs = ([os.environ["RPC_URL"]] if os.environ.get("RPC_URL") else []) + FALLBACK_RPCS
    trace = rpc_call(rpcs, "debug_traceBlockByNumber", [hex(block), {"tracer": "callTracer", "timeout": "120s"}])
    counts = {}
    for tx in trace:
        count_calls(tx.get("result", {}), counts)

    print(f"### Precompile mix of block {block} (measured)")
    print()
    if not counts:
        print("No precompile calls — pure EVM compute block.")
    else:
        print("| precompile | calls |")
        print("|---|---|")
        for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"| {name} | {n} |")
        print()
        print("A win concentrated in one precompile only generalizes to blocks that call it — check the mix before extrapolating single-block deltas to fleet percentiles.")
    print()


if __name__ == "__main__":
    main()
