#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx", "hishel", "rich", "tenacity"]
# ///
"""
Fetches data from ethproofs.org API and analyzes proving times.

Reports:
- Top K blocks by gas used
- Range-wide proving-time statistics across completed proofs
- Legacy per-block proving-time rankings
- How a single prover (default OpenVM 2.0) compares with the fastest other prover

Run it directly (uv installs the dependencies on first use):
    ./scripts/ethproofs_analyzer.py ...        # via the uv shebang
    uv run scripts/ethproofs_analyzer.py ...   # equivalent

Common recipes:
    # Blocks with the highest OpenVM / fastest-other ratio, over the last day / week:
    ./scripts/ethproofs_analyzer.py --last 1d --compare --top-k 20
    ./scripts/ethproofs_analyzer.py --last 1w --compare --top-k 20

    # Median OpenVM proving time across the last day / week:
    ./scripts/ethproofs_analyzer.py --last 1d --metric median --zkvm openvm2
    ./scripts/ethproofs_analyzer.py --last 1w --metric median --zkvm openvm2

    # Fastest completed multi-machine proof across all zkVMs in the last week:
    ./scripts/ethproofs_analyzer.py --last 1w --metric min

    # Compare a different prover against the field:
    ./scripts/ethproofs_analyzer.py --last 1w --compare --compare-zkvm pico --top-k 20

    # Follow up on a slow block — inspect its precompile load (needs an RPC with `debug`):
    ./scripts/precompile_analyzer.py <block_number>

Usage:
    ./scripts/ethproofs_analyzer.py                  # last 100 blocks, all metrics
    ./scripts/ethproofs_analyzer.py --last 6h        # last 6 wall-clock hours
    ./scripts/ethproofs_analyzer.py --last 500       # last 500 blocks
    ./scripts/ethproofs_analyzer.py --file data.json # load from a JSON file
    ./scripts/ethproofs_analyzer.py --top-k 5        # top 5 gas and per-block time rows
    ./scripts/ethproofs_analyzer.py --metric median  # range median
    ./scripts/ethproofs_analyzer.py --top-k 5 --no-block-rankings  # rank gas only
    ./scripts/ethproofs_analyzer.py --cluster axiom  # only proofs from the Axiom cluster
    ./scripts/ethproofs_analyzer.py --zkvm openvm2   # only OpenVM 2.0 proofs
    ./scripts/ethproofs_analyzer.py --list-provers   # print distinct provers
    ./scripts/ethproofs_analyzer.py --compare        # compare OpenVM with other provers
    ./scripts/ethproofs_analyzer.py --cache-ttl 600  # override the cache TTL
    ./scripts/ethproofs_analyzer.py --no-cache       # require fresh API pages
    ./scripts/ethproofs_analyzer.py --require-complete  # fail instead of using partial results

Successful API pages are cached for one hour by default so long queries can resume
after a failure. Pagination consistency checks reject incompatible cached snapshots.
Cached responses live in scripts/.cache.
"""

import argparse
import json
import math
import os
import statistics
import sys
from datetime import datetime, timedelta, timezone

import hishel
import hishel.httpx
import httpx
import tenacity
from rich.console import Console
from rich.progress import Progress

API_URL = "https://ethproofs.org/api/blocks"

# Directory of cached successful API responses.
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
CACHE_TTL = 3600
INITIAL_FETCH_ATTEMPTS = 4
CONTINUATION_FETCH_ATTEMPTS = 2

# Duration suffixes accepted by --last (e.g. "6h", "1w"), in seconds.
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# Column widths (chars).
COL_RANK, COL_BLOCK, COL_GAS, COL_TXS = 4, 10, 14, 5
COL_TIME, COL_TIMESTAMP, COL_RATIO = 13, 19, 16
COL_ZKVM, COL_CLUSTER, COL_PROVER = 18, 32, 40
ABS_BLOCK, ABS_TARGET_TIME, ABS_CLOSEST_TIME, ABS_CLOSEST_ZKVM = range(4)
REL_BLOCK, REL_TARGET_TIME, REL_FASTEST_TIME, REL_FASTEST_ZKVM, REL_SLOWDOWN = range(5)

# Statistics available as proving-time metrics, keyed by their CLI name.
STATS = {"min": min, "max": max, "median": statistics.median, "avg": statistics.mean}


# --- Formatting -------------------------------------------------------------


def fmt_time(ms: float) -> str:
    """Format milliseconds as seconds."""
    return f"{ms / 1000:.2f}s"


def numeric_value(value) -> int | float | None:
    """Return a finite numeric value while rejecting bools and malformed JSON fields."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) else None


def fmt_gas(gas) -> str:
    """Format gas with thousands separators."""
    value = numeric_value(gas)
    return f"{value:,}" if value is not None else "N/A"


def fmt_timestamp(ts: str | None) -> str:
    """Format a timestamp as UTC without an offset."""
    parsed = parse_ts(ts)
    return parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else "N/A"


def parse_ts(ts: str | None) -> datetime | None:
    """Parse a block timestamp and normalize it to UTC."""
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        value = ts.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def value_or_na(value):
    """Preserve zero and other false-y values while formatting missing data."""
    return "N/A" if value is None else value


def print_table(columns: list[tuple[str, int, str]], rows: list[tuple]) -> None:
    """Print a markdown table.

    columns: (header, width, align) per column, align being '<' or '>'.
    rows:    row tuples whose cells line up positionally with columns.
    """
    def cell(value, width, align):
        text = str(value_or_na(value)).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
        if len(text) > width:
            text = text[: max(width - 1, 0)] + "…"
        return f"{text:{align}{width}}"

    print("| " + " | ".join(cell(h, w, a) for h, w, a in columns) + " |")
    print("|" + "|".join("-" * (w + 2) for _, w, _ in columns) + "|")
    for row in rows:
        print("| " + " | ".join(cell(v, w, a) for v, (_, w, a) in zip(row, columns)) + " |")


def comparison_time_columns(target_zkvm: str, relationship: str) -> list[tuple[str, int, str]]:
    """Consistent target/competitor columns for comparison tables."""
    return [
        (f"{target_zkvm} Time", COL_TIME, "<"),
        (f"{relationship} Other", COL_TIME, "<"),
        (f"{relationship} Prover", COL_PROVER, "<"),
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
    if not isinstance(cv, dict):
        return None, None, None, None
    cluster = cv.get("cluster") or {}
    zkvm_version = cv.get("zkvm_version") or {}
    if not isinstance(cluster, dict) or not isinstance(zkvm_version, dict):
        return None, None, None, None
    zkvm = zkvm_version.get("zkvm") or {}
    if not isinstance(zkvm, dict):
        zkvm = {}

    def text_or_none(value):
        return None if value is None else str(value)

    return (
        text_or_none(cluster.get("name")),
        text_or_none(zkvm.get("slug")),
        text_or_none(zkvm.get("name")),
        cluster.get("num_gpus"),
    )


def proof_zkvm_label(proof: dict) -> str:
    """Short label for the zkVM that produced a proof."""
    _, zkvm_slug, zkvm_name, _ = proof_prover_info(proof)
    return zkvm_slug or zkvm_name or "N/A"


def proof_prover_label(proof: dict) -> str:
    """Short zkVM/cluster label for a proof."""
    cluster_name, _, _, _ = proof_prover_info(proof)
    zkvm = proof_zkvm_label(proof)
    return f"{zkvm} / {cluster_name}" if cluster_name else zkvm


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


def proof_time(proof: dict) -> float | int | None:
    """Return a finite positive proving time, or None for pending/invalid records."""
    value = proof.get("proving_time")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) and value > 0 else None


def proving_times(proofs) -> list[float]:
    """Completed proving times (ms) from an iterable of proofs."""
    return [time for p in proofs if (time := proof_time(p)) is not None]


# --- Fetching / loading -----------------------------------------------------


class InvalidLastError(ValueError):
    """Raised when --last is not a finite positive duration or block count."""


def parse_last(spec: str) -> tuple[str, float]:
    """Parse a --last value into ('seconds', n) for durations or ('blocks', n) for counts.

    Durations end in a unit (s/m/h/d/w), e.g. '6h' or '1w'; a bare number means blocks.
    """
    try:
        spec = spec.strip().lower()
        if spec and spec[-1] in UNITS:
            amount = float(spec[:-1]) * UNITS[spec[-1]]
            if (
                not math.isfinite(amount)
                or amount <= 0
                or amount > timedelta.max.total_seconds()
            ):
                raise InvalidLastError
            return "seconds", amount
        amount = int(spec)
        if amount <= 0:
            raise InvalidLastError
        return "blocks", amount
    except (TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, InvalidLastError):
            raise
        raise InvalidLastError from exc


def positive_int_arg(value: str) -> int:
    """argparse type for strictly positive integers."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int_arg(value: str) -> int:
    """argparse type for nonnegative integers."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


class AnalyzerDataError(ValueError):
    """Raised when input or paginated API data cannot support a correct report."""


def data_rows(data: dict, source: str = "input") -> list[dict]:
    """Validate and return the top-level block rows."""
    if not isinstance(data, dict):
        raise AnalyzerDataError(f"{source} must be a JSON object")
    rows = data.get("rows", [])
    if rows is None or not isinstance(rows, list):
        raise AnalyzerDataError(f"{source} field 'rows' must be a list")
    if any(not isinstance(block, dict) for block in rows):
        raise AnalyzerDataError(f"{source} contains a non-object block row")
    return rows


def block_proofs(block: dict) -> list[dict]:
    """Return a block's proof objects, treating a null proof list as empty."""
    proofs = block.get("proofs", [])
    if proofs is None:
        proofs = []
    if not isinstance(proofs, list) or any(not isinstance(proof, dict) for proof in proofs):
        raise AnalyzerDataError("block field 'proofs' must be a list of objects or null")
    return proofs


class CacheEverything(hishel.BaseFilter):
    """Filter matching every request, regardless of request cache headers."""

    def needs_body(self) -> bool:
        return False

    def apply(self, item, body) -> bool:
        return True


class CacheSuccessfulResponses(hishel.BaseFilter):
    """Cache only successful responses so retries never replay a cached failure."""

    def needs_body(self) -> bool:
        return False

    def apply(self, item, body) -> bool:
        return 200 <= item.status_code < 300


def make_client(ttl: float) -> httpx.Client:
    """An HTTP client whose responses are cached on disk for ttl seconds (0 disables caching)."""
    if not ttl:
        return httpx.Client(timeout=30)
    os.makedirs(CACHE_DIR, exist_ok=True)
    storage = hishel.SyncSqliteStorage(
        database_path=os.path.join(CACHE_DIR, "pages.db"), default_ttl=ttl
    )
    policy = hishel.FilterPolicy(
        request_filters=[CacheEverything()], response_filters=[CacheSuccessfulResponses()]
    )
    return hishel.httpx.SyncCacheClient(storage=storage, policy=policy, timeout=30)


def is_transient(exc: BaseException) -> bool:
    """True for errors worth retrying: transport errors, rate limits, and 5xx responses."""
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code == 429 or exc.response.status_code >= 500
    return False


def fetch_blocks(client: httpx.Client, page_index: int, page_size: int, machine_type: str) -> dict:
    """Fetch one page of blocks, retrying transient errors with exponential backoff."""
    retryer = tenacity.Retrying(
        retry=tenacity.retry_if_exception(is_transient),
        wait=tenacity.wait_exponential(multiplier=0.5, max=5),
        stop=tenacity.stop_after_attempt(
            INITIAL_FETCH_ATTEMPTS if page_index == 0 else CONTINUATION_FETCH_ATTEMPTS
        ),
        reraise=True,
    )

    def request():
        response = client.get(
            API_URL,
            params={
                "page_index": page_index,
                "page_size": page_size,
                "machine_type": machine_type,
            },
        )
        response.raise_for_status()
        return response.json()

    return retryer(request)


def fetch_window(
    client: httpx.Client, mode: str, amount: float, page_size: int,
    machine_type: str, max_pages: int = 4000, now: datetime | None = None,
    require_complete: bool = False,
) -> dict:
    """Page through blocks (newest first) until the requested window is covered.

    mode='blocks' keeps the most recent `amount` blocks; mode='seconds' keeps blocks
    within `amount` seconds of the current wall clock. After at least one successful
    page, an HTTP failure returns the fetched prefix unless require_complete is true.
    """
    if mode not in ("blocks", "seconds") or amount <= 0 or page_size <= 0 or max_pages <= 0:
        raise ValueError("invalid fetch window parameters")

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cutoff = current_time - timedelta(seconds=amount) if mode == "seconds" else None
    rows: list[dict] = []
    seen_block_numbers = set()
    previous_block_number = None
    previous_timestamp = None
    duplicate_count = 0
    gap_count = 0
    unknown_timestamp_count = 0
    coverage_reached = False
    partial_reason = None
    page_count = 0
    total = int(amount)
    with Progress(console=Console(stderr=True), transient=True) as progress:
        task = progress.add_task("Fetching blocks", total=total)
        for page in range(max_pages):
            try:
                payload = fetch_blocks(client, page, page_size, machine_type)
            except KeyboardInterrupt:
                if not rows or require_complete:
                    raise
                partial_reason = f"fetch interrupted while requesting API page {page + 1}"
                break
            except httpx.HTTPError as exc:
                if not rows or require_complete:
                    raise
                if isinstance(exc, httpx.TimeoutException):
                    failure = "request timed out after retries"
                elif isinstance(exc, httpx.HTTPStatusError):
                    failure = f"HTTP {exc.response.status_code} after retries"
                else:
                    failure = f"{type(exc).__name__} after retries: {exc}"
                partial_reason = f"API page {page + 1} failed: {failure}"
                break
            try:
                page_rows = data_rows(payload, f"API page {page + 1}")
            except AnalyzerDataError as exc:
                if not rows or require_complete:
                    raise
                partial_reason = str(exc)
                break
            page_count += 1
            if not page_rows:
                break

            unique_page_rows = []
            page_problem = None
            for block in page_rows:
                raw_number = block.get("block_number")
                if raw_number is None:
                    page_problem = (
                        f"API page {page + 1} has a block without 'block_number'"
                    )
                    break
                try:
                    block_number = int(raw_number)
                except (TypeError, ValueError):
                    page_problem = (
                        f"API page {page + 1} has invalid block number {raw_number!r}"
                    )
                    break

                if block_number is not None and block_number in seen_block_numbers:
                    duplicate_count += 1
                    continue
                if block_number is not None:
                    if previous_block_number is not None:
                        if block_number >= previous_block_number:
                            page_problem = (
                                f"API pages are out of order near block {block_number}; "
                                "remaining pages were not used"
                            )
                            break
                        if block_number != previous_block_number - 1:
                            missing = previous_block_number - block_number - 1
                            if require_complete:
                                raise AnalyzerDataError(
                                    f"API pages have a block gap between "
                                    f"{previous_block_number} and {block_number}; "
                                    f"{missing:,} block numbers are missing"
                                )
                            gap_count += missing
                    seen_block_numbers.add(block_number)
                    previous_block_number = block_number

                timestamp = parse_ts(block.get("timestamp"))
                if timestamp is None:
                    unknown_timestamp_count += 1
                else:
                    if previous_timestamp is not None and timestamp > previous_timestamp:
                        page_problem = (
                            f"API timestamps are out of order near block {raw_number}; "
                            "remaining pages were not used"
                        )
                        break
                    previous_timestamp = timestamp
                unique_page_rows.append(block)

            if page_problem:
                if not rows or require_complete:
                    raise AnalyzerDataError(page_problem)
                partial_reason = page_problem
                break

            page_times = None
            if mode == "seconds":
                page_times = [
                    timestamp
                    for block in unique_page_rows
                    if (timestamp := parse_ts(block.get("timestamp"))) is not None
                ]
                if not page_times:
                    problem = (
                        f"API page {page + 1} has no valid timestamps; "
                        "remaining pages were not used"
                    )
                    if not rows or require_complete:
                        raise AnalyzerDataError(problem)
                    partial_reason = problem
                    break

            rows.extend(unique_page_rows)
            if mode == "blocks":
                progress.update(task, completed=min(len(rows), total))
                if len(rows) >= amount:
                    coverage_reached = True
                    break
            else:
                progress.update(
                    task,
                    completed=min(
                        max(int((current_time - min(page_times)).total_seconds()), 0),
                        total,
                    ),
                )
                if min(page_times) <= cutoff:
                    coverage_reached = True
                    break
            if len(page_rows) < page_size:
                break
        else:
            partial_reason = (
                f"reached the {max_pages:,}-page safety limit before covering the request"
            )

    if not coverage_reached:
        unit = "blocks" if mode == "blocks" else "seconds"
        incomplete = (
            f"API ended after {len(rows):,} unique blocks without covering the requested "
            f"{amount:g} {unit}"
        )
        partial_reason = partial_reason or incomplete
        if not rows or require_complete:
            raise AnalyzerDataError(partial_reason)
    if mode == "blocks":
        rows = rows[:total]
    else:
        rows = [
            block for block in rows
            if (timestamp := parse_ts(block.get("timestamp"))) is not None and timestamp >= cutoff
        ]
    details = []
    if duplicate_count:
        details.append(f"{duplicate_count:,} duplicate rows ignored")
    if gap_count:
        label = "block number" if gap_count == 1 else "block numbers"
        details.append(f"{gap_count:,} missing {label} observed")
    if unknown_timestamp_count:
        action = "excluded" if mode == "seconds" else "retained"
        details.append(f"{unknown_timestamp_count:,} rows with unknown timestamps {action}")
    if gap_count:
        gap_warning = (
            f"{gap_count:,} block number{' is' if gap_count == 1 else 's are'} "
            "missing between API pages"
        )
        partial_reason = f"{partial_reason}; {gap_warning}" if partial_reason else gap_warning
    suffix = f"; {', '.join(details)}" if details else ""
    print(f"  Fetched {len(rows):,} unique blocks ({page_count} pages{suffix})")
    result = {"rows": rows}
    if partial_reason:
        result["_partial_reason"] = partial_reason
    return result


def load_from_file(filepath: str) -> dict:
    """Load JSON data from a file."""
    with open(filepath, "r") as f:
        data = json.load(f)
    data_rows(data, filepath)
    return data


# --- Analyses ---------------------------------------------------------------


def list_provers(
    data: dict,
    cluster_filter: str | None = None,
    zkvm_filter: str | None = None,
) -> None:
    """Print distinct (zkvm, slug, cluster, num_gpus) combinations and their counts."""
    seen: dict[tuple, int] = {}
    for block in data_rows(data):
        for p in block_proofs(block):
            if not proof_matches(p, cluster_filter, zkvm_filter):
                continue
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
    show_block_rankings: bool = True,
) -> None:
    """Show range-wide proof stats plus legacy per-block rankings."""
    rows = data_rows(data)
    if not rows:
        print("No blocks found in the response.")
        return

    filter_active = bool(cluster_filter or zkvm_filter)

    # Select blocks (those with a matching proof, when a filter is active) and retain
    # completed proofs so extrema can identify their block and prover.
    selected = []  # (block, completed proofs)
    for block in rows:
        proofs = block_proofs(block)
        if filter_active:
            proofs = [p for p in proofs if proof_matches(p, cluster_filter, zkvm_filter)]
            if not proofs:
                continue
        selected.append(
            (block, [p for p in proofs if proof_time(p) is not None])
        )

    with_gas = [
        (block, gas)
        for block, _ in selected
        if (gas := numeric_value(block.get("gas_used"))) is not None
    ]
    timed_by_block = [(b, proofs) for b, proofs in selected if proofs]
    timed = [(b, p) for b, proofs in timed_by_block for p in proofs]
    all_times = [proof_time(p) for _, p in timed]
    timed_blocks = len(timed_by_block)
    total_proofs = len(all_times)

    if filter_active:
        parts = ([f"cluster~'{cluster_filter}'"] if cluster_filter else []) + (
            [f"zkvm~'{zkvm_filter}'"] if zkvm_filter else []
        )
        print(f"**Filter:** {', '.join(parts)}")
        print(f"Fetched {len(rows):,} blocks, {len(selected):,} match filter "
              f"({len(with_gas):,} with gas, {total_proofs:,} completed matching proofs)\n")
    else:
        print(f"Fetched {len(rows):,} blocks "
              f"({len(with_gas):,} with gas, {total_proofs:,} completed proofs)\n")

    if metric in ("all", "gas"):
        print(f"## Top {top_k} by Gas Used\n")
        if with_gas:
            top = sorted(with_gas, key=lambda bg: bg[1], reverse=True)[:top_k]
            print_table(
                [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"), ("Gas", COL_GAS, ">"),
                 ("Txs", COL_TXS, ">"), ("Timestamp", COL_TIMESTAMP, "<")],
                [(rank, value_or_na(b.get("block_number")), fmt_gas(gas),
                  value_or_na(b.get("transaction_count")), fmt_timestamp(b.get("timestamp")))
                 for rank, (b, gas) in enumerate(top, 1)],
            )
        else:
            print("No blocks with gas data found")

    time_metrics = [m for m in STATS if metric in ("all", m)]
    if time_metrics and not all_times:
        print("\nNo proofs with proving time data found")
        return

    if time_metrics:
        sample_label = f"{timed_blocks:,} blocks"
        if total_proofs != timed_blocks:
            sample_label += f", {total_proofs:,} proofs"
        print(f"\n## Proof-weighted Proving Time Across {sample_label}\n")
        print("Each completed proof is one sample.\n")

        extrema = {
            "min": min(timed, key=lambda bp: proof_time(bp[1])),
            "max": max(timed, key=lambda bp: proof_time(bp[1])),
        }
        show_source = any(name in extrema for name in time_metrics)
        summary_rows = []
        for name in time_metrics:
            summary = [name.upper(), fmt_time(STATS[name](all_times))]
            if show_source:
                if name in extrema:
                    block, proof = extrema[name]
                    cluster_name, _, _, _ = proof_prover_info(proof)
                    summary.extend([
                        value_or_na(block.get("block_number")),
                        proof_zkvm_label(proof),
                        cluster_name or "N/A",
                    ])
                else:
                    summary.extend(["N/A", "N/A", "N/A"])
            summary_rows.append(tuple(summary))

        columns = [("Metric", 8, "<"), ("Time", COL_TIME, "<")]
        if show_source:
            columns.extend([
                ("Block", COL_BLOCK, "<"),
                ("zkVM", COL_ZKVM, "<"),
                ("Cluster", COL_CLUSTER, "<"),
            ])
        print_table(
            columns,
            summary_rows,
        )

    if show_block_rankings:
        for name in time_metrics:
            stat = STATS[name]
            top = sorted(
                timed_by_block,
                key=lambda bp: stat(proving_times(bp[1])),
                reverse=True,
            )[:top_k]
            print(f"\n## Top {top_k} Blocks by Per-block {name.upper()} Proving Time\n")
            print_table(
                [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"),
                 (f"Time ({name})", COL_TIME, "<"), ("Gas", COL_GAS, ">"),
                 ("Txs", COL_TXS, ">")],
                [
                    (
                        rank,
                        value_or_na(block.get("block_number")),
                        fmt_time(stat(proving_times(proofs))),
                        fmt_gas(block.get("gas_used")),
                        value_or_na(block.get("transaction_count")),
                    )
                    for rank, (block, proofs) in enumerate(top, 1)
                ],
            )


def analyze_comparison(
    data: dict,
    top_k: int = 10,
    target_zkvm: str = "openvm2",
    target_cluster: str | None = None,
) -> None:
    """Compare the target prover (default OpenVM 2.0) with other completed proofs.

    Two tables:
      1. ABSOLUTE  - blocks where the target's own proving time was highest,
                     alongside the closest other completed proof.
      2. RELATIVE  - blocks with the largest target-time / fastest-other-time ratio.
      When several target proofs match a block, the fastest target proof is used.
    """
    rows = data_rows(data)
    if not rows:
        print("No blocks found in the response.")
        return

    absolute = []  # (block, target_time, closest_other_time, closest_other_zkvm)
    relative = []  # (block, target_time, fastest_other_time, fastest_other_zkvm, ratio)
    for block in rows:
        proofs = block_proofs(block)
        target = proving_times(p for p in proofs if proof_matches(p, target_cluster, target_zkvm))
        others = [
            p for p in proofs
            if not proof_matches(p, target_cluster, target_zkvm)
            and proof_time(p) is not None
        ]
        if not target:
            continue
        t = min(target)  # target's fastest completed proof for this block
        if others:
            closest = min(others, key=lambda p: abs(proof_time(p) - t))
            absolute.append((block, t, proof_time(closest), proof_prover_label(closest)))
            fastest = min(others, key=lambda p: proof_time(p))
            fastest_time = proof_time(fastest)
            relative.append((block, t, fastest_time, proof_prover_label(fastest), t / fastest_time))
        else:
            absolute.append((block, t, None, None))

    label = target_zkvm + (f" / {target_cluster}" if target_cluster else " / any cluster")
    print(f"**Target prover:** {label}")
    print(f"Fetched {len(rows):,} blocks, {len(absolute):,} with a completed {target_zkvm} "
          f"proof, {len(relative):,} comparable to other provers\n")

    if not absolute:
        print(f"No completed proofs found for {target_zkvm}.")
        return

    top_abs = sorted(absolute, key=lambda x: x[ABS_TARGET_TIME], reverse=True)[:top_k]
    print(f"## Top {top_k} {target_zkvm} Blocks by Absolute Proving Time\n")
    print_table(
        [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"),
         *comparison_time_columns(target_zkvm, "Closest"),
         ("Gas", COL_GAS, ">"), ("Txs", COL_TXS, ">")],
        [(rank, value_or_na(b.get("block_number")),
          *comparison_time_cells(t, closest_time, closest_zkvm),
          fmt_gas(b.get("gas_used")), value_or_na(b.get("transaction_count")))
         for rank, (b, t, closest_time, closest_zkvm) in enumerate(top_abs, 1)],
    )

    if not relative:
        print(f"\nNo blocks have both a {target_zkvm} proof and another prover to compare.")
        return

    top_rel = sorted(relative, key=lambda x: x[REL_SLOWDOWN], reverse=True)[:top_k]
    print(f"\n## Top {top_k} Blocks by {target_zkvm} / FASTEST Other Prover\n")
    print_table(
        [("Rank", COL_RANK, ">"), ("Block", COL_BLOCK, "<"),
         *comparison_time_columns(target_zkvm, "Fastest"),
         ("Target / Fastest", COL_RATIO, ">")],
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
    ttl = 0 if args.no_cache else (
        CACHE_TTL if args.cache_ttl is None else args.cache_ttl
    )
    print(f"**Source:** {API_URL}  ")
    print(f"**Config:** last {args.last}, filter={args.machine_type}"
          f"{f', cache TTL={ttl}s' if ttl else ', cache off'}\n")
    with make_client(ttl) as client:
        data = fetch_window(
            client,
            mode,
            amount,
            args.size,
            args.machine_type,
            require_complete=args.require_complete,
        )
    timestamps = [
        timestamp
        for block in data_rows(data)
        if (timestamp := parse_ts(block.get("timestamp"))) is not None
    ]
    if timestamps:
        print(
            f"  Window: {min(timestamps):%Y-%m-%d %H:%M:%S} to "
            f"{max(timestamps):%Y-%m-%d %H:%M:%S} UTC"
        )
    else:
        print("  Window: no timestamped blocks in the requested range")
    if partial_reason := data.get("_partial_reason"):
        print(f"\n**WARNING: PARTIAL RESULTS:** {partial_reason}")
        print("Statistics below cover only the successfully fetched UTC window.")
    print()
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Analyze ethproofs.org block data: top blocks by gas, proving-time "
        "statistics across the selected range, and target-vs-fastest comparisons.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --last 2h --metric all --zkvm openvm2
  %(prog)s --last 1w --metric min
  %(prog)s --last 1d --compare --compare-zkvm openvm2 --top-k 20
""",
    )
    parser.add_argument("--last", "-l", default="100",
                        help="How much recent data to fetch: a duration (6h, 1d, 1w) or a "
                        "block count (500). Default: 100")
    parser.add_argument("--file", "-f", type=str,
                        help="Load data from a JSON file instead of fetching")
    parser.add_argument("--machine-type", "-m", default="multi", choices=["multi", "single"],
                        help="Machine type filter (default: multi)")
    parser.add_argument("--size", "-s", type=positive_int_arg, default=1000,
                        help="Blocks per API request, a fetch-tuning knob (default: 1000)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass the local page cache and always hit the API")
    parser.add_argument("--cache-ttl", type=nonnegative_int_arg, default=None,
                        help=f"Cache successful API pages for this many seconds "
                        f"(default: {CACHE_TTL})")
    parser.add_argument("--require-complete", action="store_true",
                        help="Fail if the API cannot cover the full requested window")
    parser.add_argument("--top-k", "-k", type=positive_int_arg, default=None,
                        help="Top gas, per-block time, or comparison rows to show "
                        "(default: 1, or 10 with --compare)")
    parser.add_argument("--metric", default="all", choices=["all", "gas", *STATS],
                        help="Which metric to show (default: all)")
    parser.add_argument("--cluster", default=None,
                        help="Filter to proofs whose cluster name contains this text, e.g. 'axiom'")
    parser.add_argument("--zkvm", default=None,
                        help="Filter to proofs whose zkvm slug/name contains this text, e.g. 'openvm2'")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--list-provers", action="store_true",
                            help="List distinct provers seen in the fetched data and exit")
    mode_group.add_argument("--compare", action="store_true",
                            help="Compare a target prover with the fastest other prover")
    parser.add_argument("--compare-zkvm", default=None,
                        help="zkvm slug/name of the prover to compare in --compare mode (default: openvm2)")
    parser.add_argument("--compare-cluster", default=None,
                        help="Optional cluster substring to further pin the --compare target (e.g. 'axiom')")
    parser.add_argument("--no-block-rankings", action="store_true",
                        help="With --top-k, omit legacy per-block time rankings")

    args = parser.parse_args()
    if args.no_cache and args.cache_ttl is not None:
        parser.error("--no-cache cannot be combined with --cache-ttl")
    if args.compare:
        if args.metric != "all" or args.cluster or args.zkvm:
            parser.error(
                "--compare cannot be combined with --metric, --cluster, or --zkvm; "
                "use --compare-zkvm/--compare-cluster"
            )
        if args.no_block_rankings:
            parser.error("--no-block-rankings is not used with --compare")
    elif args.compare_cluster is not None or args.compare_zkvm is not None:
        parser.error("--compare-zkvm and --compare-cluster require --compare")
    if args.list_provers:
        if args.metric != "all" or args.top_k is not None:
            parser.error("--list-provers cannot be combined with --metric or --top-k")
        if args.no_block_rankings:
            parser.error("--no-block-rankings is not used with --list-provers")

    top_k_explicit = args.top_k is not None
    top_k = args.top_k if top_k_explicit else (10 if args.compare else 1)

    def report(data):
        if args.list_provers:
            list_provers(data, args.cluster, args.zkvm)
        elif args.compare:
            analyze_comparison(
                data,
                top_k,
                args.compare_zkvm or "openvm2",
                args.compare_cluster,
            )
        else:
            analyze_blocks(
                data,
                top_k,
                args.metric,
                args.cluster,
                args.zkvm,
                show_block_rankings=top_k_explicit and not args.no_block_rankings,
            )

    print("\n# ETHPROOFS ANALYZER\n")

    data = None
    try:
        data = load_data(args)
        report(data)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        sys.exit(1)
    except AnalyzerDataError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except InvalidLastError:
        print(f"Error: invalid --last value '{args.last}' (use e.g. 500, 6h, 1d, 1w)")
        sys.exit(1)
    except (OSError, UnicodeError) as e:
        print(f"Error reading {args.file or 'data'}: {e}")
        sys.exit(1)
    except httpx.HTTPError as e:
        print(f"\nError fetching data: {e}")
        print("Try again, lower --size, or use: ./scripts/ethproofs_analyzer.py --file data.json")
        sys.exit(1)
    except KeyboardInterrupt:
        if data is None:
            print("\nCancelled before any usable API pages were fetched.")
            sys.exit(130)
        print("\nFetch stopped; reporting the usable pages collected so far.\n")
        report(data)


if __name__ == "__main__":
    main()
