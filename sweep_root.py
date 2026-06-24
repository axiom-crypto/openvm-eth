import json
import subprocess
import os


def find_total_prove_time(metrics):
    for record in metrics["gauge"]:
        if record["metric"] == "total_proof_time_ms" and any(
            l[0] == "group" and l[1] == "root" for l in record["labels"]
        ):
            return int(record["value"])
    return None


with open("root_params.json", "r") as f:
    params = json.load(f)

env = os.environ.copy()
metric_param_results = []
failed = []

if os.path.exists("root_sweep_results.json"):
    with open("root_sweep_results.json", "r") as f:
        metric_param_results = json.load(f)
if os.path.exists("failed_params.json"):
    with open("failed_params.json", "r") as f:
        failed = json.load(f)

log_file = open("root_sweep_log.txt", "w")


def fail(p):
    failed.append(p)
    print(f"failed {p}")
    with open("failed_params.json", "w") as f:
        json.dump(failed, f)


try:
    for p in params:
        if p in metric_param_results or p in failed:
            print(f"skipping {p}")
        env["OVERRIDE_ROOT_PARAMS"] = json.dumps(p)

        try:
            code = subprocess.call(
                [
                    "./run.sh",
                    "--block",
                    "21345144",
                    "--perf",
                    "--mode",
                    "prove-root",
                    "--tco",
                    "--proof-cache",
                    "output",
                ],
                env=env,
                stdout=log_file,
                stderr=log_file,
                timeout=150,
            )
        except subprocess.TimeoutExpired:
            print(f"timed out {p}")
            fail(p)
            continue
        if code == 0:
            with open("metrics.json", "r") as f:
                metrics = json.load(f)
            os.remove("metrics.json")
            metric_param_results.append(metrics)
            with open("root_sweep_results.json", "w") as f:
                json.dump(metric_param_results, f)
            ms = find_total_prove_time(metrics)
            print(f"param:\n{p}\nroot_time: {ms}")
        else:
            fail(p)
finally:
    log_file.close()
