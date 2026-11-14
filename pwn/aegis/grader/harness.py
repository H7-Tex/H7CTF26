#!/usr/bin/env python3
# Local grader/validator for Aegis Gateway. Runs inside ubuntu:24.04 (glibc 2.39).
# For one release binary + one submitted exploit: spin the target under socat with a fresh
# per-run flag, run the exploit (which must connect and print the recovered flag), compare.
# This mirrors the judge contract (relative-grading-judge.md section 7): a single run emits
# {"pass": bool, "raw": {...}}; run N times for reliability; the runner picks the deepest
# release cleared >= threshold.
import argparse, json, os, random, socket, string, subprocess, sys, time, signal

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def rand_flag():
    return "H7CTF{" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(24)) + "}"

def one_run(binary, exploit, seed, run_index, timeout=25):
    port = free_port()
    workdir = f"/tmp/aegis_run_{port}"
    os.makedirs(workdir, exist_ok=True)
    flag = rand_flag()
    with open(os.path.join(workdir, "flag"), "w") as f:
        f.write(flag + "\n")
    binabs = os.path.abspath(binary)
    # serve the target: socat forks a fresh process per connection, cwd = workdir (holds ./flag)
    socat = subprocess.Popen(
        ["socat", f"TCP-LISTEN:{port},reuseaddr,fork,bind=127.0.0.1", f"EXEC:{binabs},stderr"],
        cwd=workdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    passed = False
    detail = ""
    try:
        env = dict(os.environ, TARGET_HOST="127.0.0.1", TARGET_PORT=str(port),
                   SEED=str(seed), RUN_INDEX=str(run_index))
        out = subprocess.run([sys.executable, os.path.abspath(exploit)],
                             capture_output=True, timeout=timeout, env=env, cwd=workdir)
        stdout = out.stdout.decode(errors="replace")
        passed = flag in stdout
        detail = stdout.strip().splitlines()[-1][:120] if stdout.strip() else out.stderr.decode(errors="replace")[-120:]
    except subprocess.TimeoutExpired:
        detail = "exploit timed out"
    finally:
        socat.send_signal(signal.SIGTERM)
        try: socat.wait(timeout=3)
        except Exception: socat.kill()
        subprocess.run(["rm", "-rf", workdir])
    return passed, detail

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--exploit", required=True)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--threshold", type=int, default=8)
    a = ap.parse_args()
    ok = 0
    for i in range(a.runs):
        p, d = one_run(a.bin, a.exploit, seed=random.randrange(1 << 30), run_index=i + 1)
        ok += p
        print(f"  run {i+1:2d}/{a.runs}: {'PASS' if p else 'fail'}  {d}")
    verdict = "CLEARED" if ok >= a.threshold else "not cleared"
    print(json.dumps({"binary": os.path.basename(a.bin), "reliable_runs": ok, "runs": a.runs,
                      "threshold": a.threshold, "cleared": ok >= a.threshold}))
    print(f"== {os.path.basename(a.bin)}: {ok}/{a.runs} -> {verdict} ==")

if __name__ == "__main__":
    main()
