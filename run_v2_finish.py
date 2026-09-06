"""Finisher: Stage 3 (defenders) + Stage 4 (analysis). Docker-free — safe to run with the
Docker Desktop VM stopped, which frees host memory. Resumable (defender backfill is idempotent)."""
import sys, time, traceback
sys.path.insert(0, "src")
CFG = "configs/adaptive.yaml"

def stage(name, fn):
    print(f"\n=== [{time.strftime('%H:%M:%S')}] {name} ===", flush=True)
    t0 = time.time()
    try:
        out = fn(); n = len(out) if hasattr(out, "__len__") else out
        print(f"[{time.strftime('%H:%M:%S')}] DONE {name} -> {n} ({time.time()-t0:.0f}s)", flush=True)
        return out
    except Exception:
        print(f"[{time.strftime('%H:%M:%S')}] FAILED {name} after {time.time()-t0:.0f}s", flush=True)
        traceback.print_exc(); raise

def main():
    from cyberdetect.defender.real_runner import run_real_defenders
    from cyberdetect.analysis.adaptive import analyze_adaptive
    stage("3/4 defenders (4 tiers, backfill)", lambda: run_real_defenders(CFG))
    mpath, rpath = stage("4/4 analyze", lambda: analyze_adaptive(CFG))
    print(f"\n=== ALL DONE. metrics={mpath} report={rpath} ===", flush=True)

if __name__ == "__main__":
    main()
