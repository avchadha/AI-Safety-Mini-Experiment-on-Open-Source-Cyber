"""Driver: full v2 adaptive/base-rate study, 4 stages, resumable & logged."""
import sys, time, traceback
sys.path.insert(0, "src")

CFG = "configs/adaptive.yaml"

def banner(msg):
    print(f"\n{'='*70}\n[{time.strftime('%H:%M:%S')}] {msg}\n{'='*70}", flush=True)

def stage(name, fn):
    banner(f"START {name}")
    t0 = time.time()
    try:
        out = fn()
        n = len(out) if hasattr(out, "__len__") else out
        print(f"[{time.strftime('%H:%M:%S')}] DONE {name} -> {n} ({time.time()-t0:.0f}s)", flush=True)
        return out
    except Exception:
        print(f"[{time.strftime('%H:%M:%S')}] FAILED {name} after {time.time()-t0:.0f}s", flush=True)
        traceback.print_exc()
        raise

def cleanup_leaked_docker():
    """Remove any leaked cyberdetect container stacks left by a previously killed run, so
    relaunch-after-OOM does not accumulate stacks and bloat the Docker VM. Safe at startup:
    no run is in flight, so any cd* stack is orphaned."""
    import subprocess
    banner("cleanup leaked docker stacks")
    sh = r'''
      for p in $(docker ps -a --format "{{.Names}}" | grep -oE "cd(lunary|gradio)[a-f0-9]+" | sort -u); do
        docker rm -f $(docker ps -aq --filter "name=$p") 2>/dev/null
        docker network ls --format "{{.Name}}" | grep "$p" | xargs -r docker network rm 2>/dev/null
        docker volume ls --format "{{.Name}}" | grep "$p" | xargs -r docker volume rm 2>/dev/null
      done
      docker builder prune -af >/dev/null 2>&1 || true
      echo "leaked stacks remaining: $(docker ps -aq --filter name=cdlunary | wc -l)"'''
    try:
        out = subprocess.run(["bash", "-c", sh], capture_output=True, text=True, timeout=120)
        print(out.stdout.strip() or "(nothing to clean)", flush=True)
    except Exception as e:
        print(f"cleanup skipped: {e}", flush=True)


def main():
    cleanup_leaked_docker()
    from cyberdetect.actor.adaptive_runner import run_adaptive_actors
    from cyberdetect.environment.benign import generate_benign_corpus
    from cyberdetect.defender.real_runner import run_real_defenders
    from cyberdetect.analysis.adaptive import analyze_adaptive

    stage("1/4 adaptive actors (self-red-team, Kimi, ~slow)", lambda: run_adaptive_actors(CFG))
    stage("2/4 benign corpus (scripted, 250 sessions)",       lambda: generate_benign_corpus(CFG))
    stage("3/4 defenders (4 tiers over all arms+benign)",     lambda: run_real_defenders(CFG))
    mpath, rpath = stage("4/4 analyze",                        lambda: analyze_adaptive(CFG))
    banner(f"ALL DONE. metrics={mpath} report={rpath}")

if __name__ == "__main__":
    main()
