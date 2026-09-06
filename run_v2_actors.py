"""Actor-only driver for the pair-expansion round: cleanup + run_adaptive_actors.
Fast-forwards the 12 frozen pairs (resume-skip) and runs only the new ones. Docker-heavy;
benign corpus is intentionally NOT re-run (310 sessions already suffice for the FPR floor)."""
import subprocess, sys, time, traceback
sys.path.insert(0, "src")
CFG = "configs/adaptive.yaml"

def cleanup_leaked_docker():
    sh = r'''
      for p in $(docker ps -a --format "{{.Names}}" | grep -oE "cd(lunary|gradio)[a-f0-9]+" | sort -u); do
        docker rm -f $(docker ps -aq --filter "name=$p") 2>/dev/null
        docker network ls --format "{{.Name}}" | grep "$p" | xargs -r docker network rm 2>/dev/null
        docker volume ls --format "{{.Name}}" | grep "$p" | xargs -r docker volume rm 2>/dev/null
      done
      docker builder prune -af >/dev/null 2>&1 || true
      echo "leaked stacks remaining: $(docker ps -aq --filter name=cdlunary | wc -l)"'''
    try:
        print(subprocess.run(["bash","-c",sh],capture_output=True,text=True,timeout=120).stdout.strip(), flush=True)
    except Exception as e:
        print(f"cleanup skipped: {e}", flush=True)

def main():
    print(f"=== [{time.strftime('%H:%M:%S')}] cleanup ===", flush=True)
    cleanup_leaked_docker()
    from cyberdetect.actor.adaptive_runner import run_adaptive_actors
    print(f"=== [{time.strftime('%H:%M:%S')}] START actors (24 pairs; 12 frozen skip, 12 new) ===", flush=True)
    t0=time.time()
    try:
        out = run_adaptive_actors(CFG)
        print(f"=== [{time.strftime('%H:%M:%S')}] DONE actors -> {len(out)} arms ({time.time()-t0:.0f}s) ===", flush=True)
    except Exception:
        print(f"=== [{time.strftime('%H:%M:%S')}] FAILED actors after {time.time()-t0:.0f}s ===", flush=True)
        traceback.print_exc(); raise

if __name__ == "__main__":
    main()
