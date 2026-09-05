from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .actor.runner import run_mock_actors
from .actor.real_runner import run_real_actors
from .analysis.report import analyze
from .analysis.pilot import pilot_gate
from .baselines.rules import run_baselines
from .models import get_model
from .config import data_root, load_config
from .defender.runner import run_mock_defenders
from .defender.real_runner import run_real_defenders
from .doctor import global_doctor, lunary_target_doctor, toy_target_doctor
from .freeze import create_lock
from .scenarios import generate_scenarios
from .status import experiment_status
from .telemetry.leakage import audit_packets
from .utils import project_root
from .visualization.timeline import render_timeline


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _config_from_lock(lock_path: str | Path) -> str:
    lock = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    return str(lock["config_path"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberdetect")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor")

    target = subparsers.add_parser("target")
    target_sub = target.add_subparsers(dest="target_command", required=True)
    target_doctor = target_sub.add_parser("doctor")
    target_doctor.add_argument("--target", required=True)
    target_build = target_sub.add_parser("build")
    target_build.add_argument("--target", required=True)

    scenarios = subparsers.add_parser("scenarios")
    scenarios_sub = scenarios.add_subparsers(dest="scenarios_command", required=True)
    scenarios_generate = scenarios_sub.add_parser("generate")
    scenarios_generate.add_argument("--config", required=True)

    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--config", required=True)
    freeze.add_argument("--output", default="experiment.lock.json")

    run = subparsers.add_parser("run")
    run_sub = run.add_subparsers(dest="run_command", required=True)
    for name in ("actors", "defenders", "baselines"):
        command = run_sub.add_parser(name)
        command.add_argument("--lock", default="experiment.lock.json")
        command.add_argument("--config", default=None, help="Run directly from a config instead of a freeze lock (pilot use).")

    pilot = subparsers.add_parser("pilot")
    pilot_sub = pilot.add_subparsers(dest="pilot_command", required=True)
    pilot_report = pilot_sub.add_parser("report")
    pilot_report.add_argument("--config", default="configs/pilot_real.yaml")

    audit = subparsers.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    leakage = audit_sub.add_parser("leakage")
    leakage.add_argument("--lock", default="experiment.lock.json")

    analysis = subparsers.add_parser("analyze")
    analysis.add_argument("--lock", default="experiment.lock.json")

    visual = subparsers.add_parser("visualize")
    visual.add_argument("--episode", required=True)
    visual.add_argument("--config", default="configs/pilot.yaml")

    status = subparsers.add_parser("status")
    status.add_argument("--lock", default="experiment.lock.json")

    phase0 = subparsers.add_parser("phase0")
    phase0.add_argument("--config", default="configs/pilot.yaml")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = project_root()
    try:
        if args.command == "doctor":
            result = global_doctor(root)
            _print(result)
            return 1 if result["overall"] == "fail" else 0

        if args.command == "target":
            if args.target_command == "build":
                if args.target == "toy_idor":
                    _print({"target": args.target, "status": "in_process_target_requires_no_build"})
                    return 0
                if args.target == "lunary_idor":
                    from .environment.targets.lunary import build_target

                    _print(build_target(root))
                    return 0
                raise RuntimeError(f"unknown target: {args.target}")
            if args.target == "toy_idor":
                result = toy_target_doctor()
            elif args.target == "lunary_idor":
                result = lunary_target_doctor(root)
            else:
                raise RuntimeError(f"unknown target: {args.target}")
            _print(result)
            return 0 if result["overall"] == "pass" else 1

        if args.command == "scenarios":
            paths = generate_scenarios(args.config)
            _print({"created": [str(path.relative_to(root)) for path in paths]})
            return 0

        if args.command == "freeze":
            path = create_lock(args.config, args.output)
            _print({"lock": str(path.relative_to(root))})
            return 0

        if args.command == "run":
            config_path = args.config if getattr(args, "config", None) else _config_from_lock(args.lock)
            config, _, _ = load_config(config_path)
            if args.run_command == "actors":
                actor_is_mock = get_model(config.actor_model).provider == "mock"
                episodes = run_mock_actors(config_path) if actor_is_mock else run_real_actors(config_path)
                _print({"mode": "mock" if actor_is_mock else "real", "episodes": episodes})
            elif args.run_command == "defenders":
                defenders_mock = all(get_model(d).provider == "mock" for d in config.defender_models)
                runner = run_mock_defenders if defenders_mock else run_real_defenders
                _print(
                    {
                        "mode": "mock" if defenders_mock else "real",
                        "predictions": [str(path.relative_to(root)) for path in runner(config_path)],
                    }
                )
            else:
                _print({"predictions": [str(path.relative_to(root)) for path in run_baselines(config_path)]})
            return 0

        if args.command == "pilot":
            _print(pilot_gate(args.config))
            return 0

        if args.command == "audit":
            config_path = _config_from_lock(args.lock)
            findings = audit_packets(config_path)
            _print({"passed": not findings, "findings": [finding.__dict__ for finding in findings]})
            return 0 if not findings else 1

        if args.command == "analyze":
            config_path = _config_from_lock(args.lock)
            metrics, report = analyze(config_path)
            _print({"metrics": str(metrics.relative_to(root)), "report": str(report.relative_to(root))})
            return 0

        if args.command == "visualize":
            config, _, config_root = load_config(args.config)
            path = render_timeline(data_root(config, config_root), args.episode)
            _print({"timeline": str(path.relative_to(root))})
            return 0

        if args.command == "status":
            config_path = _config_from_lock(args.lock)
            _print(experiment_status(config_path))
            return 0

        if args.command == "phase0":
            doctor = global_doctor(root)
            if doctor["overall"] == "fail":
                _print(doctor)
                return 1
            target = toy_target_doctor()
            if target["overall"] != "pass":
                _print(target)
                return 1
            generated = generate_scenarios(args.config)
            lock = create_lock(args.config)
            episodes = run_mock_actors(args.config)
            findings = audit_packets(args.config)
            if findings:
                _print({"leakage_findings": [finding.__dict__ for finding in findings]})
                return 1
            predictions = run_mock_defenders(args.config)
            baselines = run_baselines(args.config)
            metrics, report = analyze(args.config)
            attack_episode = next(
                episode
                for episode in episodes
                if json.loads((data_root(load_config(args.config)[0], root) / "episodes" / episode / "ground_truth.json").read_text(encoding="utf-8"))["observable_attack"]
            )
            timeline = render_timeline(data_root(load_config(args.config)[0], root), attack_episode)
            _print(
                {
                    "phase0": "pass",
                    "doctor": doctor,
                    "target_doctor": target["overall"],
                    "scenarios_created": len(generated),
                    "lock": str(lock.relative_to(root)),
                    "episodes": episodes,
                    "defender_predictions": len(predictions),
                    "baseline_predictions": len(baselines),
                    "leakage_findings": 0,
                    "metrics": str(metrics.relative_to(root)),
                    "report": str(report.relative_to(root)),
                    "timeline": str(timeline.relative_to(root)),
                }
            )
            return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
