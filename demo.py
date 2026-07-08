"""
Entry point. Runs one fixed traffic scenario against two policy versions and
writes, for each: the generated routing config and an audit record.

The same input produces different output under each policy, because the context
differed. That delta, and the two audit records that pin it to a policy hash, is
the demonstration.

    python demo.py                  deterministic simulation (default, free)
    python demo.py --live           also generate config with a real model
    python demo.py --adversarial    also run a prompt-injection traffic scenario
    python demo.py --live --adversarial

Deterministic mode is the reproducible baseline and needs no API access. Live
mode places the policy in a real model's context window and validates the model's
output against the deterministic floor; it requires an Anthropic API credential
and is billed to your account. Without one, live mode is skipped cleanly.
"""

import argparse
import json
import os

import yaml

from agent import PolicyAgent, load_policy_context
from agent.policy_agent import ADVERSARIAL_SCENARIO, TRAFFIC_SCENARIO
from agent.report import build_markdown_report
from agent import live_agent

ROOT = os.path.dirname(os.path.abspath(__file__))

POLICY_FILES = [
    ("v1-permissive", os.path.join(ROOT, "policies", "v1-permissive", "network-policy.yaml")),
    ("v2-hardened", os.path.join(ROOT, "policies", "v2-hardened", "network-policy.yaml")),
]

# The adversarial scenario is run against the hardened policy only. That is where
# rejecting an unknown tenant is the interesting behaviour to test.
V2 = POLICY_FILES[1]


def _write_yaml(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, default_flow_style=False)


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def _audit_name(version: str, run_id: str, label: str = "", live: bool = False) -> str:
    parts = [version]
    if label:
        parts.append(label)
    if live:
        parts.append("live")
    parts.append(run_id[:8])
    return "-".join(parts) + ".json"


def run_deterministic(version, policy_path, scenario, config_filename, label=""):
    """Load the policy as context, generate config, write config plus audit."""
    context = load_policy_context(policy_path)
    agent = PolicyAgent(context)
    result = agent.generate(scenario)

    config_path = os.path.join(ROOT, "configs", version, config_filename)
    audit_path = os.path.join(ROOT, "audit", _audit_name(version, result.audit["run_id"], label))

    result.audit["output_config_path"] = os.path.relpath(config_path, ROOT)
    result.audit["policy_path"] = os.path.relpath(policy_path, ROOT)

    _write_yaml(config_path, result.config)
    _write_json(audit_path, result.audit)

    return {
        "version": version,
        "context": context,
        "config": result.config,
        "config_path": config_path,
        "audit": result.audit,
        "audit_path": audit_path,
        "audit_rel_path": os.path.relpath(audit_path, ROOT),
        "redactions": result.redactions_made,
    }


def run_live(det_run, policy_path, scenario, config_filename, label=""):
    """Generate the same config with a real model, validate, write config + audit.

    Returns a live run dict, or None if live generation is unavailable (no SDK,
    no credential, or a request error). The deterministic run always stands.
    """
    context = det_run["context"]
    try:
        result = live_agent.generate_live(
            context, scenario, det_run["config"], det_run["redactions"]
        )
    except live_agent.LiveUnavailable as exc:
        print("  [live skipped] {0}".format(exc))
        return None

    config_path = os.path.join(ROOT, "configs", det_run["version"], config_filename)
    audit_path = os.path.join(
        ROOT, "audit", _audit_name(det_run["version"], result.audit["run_id"], label, live=True)
    )

    result.audit["output_config_path"] = os.path.relpath(config_path, ROOT)
    result.audit["policy_path"] = os.path.relpath(policy_path, ROOT)

    _write_yaml(config_path, result.config)
    _write_json(audit_path, result.audit)

    return {
        "version": det_run["version"],
        "context": context,
        "config": result.config,
        "config_path": config_path,
        "audit": result.audit,
        "audit_path": audit_path,
        "audit_rel_path": os.path.relpath(audit_path, ROOT),
    }


def _print_run(run: dict) -> None:
    print("=" * 72)
    print("POLICY VERSION: {0}".format(run["version"]))
    print("POLICY HASH:    {0}".format(run["context"].sha256))
    print("-" * 72)
    print("GENERATED CONFIG  ({0})".format(os.path.relpath(run["config_path"], ROOT)))
    print("-" * 72)
    print(yaml.safe_dump(run["config"], sort_keys=False, default_flow_style=False).rstrip())
    print("-" * 72)
    print("AUDIT RECORD  ({0})".format(os.path.relpath(run["audit_path"], ROOT)))
    print("-" * 72)
    print(json.dumps(run["audit"], indent=2))
    print()


def _print_live_run(run: dict) -> None:
    audit = run["audit"]
    validation = audit["validation"]
    print("=" * 72)
    print("LIVE GENERATION: {0}  (model: {1})".format(run["version"], audit["model"]))
    print("POLICY HASH:     {0}".format(run["context"].sha256))
    print("-" * 72)
    print("GENERATED CONFIG  ({0})".format(os.path.relpath(run["config_path"], ROOT)))
    print("-" * 72)
    print(yaml.safe_dump(run["config"], sort_keys=False, default_flow_style=False).rstrip())
    print("-" * 72)
    if validation["agrees_with_deterministic"]:
        print("VALIDATION: live output agrees with the deterministic floor on every decision.")
    else:
        print("VALIDATION: live output DIVERGED from the deterministic floor:")
        for m in validation["mismatches"]:
            if "tenant" in m:
                print("  - {0}: deterministic={1}  live={2}".format(
                    m["tenant"], m["deterministic"], m["live"]))
            else:
                print("  - {0}: deterministic={1}  live={2}".format(
                    m["field"], m["deterministic"], m["live"]))
    print("AUDIT RECORD  ({0})".format(os.path.relpath(run["audit_path"], ROOT)))
    print()


def _print_delta(v1, v2) -> None:
    print("=" * 72)
    print("THE DELTA")
    print("=" * 72)
    print("Same scenario. Same agent. Different policy in the context window.")
    print()
    for run in (v1, v2):
        print("  {0}  hash {1}".format(run["version"], run["context"].sha256[:16]))
        print("    rules_applied:   {0}".format(", ".join(run["audit"]["rules_applied"])))
        print("    redactions_made: {0}".format(run["audit"]["redactions_made"]))
        print("    rejected:        {0}".format(run["audit"]["rejected_tenants"] or "none"))
        print()
    print("The output differed because the context differed. The audit records")
    print("prove which policy each run was shown, by hash, at generation time.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Policy as Context demo.")
    parser.add_argument("--live", action="store_true",
                        help="also generate config with a real model (needs an API credential; billed)")
    parser.add_argument("--adversarial", action="store_true",
                        help="also run a prompt-injection traffic scenario against the hardened policy")
    args = parser.parse_args()

    print("Policy as Context: same traffic scenario, two policy versions.")
    print("Scenario: {0}".format(", ".join(TRAFFIC_SCENARIO)))
    if args.live:
        print("Live mode ON: the policy is placed in a real model's context window.")
    print()

    # Base deterministic runs, one per policy version. This is the demonstration
    # and it is what the no-flag invocation produces, unchanged.
    runs = [run_deterministic(v, p, TRAFFIC_SCENARIO, "routing.yaml") for v, p in POLICY_FILES]
    for run in runs:
        _print_run(run)

    # Optional live runs: the same scenario, generated by a real model, validated
    # against the matching deterministic run above.
    live_runs = None
    if args.live:
        live_runs = []
        for det_run, (_, path) in zip(runs, POLICY_FILES):
            live_run = run_live(det_run, path, TRAFFIC_SCENARIO, "routing.live.yaml")
            if live_run:
                live_runs.append(live_run)
                _print_live_run(live_run)
        if not live_runs:
            live_runs = None

    # Optional adversarial run: the injection scenario against the hardened policy.
    adversarial = None
    if args.adversarial:
        version, path = V2
        det = run_deterministic(version, path, ADVERSARIAL_SCENARIO,
                                "routing.adversarial.yaml", label="adversarial")
        print("### ADVERSARIAL SCENARIO (prompt injection smuggled in as a tenant name)")
        print()
        _print_run(det)
        live = None
        if args.live:
            live = run_live(det, path, ADVERSARIAL_SCENARIO,
                            "routing.adversarial.live.yaml", label="adversarial")
            if live:
                _print_live_run(live)
        adversarial = {"scenario": ADVERSARIAL_SCENARIO, "det": det, "live": live}

    _print_delta(runs[0], runs[1])

    # Write the human readable report. It gains a live-validation section and an
    # adversarial section only when those modes ran.
    report = build_markdown_report(runs, TRAFFIC_SCENARIO, live_runs=live_runs, adversarial=adversarial)
    report_path = os.path.join(ROOT, "report.md")
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(report)
    print()
    print("Report written to {0}".format(os.path.relpath(report_path, ROOT)))


if __name__ == "__main__":
    main()
