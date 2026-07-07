"""
Entry point. Runs one fixed traffic scenario against two policy versions and
writes, for each: the generated routing config and an audit record.

The same input produces different output under each policy, because the context
differed. That delta, and the two audit records that pin it to a policy hash, is
the demonstration.

    python demo.py
"""

import json
import os

import yaml

from agent import PolicyAgent, load_policy_context
from agent.policy_agent import TRAFFIC_SCENARIO
from agent.report import build_markdown_report

ROOT = os.path.dirname(os.path.abspath(__file__))

POLICY_FILES = [
    ("v1-permissive", os.path.join(ROOT, "policies", "v1-permissive", "network-policy.yaml")),
    ("v2-hardened", os.path.join(ROOT, "policies", "v2-hardened", "network-policy.yaml")),
]


def _write_yaml(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, default_flow_style=False)


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def run_one(version: str, policy_path: str) -> dict:
    """Load the policy as context, generate config, write config plus audit."""
    context = load_policy_context(policy_path)
    agent = PolicyAgent(context)
    result = agent.generate(TRAFFIC_SCENARIO)

    config_path = os.path.join(ROOT, "configs", version, "routing.yaml")
    audit_path = os.path.join(ROOT, "audit", "{0}-{1}.json".format(version, result.audit["run_id"][:8]))

    # The audit record points at the config it explains, and at the policy it
    # was shown, both repo-relative so records are portable and legible.
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


def main() -> None:
    print("Policy as Context: same traffic scenario, two policy versions.")
    print("Scenario: {0}".format(", ".join(TRAFFIC_SCENARIO)))
    print()

    runs = [run_one(version, path) for version, path in POLICY_FILES]

    for run in runs:
        _print_run(run)

    # The one-line delta, stated plainly.
    v1, v2 = runs
    print("=" * 72)
    print("THE DELTA")
    print("=" * 72)
    print("Same scenario. Same agent. Different policy in the context window.")
    print()
    print("  v1-permissive  hash {0}".format(v1["context"].sha256[:16]))
    print("    rules_applied:   {0}".format(", ".join(v1["audit"]["rules_applied"])))
    print("    redactions_made: {0}".format(v1["audit"]["redactions_made"]))
    print("    rejected:        {0}".format(v1["audit"]["rejected_tenants"] or "none"))
    print()
    print("  v2-hardened    hash {0}".format(v2["context"].sha256[:16]))
    print("    rules_applied:   {0}".format(", ".join(v2["audit"]["rules_applied"])))
    print("    redactions_made: {0}".format(v2["audit"]["redactions_made"]))
    print("    rejected:        {0}".format(v2["audit"]["rejected_tenants"] or "none"))
    print()
    print("The output differed because the context differed. The audit records")
    print("prove which policy each run was shown, by hash, at generation time.")

    # Write a human readable report that explains what ran, which policy applied,
    # what the audit shows, and how to read it. In CI this is rendered on the
    # GitHub Actions run summary page.
    report = build_markdown_report(runs, TRAFFIC_SCENARIO)
    report_path = os.path.join(ROOT, "report.md")
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(report)
    print()
    print("Report written to {0}".format(os.path.relpath(report_path, ROOT)))


if __name__ == "__main__":
    main()
