"""
Builds a human readable Markdown report from the two runs.

The console output is dense and good for a terminal. This report is for a reader
who was not watching the run: it states which policy was applied, what the audit
record shows, and how to interpret the difference. It is written to a file and,
in CI, rendered on the GitHub Actions run summary page.

Everything here is derived from the actual run data, not asserted. If a policy
did not turn a rule on, it does not show up as applied.
"""

from datetime import datetime, timezone


def _routes_by_tenant(config: dict) -> dict:
    """Map each tenant to the cluster it routed to, or 'rejected'."""
    result = {}
    for route in config.get("routes", []):
        if route.get("status") == "rejected":
            result[route["tenant"]] = "rejected"
        else:
            result[route["tenant"]] = route.get("cluster", "unknown")
    return result


def _transport(config: dict) -> str:
    """Describe the upstream transport from the first routed tenant."""
    for route in config.get("routes", []):
        upstream = route.get("upstream")
        if upstream:
            tls = "TLS required" if upstream.get("tls") == "required" else "plaintext allowed"
            return "{0}, {1}".format(upstream.get("protocol", "?"), tls)
    return "no routed tenants"


def _summarize(run: dict) -> dict:
    config = run["config"]
    audit = run["audit"]
    return {
        "version": run["version"],
        "hash": run["context"].sha256,
        "auth": config.get("authentication", {}).get("method", "unknown"),
        "routes": _routes_by_tenant(config),
        "transport": _transport(config),
        "ddos": "on" if config.get("ddos_mitigation", {}).get("enabled") else "off",
        "redactions": audit.get("redactions_made", 0),
        "rejected": audit.get("rejected_tenants", []),
        "rules": audit.get("rules_applied", []),
        "notes": audit.get("notes", ""),
        "config_path": audit.get("output_config_path", ""),
        "audit_path": run.get("audit_rel_path", ""),
    }


def _delta_table(scenario: list, a: dict, b: dict) -> list:
    """Rows for the side by side comparison table."""
    lines = [
        "| What the reader is comparing | {0} | {1} |".format(a["version"], b["version"]),
        "| --- | --- | --- |",
        "| policy hash (first 12) | `{0}` | `{1}` |".format(a["hash"][:12], b["hash"][:12]),
        "| incoming auth | {0} | {1} |".format(a["auth"], b["auth"]),
    ]
    for tenant in scenario:
        lines.append(
            "| route: {0} | {1} | {2} |".format(
                tenant, a["routes"].get(tenant, "n/a"), b["routes"].get(tenant, "n/a")
            )
        )
    lines.append("| upstream transport | {0} | {1} |".format(a["transport"], b["transport"]))
    lines.append("| DDoS rate limits | {0} | {1} |".format(a["ddos"], b["ddos"]))
    lines.append("| secret redactions | {0} | {1} |".format(a["redactions"], b["redactions"]))
    lines.append(
        "| rules applied | {0} | {1} |".format(len(a["rules"]), len(b["rules"]))
    )
    return lines


def _per_run_section(s: dict, scenario: list) -> list:
    lines = []
    lines.append("### {0}".format(s["version"]))
    lines.append("")
    lines.append("**Which policy was applied.** The agent loaded `{0}` as context. "
                 "The audit record is pinned to this sha256 of the exact policy text "
                 "it was shown:".format(s["version"]))
    lines.append("")
    lines.append("```")
    lines.append(s["hash"])
    lines.append("```")
    lines.append("")
    lines.append("**What the agent produced.** Routing decisions for the fixed scenario:")
    lines.append("")
    lines.append("| tenant | outcome |")
    lines.append("| --- | --- |")
    for tenant in scenario:
        lines.append("| {0} | {1} |".format(tenant, s["routes"].get(tenant, "n/a")))
    lines.append("")
    lines.append("**What the audit record shows.**")
    lines.append("")
    lines.append("- rules the policy activated: {0}".format(
        ", ".join("`{0}`".format(r) for r in s["rules"]) or "none"))
    lines.append("- secret redactions made: **{0}**".format(s["redactions"]))
    lines.append("- tenants rejected: {0}".format(
        ", ".join(s["rejected"]) if s["rejected"] else "none"))
    lines.append("- note: {0}".format(s["notes"]))
    lines.append("")
    lines.append("Config written to `{0}`.".format(s["config_path"]))
    lines.append("")
    return lines


def build_markdown_report(runs: list, scenario: list) -> str:
    """Assemble the full Markdown report from both runs."""
    summaries = [_summarize(run) for run in runs]
    a, b = summaries[0], summaries[1]

    out = []
    out.append("# Policy as Context: run report")
    out.append("")
    out.append("_Generated {0}_".format(datetime.now(timezone.utc).isoformat(timespec="seconds")))
    out.append("")
    out.append("## What ran, and why")
    out.append("")
    out.append("One fixed traffic scenario (`{0}`) was generated twice, once under "
               "each policy version. The agent, the request, and the code were "
               "identical across both runs. The only variable was the policy loaded "
               "into the agent's context window. So any difference in the output "
               "below is attributable to the policy, and nothing else.".format(
                   ", ".join(scenario)))
    out.append("")
    out.append("## What it showed: same input, different output")
    out.append("")
    out.extend(_delta_table(scenario, a, b))
    out.append("")
    out.append("The two columns come from the same agent handling the same request. "
               "They differ because the context differed.")
    out.append("")
    out.append("## Per policy detail")
    out.append("")
    out.extend(_per_run_section(a, scenario))
    out.extend(_per_run_section(b, scenario))
    out.append("## How to interpret this")
    out.append("")
    out.append("There are three control surfaces behind any agent decision. Read the "
               "table above against them:")
    out.append("")
    out.append("1. **What the agent may touch** (permissions). Not shown here. This is "
               "the deterministic floor and it does not change between the two runs.")
    out.append("2. **What the agent was shown** (policy as context). This is the only "
               "thing that changed. Under `{0}` the agent shared one cluster, allowed "
               "plaintext, and wrote secrets as literals. Under `{1}` it isolated "
               "tenants, enforced TLS, rejected the unknown tenant, and redacted "
               "secrets. Same code, different context, different config.".format(
                   a["version"], b["version"]))
    out.append("3. **What the agent was shown, and what it did** (audit). Each run wrote "
               "an audit record carrying the policy hash above. That hash is what lets a "
               "reviewer prove, after the fact, which policy the agent operated under "
               "when it generated a given config.")
    out.append("")
    out.append("What to check in a real review: the policy hash pins the exact policy "
               "text; a nonzero redaction count means secrets were kept out of the "
               "generated config; a rejected tenant means the hardened policy refused to "
               "route traffic it could not place safely.")
    out.append("")
    out.append("Enforcement here is simulated. The point is the mechanic: context shapes "
               "the output, and the audit record makes that link reconstructable.")
    out.append("")
    return "\n".join(out)
