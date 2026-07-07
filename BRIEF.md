# Brief for Claude Code

Build a small, runnable Python repo that demonstrates one thesis: for an AI agent, the context it is given is its enforcement surface. What the agent is shown is policy. What the agent was shown is audit.

This is a credible proof of concept, not a marketing piece. Keep it plain and legible.

## What the agent does

The agent generates load balancing config for incoming traffic on a platform. It authenticates incoming traffic, routes it to the appropriate cluster (routing basis is tenant_id), and produces a routing config artifact as YAML. The config is cloud-agnostic and tenancy-agnostic. Nothing assumes a specific cloud provider or single versus multi tenant.

The agent does not run live traffic. It generates config from a policy loaded as context.

## The core mechanic

The agent loads a versioned network policy file as context, then generates a routing config shaped by that policy. The demo runs the same traffic scenario against two policy versions and shows the generated config differs because the context differed. Every run writes an audit record capturing which policy version was in the context window at generation time.

## The traffic scenario

A single fixed scenario used for both runs: incoming requests for `tenant-a`, `tenant-b`, and one `unknown-tenant`. This is enough to show the delta between the two policies (see below).

## The two policy versions

Policy files are provided in `policies/v1-permissive/network-policy.yaml` and `policies/v2-hardened/network-policy.yaml`. Read them as the source of truth. Do not invent new fields; use what is there.

Expected delta when the same scenario runs against each:

- Under v1: all three tenants route to `cluster-shared`, upstream TLS not required, bearer token auth, secrets appear as literals in the config.
- Under v2: tenant-a and tenant-b route to isolated clusters over enforced TLS with mutual TLS auth, unknown-tenant is rejected, DDoS rate limits are written into the config, secrets are replaced with `${SECRET_REF}`.

That delta is the demonstration. The same input, different output, because the policy context changed.

## Enforcement

Simulated. The agent reads policy context and produces a config plus an audit record. No live clusters, no real traffic. The simulation must be legible enough that a reader trusts the mechanic.

## The audit record

Plain JSON, one file per run, written to `audit/`. Shape:

```json
{
  "run_id": "uuid",
  "timestamp": "ISO-8601",
  "policy_version": "v2-hardened",
  "policy_hash": "sha256 of the policy file",
  "traffic_scenario": "tenant-a, tenant-b, unknown-tenant",
  "rules_applied": ["mutual_tls", "tenant_isolation", "ddos_rate_limit", "secret_redaction", "reject_unknown_tenant"],
  "redactions_made": 2,
  "output_config_path": "configs/v2-hardened/routing.yaml",
  "notes": "unknown-tenant rejected per reject_unknown_tenant"
}
```

`policy_hash` is load-bearing, not decorative. It is a sha256 computed over the exact policy file text at generation time. It is what lets an incident reviewer prove which policy the agent was shown. Do not stub it. Compute it for real.

## Repo structure

```
policies/          versioned network policy files the agent reads as context
  v1-permissive/network-policy.yaml
  v2-hardened/network-policy.yaml
agent/             the config-generating agent
configs/           generated output, written per run (v1-permissive/, v2-hardened/)
audit/             audit records, written per run
demo.py            entry point, runs both scenarios
README.md          provided, written as a PM spec
```

## Running it

`python demo.py` runs the fixed scenario against both policy versions and writes, for each: the generated routing config, and the audit record. Output should make the difference between the two runs immediately visible, for example by printing the two configs and two audit records for side by side comparison, or by clearly reporting the paths written.

## Constraints

- Python only.
- No em dashes anywhere in code comments, output, or docs.
- Keep dependencies minimal. PyYAML for policy parsing is fine. Avoid anything heavier unless needed.
- The values marked CONFIRM in the policy files (TLS floor, rate limits, block durations) are illustrative defaults. Leave them as is and note in the README that they are illustrative.
- Do not add features beyond what is described. Credible and small beats broad.
