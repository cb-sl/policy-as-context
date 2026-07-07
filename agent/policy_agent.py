"""
The config-generating agent.

The agent does one thing: it loads a versioned network policy as context, then
generates a routing config shaped entirely by that policy. Nothing about the
output is hardcoded per version. Change the policy in the context window and the
output changes with it. That is the whole point.

The policy hash is computed over the exact policy file text at load time. It is
what lets an incident reviewer prove which policy the agent was shown when it ran.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import yaml


# The fixed traffic scenario. Same input for every run so that any difference in
# output is attributable to the policy context, not to the request.
TRAFFIC_SCENARIO = ["tenant-a", "tenant-b", "unknown-tenant"]

# Simulated upstream credential the agent would otherwise write into the config
# verbatim. Under a redacting policy it is replaced with the policy's reference
# pattern. Under a permissive policy it appears as a literal, which is the point.
_SIMULATED_UPSTREAM_CREDENTIAL = {
    "tenant-a": "svc-cred-tenant-a-9f2c17b4e0",
    "tenant-b": "svc-cred-tenant-b-3a81de55c9",
}


@dataclass
class PolicyContext:
    """A policy file loaded into the agent's context window.

    Holds the parsed policy and, just as importantly, the exact text and its hash.
    The text is what the agent was shown. The hash is what proves it.
    """

    version: str
    path: str
    raw_text: str
    policy: dict

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw_text.encode("utf-8")).hexdigest()


def load_policy_context(path: str) -> PolicyContext:
    """Read a policy file as the agent's context. Hash the exact bytes shown."""
    with open(path, "r", encoding="utf-8") as handle:
        raw_text = handle.read()
    policy = yaml.safe_load(raw_text)
    return PolicyContext(
        version=policy.get("policy_version", "unknown"),
        path=path,
        raw_text=raw_text,
        policy=policy,
    )


@dataclass
class GenerationResult:
    config: dict
    audit: dict
    rejected_tenants: list = field(default_factory=list)
    redactions_made: int = 0


class PolicyAgent:
    """Generates a routing config from whatever policy is in its context."""

    def __init__(self, context: PolicyContext):
        self.context = context
        self.policy = context.policy

    # Routing decisions, read straight from the policy.

    def _cluster_for(self, tenant: str):
        """Return the cluster this tenant routes to, or None if it is rejected."""
        routing = self.policy.get("routing", {})
        for entry in routing.get("tenant_assignment", []):
            assigned = entry.get("tenant")
            if assigned == tenant or assigned == "*":
                return entry.get("cluster")
        # No explicit assignment. Fall back to the policy's default behaviour.
        if routing.get("reject_unknown_tenant"):
            return None
        return routing.get("default_cluster")

    def _redact(self, secret_value: str):
        """Apply the policy's secret redaction. Returns (value, was_redacted)."""
        redaction = self.policy.get("secret_redaction", {})
        if redaction.get("enabled") and "upstream_credentials" in redaction.get(
            "applies_to", []
        ):
            return redaction.get("redact_pattern", "${SECRET_REF}"), True
        return secret_value, False

    def _rules_applied(self) -> list:
        """The named rules the policy actually activated for this generation.

        Derived from the policy, not asserted. If a policy does not turn a rule
        on, that rule does not appear in the audit record.
        """
        rules = []
        auth = self.policy.get("authentication", {}).get("incoming_traffic", {})
        if auth.get("mutual_tls"):
            rules.append("mutual_tls")
        else:
            rules.append("bearer_token_auth")

        routing = self.policy.get("routing", {})
        assignments = routing.get("tenant_assignment", [])
        if any(a.get("tenant") == "*" for a in assignments):
            rules.append("shared_cluster_routing")
        else:
            rules.append("tenant_isolation")

        if self.policy.get("secure_routing", {}).get("require_tls_upstream"):
            rules.append("tls_upstream_enforced")
        else:
            rules.append("plaintext_upstream_allowed")

        if self.policy.get("ddos_mitigation", {}).get("enabled"):
            rules.append("ddos_rate_limit")

        if self.policy.get("secret_redaction", {}).get("enabled"):
            rules.append("secret_redaction")

        if routing.get("reject_unknown_tenant"):
            rules.append("reject_unknown_tenant")

        return rules

    def generate(self, scenario=None) -> GenerationResult:
        """Produce a routing config for the scenario under the loaded policy."""
        scenario = scenario or TRAFFIC_SCENARIO

        auth = self.policy.get("authentication", {}).get("incoming_traffic", {})
        secure = self.policy.get("secure_routing", {})
        ddos = self.policy.get("ddos_mitigation", {})

        routes = []
        rejected = []
        redactions = 0

        for tenant in scenario:
            cluster = self._cluster_for(tenant)
            if cluster is None:
                rejected.append(tenant)
                routes.append(
                    {
                        "tenant": tenant,
                        "status": "rejected",
                        "reason": "reject_unknown_tenant",
                    }
                )
                continue

            protocol = "https" if secure.get("require_tls_upstream") else "http"
            credential = _SIMULATED_UPSTREAM_CREDENTIAL.get(
                tenant, "svc-cred-shared-000000"
            )
            credential, was_redacted = self._redact(credential)
            if was_redacted:
                redactions += 1

            upstream = {
                "protocol": protocol,
                "tls": "required" if secure.get("require_tls_upstream") else "not_required",
                "upstream_credentials": credential,
            }
            if secure.get("require_tls_upstream") and secure.get("min_tls_version"):
                upstream["min_tls_version"] = secure["min_tls_version"]

            routes.append(
                {
                    "tenant": tenant,
                    "cluster": cluster,
                    "status": "routed",
                    "upstream": upstream,
                }
            )

        config = {
            "generated_by": "policy-as-context-agent",
            "policy_version": self.context.version,
            "policy_hash": self.context.sha256,
            "authentication": {
                "method": auth.get("method"),
                "mutual_tls": bool(auth.get("mutual_tls")),
                "reject_unauthenticated": bool(auth.get("reject_unauthenticated")),
            },
            "routes": routes,
        }

        if ddos.get("enabled"):
            config["ddos_mitigation"] = {
                "enabled": True,
                "rate_limit_per_ip": ddos.get("rate_limit_per_ip"),
                "connection_limit_per_ip": ddos.get("connection_limit_per_ip"),
                "block_duration_seconds": ddos.get("block_duration_seconds"),
                "syn_flood_protection": ddos.get("syn_flood_protection", False),
            }

        audit = {
            "run_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_version": self.context.version,
            "policy_hash": self.context.sha256,
            "policy_path": self.context.path,
            "traffic_scenario": ", ".join(scenario),
            "rules_applied": self._rules_applied(),
            "redactions_made": redactions,
            "rejected_tenants": rejected,
            "output_config_path": None,  # filled in by the caller once written
            "notes": self._notes(rejected),
        }

        return GenerationResult(
            config=config,
            audit=audit,
            rejected_tenants=rejected,
            redactions_made=redactions,
        )

    def _notes(self, rejected: list) -> str:
        if rejected:
            return "{0} rejected per reject_unknown_tenant".format(
                ", ".join(rejected)
            )
        return "all tenants routed under permissive policy; no rejections"
