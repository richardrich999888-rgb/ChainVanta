# Agility threat boundary

Status: design, not a completed security review.

Untrusted bytecode, proxy indirection and selector collisions must not imply upgradeability. Foundry fixtures are required before adapter activation.

Trust boundaries: tenant identity originates in authenticated server context; external metadata is hostile; network endpoints are operator controlled; raw evidence and versioned parsers precede conclusions.

Threats: forged provenance, cross-tenant references, replayed observations, stale configurations, malicious metadata and secret leakage. Require source identity, observation time, confidence and evidence links; fail closed on unsupported formats.
