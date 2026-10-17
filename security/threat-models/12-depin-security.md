# Edge threat boundary

Status: design, not a completed security review.

Attestation requires a supported device, verified trust anchor, freshness and replay defenses. No simulated hardware assurance.

Trust boundaries: tenant identity originates in authenticated server context; external metadata is hostile; network endpoints are operator controlled; raw evidence and versioned parsers precede conclusions.

Threats: forged provenance, cross-tenant references, replayed observations, stale configurations, malicious metadata and secret leakage. Require source identity, observation time, confidence and evidence links; fail closed on unsupported formats.
