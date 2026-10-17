# Provenance threat boundary

Status: design, not a completed security review.

Content integrity and signature validity do not establish legal ownership or authentic real-world claims.

Trust boundaries: tenant identity originates in authenticated server context; external metadata is hostile; network endpoints are operator controlled; raw evidence and versioned parsers precede conclusions.

Threats: forged provenance, cross-tenant references, replayed observations, stale configurations, malicious metadata and secret leakage. Require source identity, observation time, confidence and evidence links; fail closed on unsupported formats.
