# Provenance acceptance tests

Contract tests run now. Adapter tests below are required before implementation can be marked complete:

- Positive, negative and malformed fixtures for content-signature.
- Reject the wrong asset kind and missing provenance; preserve unknowns.
- Verify tenant isolation and authenticated integration authorization.
- Exercise timeout, replay, stale evidence, corrupted signatures and unsupported version handling.
- Compare findings with expected rule version, confidence and original evidence.
- Verify: Content integrity and signature validity do not establish legal ownership or authentic real-world claims.
