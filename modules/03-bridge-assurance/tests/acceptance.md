# Bridge acceptance tests

Contract tests run now. Adapter tests below are required before implementation can be marked complete:

- Positive, negative and malformed fixtures for bridge-verification.
- Reject the wrong asset kind and missing provenance; preserve unknowns.
- Verify tenant isolation and authenticated integration authorization.
- Exercise timeout, replay, stale evidence, corrupted signatures and unsupported version handling.
- Compare findings with expected rule version, confidence and original evidence.
- Verify: Each bridge adapter must declare its own validation architecture; generic signature counts cannot establish bridge security.
