# Supply chain and release strategy

Implemented: exact direct Node dependency pins and pnpm lockfile; pinned Go module with checksums; production Node vulnerability audit command and CI gate; installed Node dependency SBOM exporter (`pnpm sbom`); CodeQL workflow configuration. Local audit results are recorded in the implementation report. CI has not run remotely in this local-only session.

The CycloneDX 1.5 exporter inventories pnpm's installed production dependency graph, including the console. It excludes Go and OS packages, licenses, hashes and build provenance. It must not be represented as a complete signed release SBOM.

Release plan (not executed): build from an approved immutable commit in a protected CI environment; generate full Node/Go/container SBOMs and provenance; scan dependencies and images; sign artifact digests and attestations with workload identity through Sigstore/cosign; require identity/issuer verification before deployment; retain audit records and a tested rollback artifact. Pin action and image digests for a release. Release signing, deployment and publication require approval. No signature or attestation is fabricated here.
