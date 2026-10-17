# Dependency audit

Node production packages: `pnpm audit --prod --audit-level high`. Go packages and standard library: run `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` with Go 1.27.2 from the worker directory. Audit results are time-bound. The initial Go pins were upgraded after the scanner reported advisories; see docs/development/implementation-report.md for final outcomes.

No audit result is a security certification. Full image/OS inventory, license review and release provenance remain release prerequisites.
