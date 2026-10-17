# Contributing

`main` contains the shared foundation. Continue implementation on `feature/chainvanta-platform-foundation`, or create a focused `codex/<change-name>` branch from `main`. Submit changes to `main` through a reviewed pull request. Branch protection and required checks must be configured separately in GitHub; workflows alone do not enable protection.

Run `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm lint`, `pnpm test` and `pnpm build`. Browser behavior changes also require `pnpm test:e2e`. Use disposable PostgreSQL for integration tests. Keep fixtures visibly synthetic and out of production seed paths.

Every activated module needs observable evidence, explicit unknown states, error semantics, API contracts and tenant-isolation tests. Do not label planned code operational, invent risk scores or claim quantum safety without validated evidence. Prefer audited cryptographic libraries to custom primitives.

Keep customer data, provider keys, private integrations, patent material and credentials out of this public repository. Do not publish, deploy or choose licensing without owner authorization. See SECURITY.md for private reporting guidance.
