# ADR 0001: Start with a modular application

Status: accepted for the prototype.

The supplied architecture spans 12 domains and multiple languages. Implementing every service and runtime before proving the data path would create unverified scaffolding and unnecessary operations work.

Use a pnpm TypeScript workspace with Next.js, NestJS and PostgreSQL. Keep domain, connector, engine and module boundaries in folders, with relative imports and a single backend TypeScript build. Only the web application is a separately built workspace package in this milestone. Extract backend packages with explicit public exports when independent versioning or consumers justify it.

Redis has an opt-in Compose profile. Go indexing, Rust cryptography, offline Python research and container orchestration remain planned. This makes the first milestone installable and testable without implying that planned modules are usable.

The initial authorization mechanism is an operator-configured tenant key, not end-user identity. It supports reproducible isolation tests but does not meet the proposed production identity and RBAC milestone.
