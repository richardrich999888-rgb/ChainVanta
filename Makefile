.PHONY: bootstrap up migrate dev test build check
bootstrap:
	pnpm install --frozen-lockfile
	pnpm bootstrap
up:
	docker compose up -d --wait postgres
migrate:
	pnpm db:migrate
dev:
	pnpm dev
test:
	pnpm test
build:
	pnpm build
check:
	pnpm check:structure
	pnpm typecheck
	pnpm lint
	pnpm test
