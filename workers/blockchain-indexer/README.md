# Finalized EVM worker

Status: **Partially implemented**. A bounded, single-worker Go collector submits verified transaction assessment requests to the API. It uses go-ethereum's canonical hash/address/quantity types and the standard HTTP client; the API verifies signatures and receipts using viem.

`Worker.Step` validates chain identity, checks the previous checkpoint against canonical state, processes one finalized block, rechecks its hash and atomically renames a local checkpoint file. Duplicate or unsupported transaction types stop the block. Retries reuse per-chain/block/transaction idempotency keys in PostgreSQL, so partial work is not duplicated. Reorganized finalized history stops for operator review; already saved observations remain historical evidence and are not silently rewritten.

Only transaction types 0, 1 and 2 are supported. The worker bounds blocks to 1,000 transactions, RPC bodies to 4 MiB, HTTP requests to 10 seconds and retries to three attempts. API submissions are paced at 600 ms; shared tenant activity may still cause 429. API failures preserve the checkpoint for a later run. One invocation has a 30-minute deadline and processes one block. Deploy an operator-controlled scheduler only after validating throughput and recovery.

## Test without installing Go globally

From the repository root (substitute your absolute checkout path):

```sh
docker run --rm -v /Users/richardrich/Desktop/chainvanta:/workspace \
  -w /workspace/workers/blockchain-indexer -e GOWORK=off \
  golang:1.27.2-alpine sh -c 'go test ./... && go vet ./... && go build ./cmd/indexer'
```

The toolchain and go-ethereum dependency are pinned; `go.sum` records module checksums. Docker output is a Linux binary; do not run it directly on macOS. With native Go installed, `go run ./cmd/indexer` runs locally.

Required environment: `RPC_URL`, `CHAIN_ID`, `START_BLOCK`, `API_BASE_URL`, `CHAINVANTA_API_KEY`, `CHECKPOINT_PATH`. Only HTTPS or explicit loopback HTTP is accepted. Keep credentials out of command-line arguments. The API must configure the same chain. Select a recent finalized starting block explicitly; genesis backfill is never automatic.

Checkpoint files require durable storage and **one writer per path, chain and tenant**. There is no distributed lease, database cursor or automatic downstream reorg invalidation. The transport still relies on operator-controlled DNS/egress policy. Run only against approved endpoints. Never use this worker for signing, transfers or contract modification.
