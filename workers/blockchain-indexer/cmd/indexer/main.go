package main

import (
	"context"
	indexer "github.com/richardrich999888-rgb/ChainVanta/workers/blockchain-indexer"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	chain, err := strconv.ParseUint(os.Getenv("CHAIN_ID"), 10, 64)
	if err != nil || chain == 0 {
		log.Fatal("CHAIN_ID required")
	}
	start, err := strconv.ParseUint(os.Getenv("START_BLOCK"), 10, 64)
	if err != nil {
		log.Fatal("START_BLOCK required; never implicitly backfill genesis")
	}
	path := os.Getenv("CHECKPOINT_PATH")
	if path == "" {
		log.Fatal("CHECKPOINT_PATH required (single worker per path)")
	}
	if os.Getenv("CHAINVANTA_API_KEY") == "" {
		log.Fatal("CHAINVANTA_API_KEY required")
	}
	client := indexer.HTTPClient()
	apiClient := indexer.HTTPClient()
	apiClient.Timeout = 180 * time.Second
	worker := indexer.Worker{Source: indexer.RPC{URL: os.Getenv("RPC_URL"), Client: client}, Sink: indexer.API{URL: os.Getenv("API_BASE_URL"), Key: os.Getenv("CHAINVANTA_API_KEY"), Client: apiClient}, Store: indexer.FileStore{Path: path}, ChainID: chain, StartBlock: start}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	progressed, err := worker.Step(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("finalized_block_processed=%t", progressed)
}
