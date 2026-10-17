// Package indexer implements a bounded, read-only finalized EVM transaction collector.
package indexer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
)

type Transaction struct {
	Hash common.Hash    `json:"hash"`
	From common.Address `json:"from"`
	Type string         `json:"type"`
}
type Block struct {
	Number       uint64
	Hash         common.Hash
	ParentHash   common.Hash
	Transactions []Transaction
}
type Source interface {
	ChainID(context.Context) (uint64, error)
	Finalized(context.Context) (Block, error)
	Block(context.Context, uint64) (Block, error)
}
type Sink interface {
	Assess(context.Context, uint64, Transaction, string) error
}
type Cursor struct {
	ChainID uint64      `json:"chainId"`
	Number  uint64      `json:"number"`
	Hash    common.Hash `json:"hash"`
}
type Store interface {
	Load() (*Cursor, error)
	Save(Cursor) error
}
type Worker struct {
	Source     Source
	Sink       Sink
	Store      Store
	ChainID    uint64
	StartBlock uint64
}

// Step commits its cursor only after every transaction was accepted by the API.
// Retried partial blocks use the same PostgreSQL-backed API idempotency keys.
// Reorganizations of already processed finalized blocks stop processing for operator review.
func (w Worker) Step(ctx context.Context) (bool, error) {
	chain, err := w.Source.ChainID(ctx)
	if err != nil {
		return false, err
	}
	if chain != w.ChainID {
		return false, errors.New("provider chain mismatch")
	}
	cursor, err := w.Store.Load()
	if err != nil {
		return false, err
	}
	next := w.StartBlock
	if cursor != nil {
		if cursor.ChainID != chain {
			return false, errors.New("checkpoint chain mismatch")
		}
		canonical, err := w.Source.Block(ctx, cursor.Number)
		if err != nil {
			return false, err
		}
		if canonical.Number != cursor.Number || canonical.Hash != cursor.Hash {
			return false, errors.New("finalized chain reorganization: operator review required")
		}
		if cursor.Number == ^uint64(0) {
			return false, errors.New("checkpoint overflow")
		}
		next = cursor.Number + 1
	}
	finalized, err := w.Source.Finalized(ctx)
	if err != nil {
		return false, err
	}
	if next > finalized.Number {
		return false, nil
	}
	block, err := w.Source.Block(ctx, next)
	if err != nil {
		return false, err
	}
	if block.Number != next || block.Hash == (common.Hash{}) || len(block.Transactions) > 1000 {
		return false, errors.New("invalid or oversized block")
	}
	if cursor != nil && block.ParentHash != cursor.Hash {
		return false, errors.New("parent hash mismatch")
	}
	if block.Number == finalized.Number && block.Hash != finalized.Hash {
		return false, errors.New("finality changed")
	}
	seen := map[common.Hash]bool{}
	for _, tx := range block.Transactions {
		if tx.Hash == (common.Hash{}) || seen[tx.Hash] {
			return false, errors.New("malformed or duplicate transaction")
		}
		seen[tx.Hash] = true
		if tx.Type != "0x0" && tx.Type != "0x1" && tx.Type != "0x2" {
			return false, errors.New("unsupported transaction type; checkpoint not advanced")
		}
		key := fmt.Sprintf("evm-%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", chain, block.Hash, tx.Hash))))
		if err := w.Sink.Assess(ctx, chain, tx, key); err != nil {
			return false, err
		}
	}
	after, err := w.Source.Block(ctx, next)
	if err != nil {
		return false, err
	}
	if after.Hash != block.Hash || after.Number != next {
		return false, errors.New("block changed during ingestion")
	}
	if err = w.Store.Save(Cursor{ChainID: chain, Number: next, Hash: block.Hash}); err != nil {
		return false, err
	}
	return true, nil
}

// FileStore is a single-worker local checkpoint, not a multi-replica lease or database cursor.
// Keep this file on durable storage. The API remains the authoritative assessment store.
type FileStore struct{ Path string }

func (s FileStore) Load() (*Cursor, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Cursor
	if err = json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
func (s FileStore) Save(c Cursor) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.Path), ".checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.Path)
}
