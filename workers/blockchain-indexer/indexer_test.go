package indexer

import (
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"path/filepath"
	"testing"
)

type source struct {
	chain  uint64
	block  Block
	calls  int
	change bool
}

func (s *source) ChainID(context.Context) (uint64, error)  { return s.chain, nil }
func (s *source) Finalized(context.Context) (Block, error) { return s.block, nil }
func (s *source) Block(_ context.Context, n uint64) (Block, error) {
	s.calls++
	b := s.block
	b.Number = n
	if s.change && s.calls > 1 {
		b.Hash = common.HexToHash("0xff")
	}
	return b, nil
}

type sink struct {
	keys []string
	fail bool
}

func (s *sink) Assess(_ context.Context, _ uint64, _ Transaction, key string) error {
	s.keys = append(s.keys, key)
	if s.fail {
		return errors.New("partial failure")
	}
	return nil
}
func fixture(t *testing.T) (Worker, *source, *sink) {
	t.Helper()
	s := &source{chain: 1, block: Block{Number: 10, Hash: common.HexToHash("0xab"), Transactions: []Transaction{{Hash: common.HexToHash("0x1"), Type: "0x2"}}}}
	k := &sink{}
	return Worker{Source: s, Sink: k, Store: FileStore{filepath.Join(t.TempDir(), "checkpoint.json")}, ChainID: 1, StartBlock: 10}, s, k
}
func TestPartialRecoveryAndReplay(t *testing.T) {
	w, _, k := fixture(t)
	k.fail = true
	if _, err := w.Step(context.Background()); err == nil {
		t.Fatal("failure accepted")
	}
	c, _ := w.Store.Load()
	if c != nil {
		t.Fatal("partial checkpoint persisted")
	}
	k.fail = false
	if ok, err := w.Step(context.Background()); !ok || err != nil {
		t.Fatal(err)
	}
	if len(k.keys) != 2 || k.keys[0] != k.keys[1] {
		t.Fatal("replay key changed")
	}
	c, _ = w.Store.Load()
	if c == nil || c.Number != 10 {
		t.Fatal("checkpoint missing")
	}
	if ok, err := w.Step(context.Background()); ok || err != nil {
		t.Fatal("duplicate finalized block processed")
	}
}
func TestWrongChain(t *testing.T) {
	w, s, k := fixture(t)
	s.chain = 2
	if _, err := w.Step(context.Background()); err == nil {
		t.Fatal("wrong chain accepted")
	}
	if len(k.keys) != 0 {
		t.Fatal("wrong chain processed")
	}
}
func TestReorganization(t *testing.T) {
	w, s, _ := fixture(t)
	s.change = true
	if _, err := w.Step(context.Background()); err == nil {
		t.Fatal("reorg accepted")
	}
	c, _ := w.Store.Load()
	if c != nil {
		t.Fatal("reorg checkpoint saved")
	}
}
func TestPersistedReorganization(t *testing.T) {
	w, s, _ := fixture(t)
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.block.Hash = common.HexToHash("0xcd")
	if _, err := w.Step(context.Background()); err == nil {
		t.Fatal("changed finalized history accepted")
	}
}
func TestUnsupportedAndDuplicateTransactions(t *testing.T) {
	for _, kind := range []string{"unsupported", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			w, s, _ := fixture(t)
			if kind == "unsupported" {
				s.block.Transactions[0].Type = "0x4"
			} else {
				s.block.Transactions = append(s.block.Transactions, s.block.Transactions[0])
			}
			if _, err := w.Step(context.Background()); err == nil {
				t.Fatal("invalid block accepted")
			}
			c, _ := w.Store.Load()
			if c != nil {
				t.Fatal("invalid checkpoint persisted")
			}
		})
	}
}
func TestUnsafeEndpoint(t *testing.T) {
	for _, url := range []string{"file:///etc/passwd", "http://169.254.169.254", "https://user:secret@example.com", "http://example.com"} {
		if ValidateEndpoint(url) == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}
