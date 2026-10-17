package indexer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"io"
	"net/http"
	"net/url"
	"time"
)

func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" {
		return errors.New("invalid endpoint")
	}
	local := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return errors.New("HTTPS or explicit loopback endpoint required")
	}
	return nil
}
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect prohibited") }}
}

type RPC struct {
	URL    string
	Client *http.Client
}

func (r RPC) call(ctx context.Context, method string, params []any, out any) error {
	if err := ValidateEndpoint(r.URL); err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "POST", r.URL, bytes.NewReader(data))
		if err != nil {
			return errors.New("invalid RPC request")
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := r.Client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
		res.Body.Close()
		if readErr != nil || len(body) > 4*1024*1024 || res.StatusCode != 200 {
			continue
		}
		var envelope struct {
			Version string          `json:"jsonrpc"`
			ID      int             `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}
		if json.Unmarshal(body, &envelope) != nil || envelope.Version != "2.0" || envelope.ID != 1 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || (len(envelope.Error) > 0 && string(envelope.Error) != "null") {
			continue
		}
		if json.Unmarshal(envelope.Result, out) != nil {
			return errors.New("malformed RPC result")
		}
		return nil
	}
	return errors.New("RPC unavailable after bounded retries")
}
func (r RPC) ChainID(ctx context.Context) (uint64, error) {
	var id hexutil.Uint64
	err := r.call(ctx, "eth_chainId", []any{}, &id)
	return uint64(id), err
}
func (r RPC) readBlock(ctx context.Context, tag string) (Block, error) {
	var raw struct {
		Number       *hexutil.Uint64 `json:"number"`
		Hash         common.Hash     `json:"hash"`
		ParentHash   common.Hash     `json:"parentHash"`
		Transactions []Transaction   `json:"transactions"`
	}
	err := r.call(ctx, "eth_getBlockByNumber", []any{tag, true}, &raw)
	if err != nil {
		return Block{}, err
	}
	if raw.Number == nil || raw.Hash == (common.Hash{}) {
		return Block{}, errors.New("missing block context")
	}
	return Block{Number: uint64(*raw.Number), Hash: raw.Hash, ParentHash: raw.ParentHash, Transactions: raw.Transactions}, nil
}
func (r RPC) Finalized(ctx context.Context) (Block, error) { return r.readBlock(ctx, "finalized") }
func (r RPC) Block(ctx context.Context, n uint64) (Block, error) {
	return r.readBlock(ctx, hexutil.EncodeUint64(n))
}

type API struct {
	URL, Key string
	Client   *http.Client
}

func (a API) Assess(ctx context.Context, chain uint64, tx Transaction, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(600 * time.Millisecond):
	}
	if err := ValidateEndpoint(a.URL); err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]any{"address": tx.From.Hex(), "chainId": chain, "transactionHash": tx.Hash.Hex()})
	req, err := http.NewRequestWithContext(ctx, "POST", a.URL+"/v1/assessments", bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid API endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+a.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	res, err := a.Client.Do(req)
	if err != nil {
		return errors.New("assessment API unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 201 {
		return fmt.Errorf("assessment API returned %d; checkpoint retained", res.StatusCode)
	}
	return nil
}
