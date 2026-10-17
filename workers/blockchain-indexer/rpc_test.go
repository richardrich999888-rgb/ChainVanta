package indexer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyRPCAndContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		if v.Method != "eth_chainId" {
			t.Errorf("unexpected RPC %s", v.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer srv.Close()
	rpc := RPC{URL: srv.URL, Client: HTTPClient()}
	id, err := rpc.ChainID(context.Background())
	if err != nil || id != 1 {
		t.Fatal("valid chain failed", err)
	}
}
func TestMalformedResponseAndTimeout(t *testing.T) {
	for _, kind := range []string{"malformed", "timeout", "wrong-id"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "timeout" {
					time.Sleep(20 * time.Millisecond)
				}
				if kind == "wrong-id" {
					w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":"0x1"}`))
				} else {
					w.Write([]byte(`not-json-provider-secret`))
				}
			}))
			defer srv.Close()
			client := HTTPClient()
			client.Timeout = 5 * time.Millisecond
			_, err := (RPC{URL: srv.URL, Client: client}).ChainID(context.Background())
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("unsafe failure", err)
			}
		})
	}
}
