package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 创建一个基本的模拟服务器用于测试
func setupBasicMockServer() *httptest.Server {
	handler := http.NewServeMux()

	// 版本请求
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "4.8",
		})
	})

	return httptest.NewServer(handler)
}

func TestNewDataFetcher(t *testing.T) {
	fetcher := NewDataFetcher()
	if fetcher.client == nil {
		t.Error("Expected client to be initialized")
	}
}

func TestNewDataFetcherWithClient(t *testing.T) {
	client := NewAPIClient()
	fetcher := NewDataFetcherWithClient(client)
	if fetcher.client != client {
		t.Error("Expected client to be the provided client")
	}
}

func TestGetCurrentVersion(t *testing.T) {
	server := setupBasicMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	version, err := fetcher.GetCurrentVersion()
	if err != nil {
		t.Errorf("GetCurrentVersion failed: %v", err)
		return
	}

	if version != "4.8" {
		t.Errorf("Expected version to be 4.8, got %s", version)
	}
}
