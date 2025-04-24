// 该文件包含对api_client_version.go中版本API的测试
package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// setupVersionTestServerComprehensive 创建专门测试版本相关方法的测试服务器
func setupVersionTestServerComprehensive() *httptest.Server {
	handler := http.NewServeMux()

	// 正常版本响应
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version": "4.7",
			"updated": "2022-06-28",
			"notes":   "Regular update for CWE List",
		})
	})

	// 格式错误的JSON
	handler.HandleFunc("/cwe/version/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version": "4.7"`)) // 缺少结束括号
	})

	// 错误的结构 - version不是字符串
	handler.HandleFunc("/cwe/version/wrong-structure", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version": 4.7, // 数字而不是字符串
			"updated": "2022-06-28",
		})
	})

	// 缺少版本信息
	handler.HandleFunc("/cwe/version/missing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"updated": "2022-06-28",
			"notes":   "No version information",
		})
	})

	// 服务器错误
	handler.HandleFunc("/cwe/version/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	})

	// 无效路径
	handler.HandleFunc("/cwe/invalid-path", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(handler)
}

// TestGetVersionExtraEdgeCases 全面测试GetVersion方法
func TestGetVersionExtraEdgeCases(t *testing.T) {
	server := setupVersionTestServerComprehensive()
	defer server.Close()

	// 创建一个默认的速率限制器
	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	// 测试正常响应
	versionResp, err := client.GetVersion()
	if err != nil {
		t.Errorf("GetVersion failed for normal case: %v", err)
	}
	if versionResp.Version != "4.7" {
		t.Errorf("Expected version 4.7, got %s", versionResp.Version)
	}

	// 调整baseURL以测试其他情况
	// 测试格式错误的JSON
	client.baseURL = server.URL + "/cwe/version/malformed"
	_, err = client.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail with malformed JSON")
	}

	// 测试错误的结构
	client.baseURL = server.URL + "/cwe/version/wrong-structure"
	_, err = client.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail with wrong structure")
	}

	// 测试缺少版本信息
	client.baseURL = server.URL + "/cwe/version/missing"
	_, err = client.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail with missing version")
	}

	// 测试服务器错误
	client.baseURL = server.URL + "/cwe/version/error"
	_, err = client.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail with server error")
	}

	// 测试无效路径
	client.baseURL = server.URL + "/cwe/invalid-path"
	_, err = client.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail with invalid path")
	}

	// 测试连接失败
	client.baseURL = "http://non-existent-server"
	_, err = client.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail with connection error")
	}
}

// TestGetCurrentVersionExtra 详细测试GetCurrentVersion方法
func TestGetCurrentVersionExtra(t *testing.T) {
	server := setupVersionTestServerComprehensive()
	defer server.Close()

	// 创建一个默认的速率限制器
	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)
	fetcher := NewDataFetcherWithClient(client)

	// 测试正常响应
	version, err := fetcher.GetCurrentVersion()
	if err != nil {
		t.Errorf("GetCurrentVersion failed: %v", err)
	}
	if version != "4.7" {
		t.Errorf("Expected version 4.7, got %s", version)
	}

	// 测试当API客户端返回错误时
	badRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, badRateLimiter)
	badFetcher := NewDataFetcherWithClient(badClient)

	_, err = badFetcher.GetCurrentVersion()
	if err == nil {
		t.Error("GetCurrentVersion should fail when API client fails")
	}
}
