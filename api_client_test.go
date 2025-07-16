package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// 创建一个模拟CWE API服务器
func setupMockServer() *httptest.Server {
	handler := http.NewServeMux()

	// 处理版本请求
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "4.7",
		})
	})

	// 处理多个CWE请求
	handler.HandleFunc("/cwe/74,79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"cwes": map[string]interface{}{
				"CWE-74": map[string]interface{}{
					"id":   "CWE-74",
					"name": "Improper Neutralization of Special Elements in Output Used by a Downstream Component",
				},
				"CWE-79": map[string]interface{}{
					"id":   "CWE-79",
					"name": "Improper Neutralization of Input During Web Page Generation",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理弱点请求
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-89",
					"name":        "Improper Neutralization of Special Elements used in an SQL Command",
					"description": "SQL injection description",
					"url":         "https://cwe.mitre.org/data/definitions/89.html",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理类别请求
	handler.HandleFunc("/cwe/category/189", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"categories": []map[string]interface{}{
				{
					"id":          "CWE-189",
					"name":        "Numeric Errors",
					"description": "Weaknesses in this category are related to improper calculation or conversion of numbers.",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理视图请求
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"views": []map[string]interface{}{
				{
					"id":          "CWE-1000",
					"name":        "Research Concepts",
					"description": "CWE-1000: Research Concepts",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理子节点请求
	handler.HandleFunc("/cwe/74/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "80"})
	})

	// 处理父节点请求
	handler.HandleFunc("/cwe/89/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 处理祖先节点请求
	handler.HandleFunc("/cwe/89/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	// 处理后代节点请求
	handler.HandleFunc("/cwe/20/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 处理空结果
	handler.HandleFunc("/cwe/999/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 处理错误请求
	handler.HandleFunc("/cwe/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(handler)
}

func TestNewAPIClient(t *testing.T) {
	client := NewAPIClient()

	if client.client == nil {
		t.Error("Expected HTTP client to be initialized")
	}

	if client.baseURL != BaseURL {
		t.Errorf("Expected baseURL to be %s, got %s", BaseURL, client.baseURL)
	}

	// 获取底层HTTPClient的超时设置
	httpClient := client.GetClient()
	if httpClient.GetClient().Timeout != DefaultTimeout {
		t.Errorf("Expected timeout to be %v, got %v", DefaultTimeout, httpClient.GetClient().Timeout)
	}
}

func TestNewAPIClientWithOptions(t *testing.T) {
	customURL := "https://custom-api.example.com"
	customTimeout := 60 * time.Second
	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)

	client := NewAPIClientWithOptions(customURL, customTimeout, rateLimiter)

	if client.baseURL != customURL {
		t.Errorf("Expected baseURL to be %s, got %s", customURL, client.baseURL)
	}

	// 获取底层HTTPClient的超时设置
	httpClient := client.GetClient()
	if httpClient.GetClient().Timeout != customTimeout {
		t.Errorf("Expected timeout to be %v, got %v", customTimeout, httpClient.GetClient().Timeout)
	}

	// Test with empty values (should use defaults)
	defaultRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client = NewAPIClientWithOptions("", 0, defaultRateLimiter)

	if client.baseURL != BaseURL {
		t.Errorf("Expected default baseURL to be %s, got %s", BaseURL, client.baseURL)
	}

	// 获取底层HTTPClient的超时设置
	httpClient = client.GetClient()
	if httpClient.GetClient().Timeout != DefaultTimeout {
		t.Errorf("Expected default timeout to be %v, got %v", DefaultTimeout, httpClient.GetClient().Timeout)
	}
}

func TestGetVersion(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	version, err := client.GetVersion()
	if err != nil {
		t.Errorf("GetVersion failed: %v", err)
	}

	if version.Version != "4.7" {
		t.Errorf("Expected version to be 4.7, got %s", version.Version)
	}
}

func TestGetCWEs(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	// Test with valid IDs
	result, err := client.GetCWEs([]string{"74", "79"})
	if err != nil {
		t.Errorf("GetCWEs failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected result to have 2 items, got %d", len(result))
	}

	// Test with empty IDs
	_, err = client.GetCWEs([]string{})
	if err == nil {
		t.Error("Expected error for empty IDs, got none")
	}

	// Test with invalid URL
	badRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client = NewAPIClientWithOptions("http://invalid-url", DefaultTimeout, badRateLimiter)
	_, err = client.GetCWEs([]string{"74", "79"})
	if err == nil {
		t.Error("Expected error for invalid URL, got none")
	}
}

func TestGetWeakness(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	result, err := client.GetWeakness("89")
	if err != nil {
		t.Errorf("GetWeakness failed: %v", err)
	}

	if result.ID != "CWE-89" {
		t.Errorf("Expected ID to be CWE-89, got %v", result.ID)
	}

	if result.Name != "Improper Neutralization of Special Elements used in an SQL Command" {
		t.Errorf("Expected name to match, got %v", result.Name)
	}

	// Test with invalid ID
	badRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client = NewAPIClientWithOptions(server.URL, DefaultTimeout, badRateLimiter)
	_, err = client.GetWeakness("invalid")
	if err == nil {
		t.Error("Expected error for invalid ID, got none")
	}
}

func TestGetCategory(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	result, err := client.GetCategory("189")
	if err != nil {
		t.Errorf("GetCategory failed: %v", err)
	}

	if result.ID != "CWE-189" {
		t.Errorf("Expected ID to be CWE-189, got %v", result.ID)
	}

	if result.Name != "Numeric Errors" {
		t.Errorf("Expected name to be 'Numeric Errors', got %v", result.Name)
	}
}

func TestGetView(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	result, err := client.GetView("1000")
	if err != nil {
		t.Errorf("GetView failed: %v", err)
	}

	if result.ID != "CWE-1000" {
		t.Errorf("Expected ID to be CWE-1000, got %v", result.ID)
	}

	if result.Name != "Research Concepts" {
		t.Errorf("Expected name to be 'Research Concepts', got %v", result.Name)
	}
}

func TestGetChildren(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	// Test with valid ID
	result, err := client.GetChildren("74", "")
	if err != nil {
		t.Errorf("GetChildren failed: %v", err)
	}

	expected := []string{"79", "80"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected children to be %v, got %v", expected, result)
	}

	// Test with view parameter
	result, err = client.GetChildren("74", "1000")
	if err != nil {
		t.Errorf("GetChildren with view failed: %v", err)
	}

	// Test with empty result
	result, err = client.GetChildren("999", "")
	if err != nil {
		t.Errorf("GetChildren for empty result failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected empty result, got %v", result)
	}
}

func TestGetParents(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	result, err := client.GetParents("89", "")
	if err != nil {
		t.Errorf("GetParents failed: %v", err)
	}

	expected := []string{"20"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected parents to be %v, got %v", expected, result)
	}
}

func TestGetAncestors(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	result, err := client.GetAncestors("89", "")
	if err != nil {
		t.Errorf("GetAncestors failed: %v", err)
	}

	expected := []string{"20", "1000"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected ancestors to be %v, got %v", expected, result)
	}
}

func TestGetDescendants(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	result, err := client.GetDescendants("20", "")
	if err != nil {
		t.Errorf("GetDescendants failed: %v", err)
	}

	expected := []string{"79", "89"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected descendants to be %v, got %v", expected, result)
	}
}

func TestErrorHandling(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	// Test with invalid endpoint
	_, err := client.GetWeakness("invalid")
	if err == nil {
		t.Error("Expected error for invalid endpoint, got none")
	}

	// Test with server error
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badServer.Close()

	badClient := NewAPIClientWithOptions(badServer.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetVersion()
	if err == nil {
		t.Error("Expected error for server error, got none")
	}

	// Test with invalid JSON response
	invalidJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer invalidJSONServer.Close()

	invalidJSONClient := NewAPIClientWithOptions(invalidJSONServer.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = invalidJSONClient.GetVersion()
	if err == nil {
		t.Error("Expected error for invalid JSON, got none")
	}
}

// 创建专门用于测试版本相关API的测试服务器
func setupVersionTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// 正常版本响应
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "4.9",
		})
	})

	// 多字段版本响应
	handler.HandleFunc("/cwe/version/extended", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":  "4.9",
			"released": "2023-11-15",
			"notes":    "This version includes new weaknesses",
			"status":   "stable",
		})
	})

	// 格式错误的版本响应
	handler.HandleFunc("/cwe/version/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{malformed json`))
	})

	// 结构错误的版本响应
	handler.HandleFunc("/cwe/version/wrongstructure", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"Not an object"})
	})

	// 缺少版本字段的响应
	handler.HandleFunc("/cwe/version/missing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"other": "data",
		})
	})

	// 服务器错误
	handler.HandleFunc("/cwe/version/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	return httptest.NewServer(handler)
}

// TestGetVersionComprehensive 测试GetVersion方法的各种场景
func TestGetVersionComprehensive(t *testing.T) {
	server := setupVersionTestServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)

	// Test normal response
	version, err := client.GetVersion()
	if err != nil {
		t.Errorf("GetVersion failed: %v", err)
	}
	if version.Version != "4.9" {
		t.Errorf("Expected version 4.9, got %s", version.Version)
	}

	// Test with invalid server URL
	badRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	badClient := NewAPIClientWithOptions("http://invalid-url", DefaultTimeout, badRateLimiter)
	_, err = badClient.GetVersion()
	if err == nil {
		t.Error("Expected error for invalid URL, got none")
	}
}

// TestGetCurrentVersionDetailed 测试DataFetcher的GetCurrentVersion方法
func TestGetCurrentVersionDetailed(t *testing.T) {
	server := setupDetailedTestServer()
	defer server.Close()

	rateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, rateLimiter)
	fetcher := NewDataFetcherWithClient(client)

	version, err := fetcher.GetCurrentVersion()
	if err != nil {
		t.Errorf("GetCurrentVersion failed: %v", err)
	}
	if version != "4.9" {
		t.Errorf("Expected version 4.9, got %s", version)
	}

	// Test with invalid server URL
	badRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	badClient := NewAPIClientWithOptions("http://invalid-url", DefaultTimeout, badRateLimiter)
	badFetcher := NewDataFetcherWithClient(badClient)
	_, err = badFetcher.GetCurrentVersion()
	if err == nil {
		t.Error("Expected error for invalid URL, got none")
	}
}

// 创建详细的测试服务器，专门测试所有API方法
func setupDetailedTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// 处理版本请求
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "4.9",
		})
	})

	// 处理弱点请求
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"weaknesses": []*CWEWeakness{
				{
					ID:   "CWE-89",
					Name: "SQL Injection",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理类别请求
	handler.HandleFunc("/cwe/category/189", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"categories": []*CWECategory{
				{
					ID:   "CWE-189",
					Name: "Numeric Errors",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理视图请求
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"views": []*CWEView{
				{
					ID:   "CWE-1000",
					Name: "Research Concepts",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	return httptest.NewServer(handler)
}

// 测试API客户端的各种方法
func TestAPIClientMethods(t *testing.T) {
	server := setupDetailedTestServer()
	defer server.Close()

	// Test GetWeakness
	testRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	testClient := NewAPIClientWithOptions(server.URL, DefaultTimeout, testRateLimiter)
	weakness, err := testClient.GetWeakness("89")
	if err != nil {
		t.Errorf("GetWeakness failed: %v", err)
	}
	if weakness.ID != "CWE-89" {
		t.Errorf("Expected ID CWE-89, got %s", weakness.ID)
	}

	// Test GetCategory
	categoryRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	categoryClient := NewAPIClientWithOptions(server.URL, DefaultTimeout, categoryRateLimiter)
	category, err := categoryClient.GetCategory("189")
	if err != nil {
		t.Errorf("GetCategory failed: %v", err)
	}
	if category.ID != "CWE-189" {
		t.Errorf("Expected ID CWE-189, got %s", category.ID)
	}

	// Test GetView
	viewRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	viewClient := NewAPIClientWithOptions(server.URL, DefaultTimeout, viewRateLimiter)
	view, err := viewClient.GetView("1000")
	if err != nil {
		t.Errorf("GetView failed: %v", err)
	}
	if view.ID != "CWE-1000" {
		t.Errorf("Expected ID CWE-1000, got %s", view.ID)
	}

	// Test error cases
	errorRateLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
	errorClient := NewAPIClientWithOptions("http://invalid-url", DefaultTimeout, errorRateLimiter)
	_, err = errorClient.GetWeakness("invalid")
	if err == nil {
		t.Error("Expected error for invalid weakness ID, got none")
	}
}

// 辅助函数：检查字符串是否在切片中
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
