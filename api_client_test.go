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
			"74": map[string]string{
				"id":   "CWE-74",
				"name": "Improper Neutralization of Special Elements in Output Used by a Downstream Component",
			},
			"79": map[string]string{
				"id":   "CWE-79",
				"name": "Improper Neutralization of Input During Web Page Generation",
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理弱点请求
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-89",
			"name":        "Improper Neutralization of Special Elements used in an SQL Command",
			"description": "SQL injection description",
			"url":         "https://cwe.mitre.org/data/definitions/89.html",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理类别请求
	handler.HandleFunc("/cwe/category/189", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-189",
			"name":        "Numeric Errors",
			"description": "Weaknesses in this category are related to improper calculation or conversion of numbers.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理视图请求
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "CWE-1000: Research Concepts",
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

	if client.client.Timeout != DefaultTimeout {
		t.Errorf("Expected timeout to be %v, got %v", DefaultTimeout, client.client.Timeout)
	}
}

func TestNewAPIClientWithOptions(t *testing.T) {
	customURL := "https://custom-api.example.com"
	customTimeout := 60 * time.Second

	client := NewAPIClientWithOptions(customURL, customTimeout)

	if client.baseURL != customURL {
		t.Errorf("Expected baseURL to be %s, got %s", customURL, client.baseURL)
	}

	if client.client.Timeout != customTimeout {
		t.Errorf("Expected timeout to be %v, got %v", customTimeout, client.client.Timeout)
	}

	// Test with empty values (should use defaults)
	client = NewAPIClientWithOptions("", 0)

	if client.baseURL != BaseURL {
		t.Errorf("Expected default baseURL to be %s, got %s", BaseURL, client.baseURL)
	}

	if client.client.Timeout != DefaultTimeout {
		t.Errorf("Expected default timeout to be %v, got %v", DefaultTimeout, client.client.Timeout)
	}
}

func TestGetVersion(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	version, err := client.GetVersion()
	if err != nil {
		t.Errorf("GetVersion failed: %v", err)
	}

	if version != "4.7" {
		t.Errorf("Expected version to be 4.7, got %s", version)
	}
}

func TestGetCWEs(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

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
	client = NewAPIClientWithOptions("http://invalid-url", DefaultTimeout)
	_, err = client.GetCWEs([]string{"74", "79"})
	if err == nil {
		t.Error("Expected error for invalid URL, got none")
	}
}

func TestGetWeakness(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	result, err := client.GetWeakness("89")
	if err != nil {
		t.Errorf("GetWeakness failed: %v", err)
	}

	if result["id"] != "CWE-89" {
		t.Errorf("Expected ID to be CWE-89, got %v", result["id"])
	}

	if result["name"] != "Improper Neutralization of Special Elements used in an SQL Command" {
		t.Errorf("Expected name to match, got %v", result["name"])
	}

	// Test with invalid ID
	client = NewAPIClientWithOptions(server.URL, DefaultTimeout)
	_, err = client.GetWeakness("invalid")
	if err == nil {
		t.Error("Expected error for invalid ID, got none")
	}
}

func TestGetCategory(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	result, err := client.GetCategory("189")
	if err != nil {
		t.Errorf("GetCategory failed: %v", err)
	}

	if result["id"] != "CWE-189" {
		t.Errorf("Expected ID to be CWE-189, got %v", result["id"])
	}

	if result["name"] != "Numeric Errors" {
		t.Errorf("Expected name to be 'Numeric Errors', got %v", result["name"])
	}
}

func TestGetView(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	result, err := client.GetView("1000")
	if err != nil {
		t.Errorf("GetView failed: %v", err)
	}

	if result["id"] != "CWE-1000" {
		t.Errorf("Expected ID to be CWE-1000, got %v", result["id"])
	}

	if result["name"] != "Research Concepts" {
		t.Errorf("Expected name to be 'Research Concepts', got %v", result["name"])
	}
}

func TestGetChildren(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

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

	badClient := NewAPIClientWithOptions(badServer.URL, DefaultTimeout)
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

	invalidJSONClient := NewAPIClientWithOptions(invalidJSONServer.URL, DefaultTimeout)
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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试正常版本获取
	version, err := client.GetVersion()
	if err != nil {
		t.Errorf("GetVersion failed for normal case: %v", err)
	}
	if version != "4.9" {
		t.Errorf("Expected version 4.9, got %s", version)
	}

	// 测试URL路径问题
	badClient := NewAPIClientWithOptions(server.URL+"/invalid", DefaultTimeout)
	_, err = badClient.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail for invalid URL path")
	}

	// 创建恶意客户端，用于测试响应处理边缘情况
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cwe/version/malformed" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{malformed json`))
			return
		}
		if r.URL.Path == "/cwe/version/wrongstructure" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]string{"Not an object"})
			return
		}
		if r.URL.Path == "/cwe/version/missing" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"other": "data"})
			return
		}
		if r.URL.Path == "/cwe/version/error" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
	mockServer := httptest.NewServer(mockHandler)
	defer mockServer.Close()

	// 测试格式错误
	malformedClient := NewAPIClientWithOptions(mockServer.URL, DefaultTimeout)
	malformedClient.baseURL = mockServer.URL + "/cwe/version/malformed"
	_, err = malformedClient.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail for malformed JSON")
	}

	// 测试错误的响应结构
	wrongStructureClient := NewAPIClientWithOptions(mockServer.URL, DefaultTimeout)
	wrongStructureClient.baseURL = mockServer.URL + "/cwe/version/wrongstructure"
	_, err = wrongStructureClient.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail for wrong response structure")
	}

	// 测试缺少版本字段
	missingClient := NewAPIClientWithOptions(mockServer.URL, DefaultTimeout)
	missingClient.baseURL = mockServer.URL + "/cwe/version/missing"
	_, err = missingClient.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail when version field is missing")
	}

	// 测试服务器错误
	errorClient := NewAPIClientWithOptions(mockServer.URL, DefaultTimeout)
	errorClient.baseURL = mockServer.URL + "/cwe/version/error"
	_, err = errorClient.GetVersion()
	if err == nil {
		t.Error("GetVersion should fail for server error")
	}
}

// TestGetCurrentVersionDetailed 测试DataFetcher的GetCurrentVersion方法
func TestGetCurrentVersionDetailed(t *testing.T) {
	server := setupVersionTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试正常版本获取
	version, err := fetcher.GetCurrentVersion()
	if err != nil {
		t.Errorf("GetCurrentVersion failed: %v", err)
	}
	if version != "4.9" {
		t.Errorf("Expected version 4.9, got %s", version)
	}

	// 创建错误客户端
	errorClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout)
	errorFetcher := NewDataFetcherWithClient(errorClient)

	// 测试错误情况
	_, err = errorFetcher.GetCurrentVersion()
	if err == nil {
		t.Error("GetCurrentVersion should fail for connection error")
	}
}

// 创建详细的测试服务器，专门测试所有API方法
func setupDetailedTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// 版本信息
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "4.9",
		})
	})

	// 弱点信息 - 支持两种ID格式
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "This vulnerability occurs when unsanitized input is used in SQL queries.",
			"severity":    "High",
		})
	})

	// 支持规范化的CWE-ID格式
	handler.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "This vulnerability occurs when unsanitized input is used in SQL queries.",
			"severity":    "High",
		})
	})

	// 类别信息 - 支持两种ID格式
	handler.HandleFunc("/cwe/category/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "Input validation errors occur when a program does not properly validate input.",
			"severity":    "Medium",
		})
	})

	handler.HandleFunc("/cwe/category/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "Input validation errors occur when a program does not properly validate input.",
			"severity":    "Medium",
		})
	})

	// 视图信息 - 支持两种ID格式
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "Research concepts view.",
			"severity":    "Low",
		})
	})

	handler.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "Research concepts view.",
			"severity":    "Low",
		})
	})

	// 父节点 - 支持两种ID格式
	handler.HandleFunc("/cwe/89/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	handler.HandleFunc("/cwe/CWE-89/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 带视图的父节点
	handler.HandleFunc("/cwe/89/parents/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	handler.HandleFunc("/cwe/CWE-89/parents/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 子节点 - 支持两种ID格式
	handler.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	handler.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 带视图的子节点
	handler.HandleFunc("/cwe/20/children/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	handler.HandleFunc("/cwe/CWE-20/children/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 祖先节点 - 支持两种ID格式
	handler.HandleFunc("/cwe/89/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	handler.HandleFunc("/cwe/CWE-89/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	// 带视图的祖先节点
	handler.HandleFunc("/cwe/89/ancestors/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	handler.HandleFunc("/cwe/CWE-89/ancestors/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	// 后代节点 - 支持两种ID格式
	handler.HandleFunc("/cwe/20/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	handler.HandleFunc("/cwe/CWE-20/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 带视图的后代节点
	handler.HandleFunc("/cwe/20/descendants/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	handler.HandleFunc("/cwe/CWE-20/descendants/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 多CWE信息 - 支持各种ID格式组合
	handler.HandleFunc("/cwe/79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS vulnerability.",
			},
			"89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection vulnerability.",
			},
		})
	})

	handler.HandleFunc("/cwe/CWE-79,CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"CWE-79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS vulnerability.",
			},
			"CWE-89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection vulnerability.",
			},
		})
	})

	// 添加针对FetchCWEByIDWithRelations的路径
	handler.HandleFunc("/cwe/1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	handler.HandleFunc("/cwe/CWE-1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	handler.HandleFunc("/cwe/weakness/79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-79",
			"name":        "Cross-site Scripting",
			"description": "XSS vulnerability.",
			"severity":    "High",
		})
	})

	handler.HandleFunc("/cwe/weakness/CWE-79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-79",
			"name":        "Cross-site Scripting",
			"description": "XSS vulnerability.",
			"severity":    "High",
		})
	})

	// 错误情况
	handler.HandleFunc("/cwe/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	return httptest.NewServer(handler)
}

// 测试API客户端的各种方法
func TestAPIClientMethods(t *testing.T) {
	server := setupDetailedTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试GetVersion
	version, err := client.GetVersion()
	if err != nil {
		t.Errorf("GetVersion failed: %v", err)
	}
	if version != "4.9" {
		t.Errorf("Expected version 4.9, got %s", version)
	}

	// 测试GetWeakness
	weakness, err := client.GetWeakness("89")
	if err != nil {
		t.Errorf("GetWeakness failed: %v", err)
	}
	if weakness["id"] != "CWE-89" {
		t.Errorf("Expected id CWE-89, got %s", weakness["id"])
	}

	// 测试GetCategory
	category, err := client.GetCategory("20")
	if err != nil {
		t.Errorf("GetCategory failed: %v", err)
	}
	if category["id"] != "CWE-20" {
		t.Errorf("Expected id CWE-20, got %s", category["id"])
	}

	// 测试GetView
	view, err := client.GetView("1000")
	if err != nil {
		t.Errorf("GetView failed: %v", err)
	}
	if view["id"] != "CWE-1000" {
		t.Errorf("Expected id CWE-1000, got %s", view["id"])
	}

	// 测试GetParents，不带视图
	parents, err := client.GetParents("89", "")
	if err != nil {
		t.Errorf("GetParents failed: %v", err)
	}
	if len(parents) != 1 || parents[0] != "20" {
		t.Errorf("Expected parent [20], got %v", parents)
	}

	// 测试GetParents，带视图
	parents, err = client.GetParents("89", "1000")
	if err != nil {
		t.Errorf("GetParents with view failed: %v", err)
	}
	if len(parents) != 1 || parents[0] != "20" {
		t.Errorf("Expected parent [20], got %v", parents)
	}

	// 测试GetChildren，不带视图
	children, err := client.GetChildren("20", "")
	if err != nil {
		t.Errorf("GetChildren failed: %v", err)
	}
	if len(children) != 2 || !contains(children, "79") || !contains(children, "89") {
		t.Errorf("Expected children [79,89], got %v", children)
	}

	// 测试GetChildren，带视图
	children, err = client.GetChildren("20", "1000")
	if err != nil {
		t.Errorf("GetChildren with view failed: %v", err)
	}
	if len(children) != 2 || !contains(children, "79") || !contains(children, "89") {
		t.Errorf("Expected children [79,89], got %v", children)
	}

	// 测试GetAncestors，不带视图
	ancestors, err := client.GetAncestors("89", "")
	if err != nil {
		t.Errorf("GetAncestors failed: %v", err)
	}
	if len(ancestors) != 2 || !contains(ancestors, "20") || !contains(ancestors, "1000") {
		t.Errorf("Expected ancestors [20,1000], got %v", ancestors)
	}

	// 测试GetAncestors，带视图
	ancestors, err = client.GetAncestors("89", "1000")
	if err != nil {
		t.Errorf("GetAncestors with view failed: %v", err)
	}
	if len(ancestors) != 2 || !contains(ancestors, "20") || !contains(ancestors, "1000") {
		t.Errorf("Expected ancestors [20,1000], got %v", ancestors)
	}

	// 测试GetDescendants，不带视图
	descendants, err := client.GetDescendants("20", "")
	if err != nil {
		t.Errorf("GetDescendants failed: %v", err)
	}
	if len(descendants) != 2 || !contains(descendants, "79") || !contains(descendants, "89") {
		t.Errorf("Expected descendants [79,89], got %v", descendants)
	}

	// 测试GetDescendants，带视图
	descendants, err = client.GetDescendants("20", "1000")
	if err != nil {
		t.Errorf("GetDescendants with view failed: %v", err)
	}
	if len(descendants) != 2 || !contains(descendants, "79") || !contains(descendants, "89") {
		t.Errorf("Expected descendants [79,89], got %v", descendants)
	}

	// 测试GetCWEs
	cwes, err := client.GetCWEs([]string{"79", "89"})
	if err != nil {
		t.Errorf("GetCWEs failed: %v", err)
	}
	if len(cwes) != 2 {
		t.Errorf("Expected 2 CWEs, got %d", len(cwes))
	}

	// 修复类型断言
	if cwe79, ok := cwes["79"].(map[string]interface{}); !ok {
		t.Errorf("Expected cwes[79] to be map[string]interface{}, got %T", cwes["79"])
	} else if cwe79["name"] != "Cross-site Scripting" {
		t.Errorf("Expected name Cross-site Scripting, got %s", cwe79["name"])
	}

	if cwe89, ok := cwes["89"].(map[string]interface{}); !ok {
		t.Errorf("Expected cwes[89] to be map[string]interface{}, got %T", cwes["89"])
	} else if cwe89["name"] != "SQL Injection" {
		t.Errorf("Expected name SQL Injection, got %s", cwe89["name"])
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
