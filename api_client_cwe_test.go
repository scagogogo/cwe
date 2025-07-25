// 该文件包含对api_client_cwe.go中的视图相关API进行的测试
package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// setupViewTestServer 创建专门测试视图相关方法的测试服务器
func setupViewTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// 正常视图响应
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"views": []map[string]interface{}{
				{
					"id":          "CWE-1000",
					"name":        "Research Concepts",
					"description": "Top level research view",
					"url":         "https://cwe.mitre.org/data/definitions/1000.html",
					"severity":    "Informational",
				},
			},
		})
	})

	// 规范化的ID响应
	handler.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"views": []map[string]interface{}{
				{
					"id":          "CWE-1000",
					"name":        "Research Concepts",
					"description": "Top level research view",
					"url":         "https://cwe.mitre.org/data/definitions/1000.html",
					"severity":    "Informational",
				},
			},
		})
	})

	// 非法视图ID
	handler.HandleFunc("/cwe/view/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "View not found"}`))
	})

	// 空ID
	handler.HandleFunc("/cwe/view/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "View ID required"}`))
	})

	// 格式错误的JSON
	handler.HandleFunc("/cwe/view/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "CWE-malformed", "name": "Malformed JSON response"`))
	})

	// 缺少ID字段的响应
	handler.HandleFunc("/cwe/view/noid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"views": []map[string]interface{}{
				{
					"name":        "No ID View",
					"description": "This view response is missing ID field",
				},
			},
		})
	})

	// 服务器错误
	handler.HandleFunc("/cwe/view/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	})

	return httptest.NewServer(handler)
}

// TestGetViewComprehensive 全面测试GetView方法
func TestGetViewComprehensive(t *testing.T) {
	server := setupViewTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// 测试正常获取
	view, err := client.GetView("1000")
	if err != nil {
		t.Errorf("GetView failed for normal case: %v", err)
	}
	if view.ID != "CWE-1000" {
		t.Errorf("Expected id CWE-1000, got %s", view.ID)
	}
	if view.Name != "Research Concepts" {
		t.Errorf("Expected name Research Concepts, got %s", view.Name)
	}

	// 测试规范化的ID
	view, err = client.GetView("CWE-1000")
	if err != nil {
		t.Errorf("GetView failed for normalized ID: %v", err)
	}
	if view.ID != "CWE-1000" {
		t.Errorf("Expected id CWE-1000, got %s", view.ID)
	}

	// 测试无效的ID
	_, err = client.GetView("invalid")
	if err == nil {
		t.Error("GetView should fail for invalid ID")
	}

	// 测试空ID
	_, err = client.GetView("")
	if err == nil {
		t.Error("GetView should fail for empty ID")
	}

	// 测试格式错误的响应
	_, err = client.GetView("malformed")
	if err == nil {
		t.Error("GetView should fail for malformed response")
	}

	// 测试缺少ID字段的响应
	_, err = client.GetView("noid")
	if err == nil {
		t.Error("GetView should fail for response missing ID field")
	}

	// 测试服务器错误
	_, err = client.GetView("error")
	if err == nil {
		t.Error("GetView should fail for server error")
	}

	// 测试连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetView("1000")
	if err == nil {
		t.Error("GetView should fail for connection error")
	}
}

// TestFetchViewComprehensive 全面测试FetchView方法
func TestFetchViewComprehensive(t *testing.T) {
	server := setupViewTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))
	fetcher := NewDataFetcherWithClient(client)

	// 测试正常获取
	view, err := fetcher.FetchView("1000")
	if err != nil {
		t.Errorf("FetchView failed for normal case: %v", err)
	}
	if view == nil {
		t.Fatal("FetchView returned nil CWE")
	}
	if view.ID != "CWE-1000" {
		t.Errorf("Expected ID CWE-1000, got %s", view.ID)
	}
	if view.Name != "Research Concepts" {
		t.Errorf("Expected name Research Concepts, got %s", view.Name)
	}

	// 测试规范化的ID
	view, err = fetcher.FetchView("CWE-1000")
	if err != nil {
		t.Errorf("FetchView failed for normalized ID: %v", err)
	}
	if view.ID != "CWE-1000" {
		t.Errorf("Expected ID CWE-1000, got %s", view.ID)
	}

	// 测试无效的ID
	_, err = fetcher.FetchView("invalid")
	if err == nil {
		t.Error("FetchView should fail for invalid ID")
	}

	// 测试空ID
	_, err = fetcher.FetchView("")
	if err == nil {
		t.Error("FetchView should fail for empty ID")
	}

	// 测试格式错误的响应
	_, err = fetcher.FetchView("malformed")
	if err == nil {
		t.Error("FetchView should fail for malformed response")
	}

	// 测试服务器错误
	_, err = fetcher.FetchView("error")
	if err == nil {
		t.Error("FetchView should fail for server error")
	}

	// 测试连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	badFetcher := NewDataFetcherWithClient(badClient)
	_, err = badFetcher.FetchView("1000")
	if err == nil {
		t.Error("FetchView should fail for connection error")
	}
}

// ***********************************************
// 以下是对api_client_cwe.go中Weakness相关API的测试
// ***********************************************

// setupWeaknessTestServer 创建专门测试弱点相关方法的测试服务器
func setupWeaknessTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// GetWeakness API
	// 正常响应
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-89",
					"name":        "SQL Injection",
					"description": "SQL injection vulnerability.",
					"severity":    "High",
				},
			},
		})
	})

	// 规范化的ID响应
	handler.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-89",
					"name":        "SQL Injection",
					"description": "SQL injection vulnerability.",
					"severity":    "High",
				},
			},
		})
	})

	// 无效ID
	handler.HandleFunc("/cwe/weakness/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Weakness not found"}`))
	})

	// 空ID
	handler.HandleFunc("/cwe/weakness/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Weakness ID required"}`))
	})

	// 格式错误的JSON
	handler.HandleFunc("/cwe/weakness/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "CWE-malformed", "name": "Malformed JSON response"`))
	})

	// 缺少字段
	handler.HandleFunc("/cwe/weakness/missing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"name": "Missing Fields",
				},
			},
		})
	})

	// 服务器错误
	handler.HandleFunc("/cwe/weakness/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	})

	// GetCategory API
	// 正常响应
	handler.HandleFunc("/cwe/category/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"categories": []map[string]interface{}{
				{
					"id":          "CWE-20",
					"name":        "Improper Input Validation",
					"description": "The product does not validate input properly.",
					"severity":    "Medium",
				},
			},
		})
	})

	// 规范化的ID响应
	handler.HandleFunc("/cwe/category/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"categories": []map[string]interface{}{
				{
					"id":          "CWE-20",
					"name":        "Improper Input Validation",
					"description": "The product does not validate input properly.",
					"severity":    "Medium",
				},
			},
		})
	})

	// 无效ID
	handler.HandleFunc("/cwe/category/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Category not found"}`))
	})

	// 空ID
	handler.HandleFunc("/cwe/category/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Category ID required"}`))
	})

	// 格式错误的JSON
	handler.HandleFunc("/cwe/category/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "CWE-malformed", "name": "Malformed JSON response"`))
	})

	// 缺少ID字段
	handler.HandleFunc("/cwe/category/missing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"categories": []map[string]interface{}{
				{
					"name": "Missing Fields",
				},
			},
		})
	})

	// 服务器错误
	handler.HandleFunc("/cwe/category/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	})

	return httptest.NewServer(handler)
}

// TestGetWeaknessComprehensive 全面测试GetWeakness方法
func TestGetWeaknessComprehensive(t *testing.T) {
	server := setupWeaknessTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// 测试正常获取
	weakness, err := client.GetWeakness("89")
	if err != nil {
		t.Errorf("GetWeakness failed for normal case: %v", err)
	}
	if weakness.ID != "CWE-89" {
		t.Errorf("Expected id CWE-89, got %s", weakness.ID)
	}
	if weakness.Name != "SQL Injection" {
		t.Errorf("Expected name SQL Injection, got %s", weakness.Name)
	}
	if weakness.Description == "" {
		t.Error("Description should not be empty")
	}
	if weakness.Severity != "High" {
		t.Errorf("Expected severity High, got %s", weakness.Severity)
	}

	// 测试规范化的ID
	weakness, err = client.GetWeakness("CWE-89")
	if err != nil {
		t.Errorf("GetWeakness failed for normalized ID: %v", err)
	}
	if weakness.ID != "CWE-89" {
		t.Errorf("Expected id CWE-89, got %s", weakness.ID)
	}

	// 测试无效ID
	_, err = client.GetWeakness("invalid")
	if err == nil {
		t.Error("GetWeakness should fail for invalid ID")
	}

	// 测试空ID
	_, err = client.GetWeakness("")
	if err == nil {
		t.Error("GetWeakness should fail for empty ID")
	}

	// 测试格式错误的JSON
	_, err = client.GetWeakness("malformed")
	if err == nil {
		t.Error("GetWeakness should fail for malformed JSON")
	}

	// 测试缺少字段
	_, err = client.GetWeakness("missing")
	if err == nil {
		t.Error("GetWeakness should fail for response missing required fields")
	}

	// 测试服务器错误
	_, err = client.GetWeakness("error")
	if err == nil {
		t.Error("GetWeakness should fail for server error")
	}

	// 测试连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetWeakness("89")
	if err == nil {
		t.Error("GetWeakness should fail for connection error")
	}
}

// TestGetCategoryComprehensive 全面测试GetCategory方法
func TestGetCategoryComprehensive(t *testing.T) {
	server := setupWeaknessTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// 测试正常获取
	category, err := client.GetCategory("20")
	if err != nil {
		t.Errorf("GetCategory failed for normal case: %v", err)
	}
	if category.ID != "CWE-20" {
		t.Errorf("Expected id CWE-20, got %s", category.ID)
	}
	if category.Name != "Improper Input Validation" {
		t.Errorf("Expected name Improper Input Validation, got %s", category.Name)
	}
	if category.Description == "" {
		t.Error("Description should not be empty")
	}

	// 测试规范化的ID
	category, err = client.GetCategory("CWE-20")
	if err != nil {
		t.Errorf("GetCategory failed for normalized ID: %v", err)
	}
	if category.ID != "CWE-20" {
		t.Errorf("Expected id CWE-20, got %s", category.ID)
	}

	// 测试无效ID
	_, err = client.GetCategory("invalid")
	if err == nil {
		t.Error("GetCategory should fail for invalid ID")
	}

	// 测试空ID
	_, err = client.GetCategory("")
	if err == nil {
		t.Error("GetCategory should fail for empty ID")
	}

	// 测试格式错误的JSON
	_, err = client.GetCategory("malformed")
	if err == nil {
		t.Error("GetCategory should fail for malformed JSON")
	}

	// 测试缺少字段
	_, err = client.GetCategory("missing")
	if err == nil {
		t.Error("GetCategory should fail for response missing required fields")
	}

	// 测试服务器错误
	_, err = client.GetCategory("error")
	if err == nil {
		t.Error("GetCategory should fail for server error")
	}

	// 测试连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetCategory("20")
	if err == nil {
		t.Error("GetCategory should fail for connection error")
	}
}
