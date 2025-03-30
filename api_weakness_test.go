package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setupWeaknessTestServer 创建专门测试弱点相关方法的测试服务器
func setupWeaknessTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// GetWeakness API
	// 正常响应
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "SQL injection vulnerability.",
			"severity":    "High",
		})
	})

	// 规范化的ID响应
	handler.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "SQL injection vulnerability.",
			"severity":    "High",
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
			"name": "Missing Fields",
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
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate input properly.",
			"severity":    "Medium",
		})
	})

	// 规范化的ID响应
	handler.HandleFunc("/cwe/category/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate input properly.",
			"severity":    "Medium",
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
			"name": "Missing Fields",
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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试正常获取
	weakness, err := client.GetWeakness("89")
	if err != nil {
		t.Errorf("GetWeakness failed for normal case: %v", err)
	}
	if weakness["id"] != "CWE-89" {
		t.Errorf("Expected id CWE-89, got %s", weakness["id"])
	}
	if weakness["name"] != "SQL Injection" {
		t.Errorf("Expected name SQL Injection, got %s", weakness["name"])
	}

	// 测试规范化的ID
	weakness, err = client.GetWeakness("CWE-89")
	if err != nil {
		t.Errorf("GetWeakness failed for normalized ID: %v", err)
	}
	if weakness["id"] != "CWE-89" {
		t.Errorf("Expected id CWE-89, got %s", weakness["id"])
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
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout)
	_, err = badClient.GetWeakness("89")
	if err == nil {
		t.Error("GetWeakness should fail for connection error")
	}
}

// TestGetCategoryComprehensive 全面测试GetCategory方法
func TestGetCategoryComprehensive(t *testing.T) {
	server := setupWeaknessTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试正常获取
	category, err := client.GetCategory("20")
	if err != nil {
		t.Errorf("GetCategory failed for normal case: %v", err)
	}
	if category["id"] != "CWE-20" {
		t.Errorf("Expected id CWE-20, got %s", category["id"])
	}
	if category["name"] != "Improper Input Validation" {
		t.Errorf("Expected name Improper Input Validation, got %s", category["name"])
	}

	// 测试规范化的ID
	category, err = client.GetCategory("CWE-20")
	if err != nil {
		t.Errorf("GetCategory failed for normalized ID: %v", err)
	}
	if category["id"] != "CWE-20" {
		t.Errorf("Expected id CWE-20, got %s", category["id"])
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
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout)
	_, err = badClient.GetCategory("20")
	if err == nil {
		t.Error("GetCategory should fail for connection error")
	}
}
