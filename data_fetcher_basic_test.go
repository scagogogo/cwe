package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 创建一个模拟服务器用于测试基本获取功能
func setupBasicFetchMockServer() *httptest.Server {
	handler := http.NewServeMux()

	// 弱点请求 (SQL注入)
	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize special elements that could modify the intended SQL command when it is sent to a downstream component.",
			"url":         "https://cwe.mitre.org/data/definitions/89.html",
			"mitigations": []string{
				"Use parameterized queries",
				"Use input validation",
			},
			"examples": []string{
				"Example 1: SQL injection in PHP",
				"Example 2: SQL injection in Java",
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 弱点请求 - 使用CWE-前缀
	handler.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize special elements that could modify the intended SQL command when it is sent to a downstream component.",
			"url":         "https://cwe.mitre.org/data/definitions/89.html",
			"mitigations": []string{
				"Use parameterized queries",
				"Use input validation",
			},
			"examples": []string{
				"Example 1: SQL injection in PHP",
				"Example 2: SQL injection in Java",
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 类别请求
	handler.HandleFunc("/cwe/category/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 类别请求 - 使用CWE-前缀
	handler.HandleFunc("/cwe/category/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 视图请求
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "This view organizes weaknesses around a concept, which can help identify complex relationships.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 视图请求 - 使用CWE-前缀
	handler.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "This view organizes weaknesses around a concept, which can help identify complex relationships.",
		}
		json.NewEncoder(w).Encode(response)
	})

	return httptest.NewServer(handler)
}

func TestFetchWeakness(t *testing.T) {
	server := setupBasicFetchMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	cwe, err := fetcher.FetchWeakness("89")
	if err != nil {
		t.Errorf("FetchWeakness failed: %v", err)
		return // 防止空指针错误
	}

	// 验证基本信息
	if cwe.ID != "CWE-89" {
		t.Errorf("Expected ID to be CWE-89, got %s", cwe.ID)
	}

	if cwe.Name != "SQL Injection" {
		t.Errorf("Expected name to be 'SQL Injection', got %s", cwe.Name)
	}

	// 验证附加信息
	if len(cwe.Mitigations) != 2 {
		t.Errorf("Expected 2 mitigations, got %d", len(cwe.Mitigations))
	}

	if len(cwe.Examples) != 2 {
		t.Errorf("Expected 2 examples, got %d", len(cwe.Examples))
	}

	// 测试错误处理
	_, err = fetcher.FetchWeakness("")
	if err == nil {
		t.Error("Expected error for empty ID, got none")
	}
}

func TestFetchCategory(t *testing.T) {
	server := setupBasicFetchMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	cwe, err := fetcher.FetchCategory("20")
	if err != nil {
		t.Errorf("FetchCategory failed: %v", err)
		return
	}

	if cwe.ID != "CWE-20" {
		t.Errorf("Expected ID to be CWE-20, got %s", cwe.ID)
	}

	if cwe.Name != "Improper Input Validation" {
		t.Errorf("Expected name to be 'Improper Input Validation', got %s", cwe.Name)
	}
}

func TestFetchView(t *testing.T) {
	server := setupBasicFetchMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	cwe, err := fetcher.FetchView("1000")
	if err != nil {
		t.Errorf("FetchView failed: %v", err)
		return
	}

	if cwe.ID != "CWE-1000" {
		t.Errorf("Expected ID to be CWE-1000, got %s", cwe.ID)
	}

	if cwe.Name != "Research Concepts" {
		t.Errorf("Expected name to be 'Research Concepts', got %s", cwe.Name)
	}
}

func TestFetchCWEByIDWithRelations(t *testing.T) {
	server := setupFetchRelationsTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	cwe, err := fetcher.FetchCWEByIDWithRelations("20", "1000")
	if err != nil {
		t.Errorf("FetchCWEByIDWithRelations failed: %v", err)
		return
	}

	if cwe.ID != "CWE-20" {
		t.Errorf("Expected ID to be CWE-20, got %s", cwe.ID)
	}

	if len(cwe.Children) != 2 {
		t.Errorf("Expected 2 children, got %d", len(cwe.Children))
	}
}

// 用于测试关系功能的模拟服务器
func setupFetchRelationsTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// 设置基本的弱点和类别
	handler.HandleFunc("/cwe/weakness/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate or incorrectly validates input.",
		})
	})

	handler.HandleFunc("/cwe/category/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate or incorrectly validates input.",
		})
	})

	handler.HandleFunc("/cwe/view/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate or incorrectly validates input.",
		})
	})

	// 设置子节点关系
	handler.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	handler.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 子节点的信息
	handler.HandleFunc("/cwe/weakness/79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-79",
			"name":        "Cross-site Scripting",
			"description": "XSS vulnerability",
		})
	})

	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "SQL injection vulnerability",
		})
	})

	// 叶子节点没有子节点
	handler.HandleFunc("/cwe/79/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	handler.HandleFunc("/cwe/89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	return httptest.NewServer(handler)
}
