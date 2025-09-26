package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 创建一个用于测试FetchMultiple的模拟服务器
func setupMultipleFetchServer() *httptest.Server {
	handler := http.NewServeMux()

	// 处理多个CWE的请求
	handler.HandleFunc("/cwe/79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"cwes": map[string]interface{}{
				"CWE-79": map[string]interface{}{
					"id":          "CWE-79",
					"name":        "Cross-site Scripting",
					"description": "XSS description",
				},
				"CWE-89": map[string]interface{}{
					"id":          "CWE-89",
					"name":        "SQL Injection",
					"description": "SQL injection description",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理多个CWE的请求 - 使用CWE-前缀
	handler.HandleFunc("/cwe/CWE-79,CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"cwes": map[string]interface{}{
				"CWE-79": map[string]interface{}{
					"id":          "CWE-79",
					"name":        "Cross-site Scripting",
					"description": "XSS description",
				},
				"CWE-89": map[string]interface{}{
					"id":          "CWE-89",
					"name":        "SQL Injection",
					"description": "SQL injection description",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	return httptest.NewServer(handler)
}

// TestFetchMultipleBasic 测试基本的多条目获取功能
func TestFetchMultipleBasic(t *testing.T) {
	server := setupMultipleFetchServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试获取多个CWE
	registry, err := fetcher.FetchMultiple([]string{"79", "89"})
	if err != nil {
		t.Errorf("FetchMultiple failed: %v", err)
		return
	}

	if len(registry.Entries) != 2 {
		t.Errorf("Expected 2 entries in registry, got %d", len(registry.Entries))
		return
	}

	// 验证CWE-79
	cwe79, err := registry.GetByID("CWE-79")
	if err != nil {
		t.Errorf("Failed to get CWE-79 from registry: %v", err)
		return
	}

	if cwe79.Name != "Cross-site Scripting" {
		t.Errorf("Expected name to be 'Cross-site Scripting', got %s", cwe79.Name)
	}

	// 验证CWE-89
	cwe89, err := registry.GetByID("CWE-89")
	if err != nil {
		t.Errorf("Failed to get CWE-89 from registry: %v", err)
		return
	}

	if cwe89.Name != "SQL Injection" {
		t.Errorf("Expected name to be 'SQL Injection', got %s", cwe89.Name)
	}

	// 测试空ID列表
	_, err = fetcher.FetchMultiple([]string{})
	if err == nil {
		t.Error("Expected error for empty ID list, got none")
	}
}

// 创建一个用于测试子节点填充的模拟服务器
func setupChildrenRecursiveServer() *httptest.Server {
	handler := http.NewServeMux()

	// 获取父节点
	handler.HandleFunc("/cwe/category/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"categories": []map[string]interface{}{
				{
					"id":          "CWE-20",
					"name":        "Improper Input Validation",
					"description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 添加缺失的端点
	handler.HandleFunc("/cwe/category/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"categories": []map[string]interface{}{
				{
					"id":          "CWE-20",
					"name":        "Improper Input Validation",
					"description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 获取子节点列表
	handler.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	handler.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 子节点详情
	handler.HandleFunc("/cwe/weakness/79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-79",
					"name":        "Cross-site Scripting",
					"description": "XSS vulnerability",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	handler.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-89",
					"name":        "SQL Injection",
					"description": "SQL injection vulnerability",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 添加缺失的端点
	handler.HandleFunc("/cwe/weakness/CWE-79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-79",
					"name":        "Cross-site Scripting",
					"description": "XSS vulnerability",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	handler.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"weaknesses": []map[string]interface{}{
				{
					"id":          "CWE-89",
					"name":        "SQL Injection",
					"description": "SQL injection vulnerability",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
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

	// 添加缺失的端点
	handler.HandleFunc("/cwe/CWE-79/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	handler.HandleFunc("/cwe/CWE-89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	return httptest.NewServer(handler)
}

// TestPopulateChildrenRecursiveBasic 测试基本的子节点递归填充功能
func TestPopulateChildrenRecursiveBasic(t *testing.T) {
	server := setupChildrenRecursiveServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 获取父节点
	parent, err := fetcher.FetchCategory("20")
	if err != nil {
		t.Errorf("Failed to fetch parent CWE: %v", err)
		return
	}

	// 填充子节点
	err = fetcher.PopulateChildrenRecursive(parent, "")
	if err != nil {
		t.Errorf("PopulateChildrenRecursive failed: %v", err)
		return
	}

	// 验证子节点数量
	if len(parent.Children) != 2 {
		t.Errorf("Expected 2 children, got %d", len(parent.Children))
		return
	}

	// 验证子节点内容
	var hasXSS, hasSQLi bool
	for _, child := range parent.Children {
		if child.ID == "CWE-79" && child.Name == "Cross-site Scripting" {
			hasXSS = true
		}
		if child.ID == "CWE-89" && child.Name == "SQL Injection" {
			hasSQLi = true
		}
	}

	if !hasXSS {
		t.Error("Expected to find XSS (CWE-79) as a child")
	}

	if !hasSQLi {
		t.Error("Expected to find SQL Injection (CWE-89) as a child")
	}
}
