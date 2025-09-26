package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 创建一个用于测试树构建功能的模拟服务器
func setupTreeBuildingServer() *httptest.Server {
	handler := http.NewServeMux()

	// 视图请求
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"views": []map[string]interface{}{
				{
					"id":          "CWE-1000",
					"name":        "Research Concepts",
					"description": "This view organizes weaknesses around a concept, which can help identify complex relationships.",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 视图请求 - 使用CWE-前缀
	handler.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"views": []map[string]interface{}{
				{
					"id":          "CWE-1000",
					"name":        "Research Concepts",
					"description": "This view organizes weaknesses around a concept, which can help identify complex relationships.",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 添加树构建相关的端点
	handler.HandleFunc("/cwe/CWE-1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	handler.HandleFunc("/cwe/1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 子节点
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
		json.NewEncoder(w).Encode([]string{})
	})

	handler.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

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

	// 添加缺失的端点
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

// TestBuildCWETreeWithView 测试通过视图构建CWE树
func TestBuildCWETreeWithView(t *testing.T) {
	server := setupTreeBuildingServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	registry, err := fetcher.BuildCWETreeWithView("1000")
	if err != nil {
		t.Errorf("BuildCWETreeWithView failed: %v", err)
		return
	}

	// 验证根节点
	if registry.Root.ID != "CWE-1000" {
		t.Errorf("Expected root ID to be CWE-1000, got %s", registry.Root.ID)
	}

	if registry.Root.Name != "Research Concepts" {
		t.Errorf("Expected root name to be 'Research Concepts', got %s", registry.Root.Name)
	}

	// 验证子节点
	if len(registry.Root.Children) != 1 {
		t.Errorf("Expected root to have 1 child, got %d", len(registry.Root.Children))
		return
	}

	if registry.Root.Children[0].ID != "CWE-20" {
		t.Errorf("Expected child ID to be CWE-20, got %s", registry.Root.Children[0].ID)
	}
}

// TestBuildCWETree 测试构建CWE树
func TestBuildCWETree(t *testing.T) {
	server := setupTreeBuildingServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	cweMap, rootNodes, err := fetcher.BuildCWETree([]string{"79", "89"})
	if err != nil {
		t.Errorf("BuildCWETree failed: %v", err)
		return
	}

	// 验证映射
	if len(cweMap) != 2 {
		t.Errorf("Expected cweMap to have 2 entries, got %d", len(cweMap))
	}

	// 验证根节点
	if len(rootNodes) != 2 {
		t.Errorf("Expected 2 root nodes, got %d", len(rootNodes))
		return
	}

	// 验证具体节点
	var hasXSS, hasSQLi bool
	for _, node := range rootNodes {
		if node.CWE.ID == "CWE-79" && node.CWE.Name == "Cross-site Scripting" {
			hasXSS = true
		}
		if node.CWE.ID == "CWE-89" && node.CWE.Name == "SQL Injection" {
			hasSQLi = true
		}
	}

	if !hasXSS {
		t.Error("Expected to find XSS (CWE-79) as a root node")
	}

	if !hasSQLi {
		t.Error("Expected to find SQL Injection (CWE-89) as a root node")
	}
}
