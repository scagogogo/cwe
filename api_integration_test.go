package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 创建一个更复杂的模拟服务器，专门用于测试集成层
func setupIntegrationMockServer() *httptest.Server {
	handler := http.NewServeMux()

	// 版本请求
	handler.HandleFunc("/cwe/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": "4.8",
		})
	})

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

	// 处理多个CWE的请求
	handler.HandleFunc("/cwe/79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS description",
			},
			"89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection description",
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理多个CWE的请求 - 使用CWE-前缀
	handler.HandleFunc("/cwe/CWE-79,CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS description",
			},
			"89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection description",
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理子节点
	handler.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 处理子节点 - 使用CWE-前缀
	handler.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 处理CWE-79的详情
	handler.HandleFunc("/cwe/weakness/79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-79",
			"name":        "Cross-site Scripting",
			"description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理CWE-79的详情 - 使用CWE-前缀
	handler.HandleFunc("/cwe/weakness/CWE-79", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"id":          "CWE-79",
			"name":        "Cross-site Scripting",
			"description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// 处理CWE-79的子节点
	handler.HandleFunc("/cwe/79/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 处理CWE-79的子节点 - 使用CWE-前缀
	handler.HandleFunc("/cwe/CWE-79/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 处理CWE-89的子节点
	handler.HandleFunc("/cwe/89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 处理CWE-89的子节点 - 使用CWE-前缀
	handler.HandleFunc("/cwe/CWE-89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 添加树构建相关的端点
	handler.HandleFunc("/cwe/CWE-1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 添加无子节点的情况
	handler.HandleFunc("/cwe/999/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 添加无子节点的情况 - 使用CWE-前缀
	handler.HandleFunc("/cwe/CWE-999/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
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

func TestFetchWeakness(t *testing.T) {
	server := setupIntegrationMockServer()
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
	server := setupIntegrationMockServer()
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
	server := setupIntegrationMockServer()
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

func TestFetchMultiple(t *testing.T) {
	server := setupIntegrationMockServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// Mock server 目前只支持 "79,89" 格式的请求
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

func TestPopulateChildrenRecursive(t *testing.T) {
	server := setupIntegrationMockServer()
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

	// 验证子节点
	if len(parent.Children) != 2 {
		t.Errorf("Expected 2 children, got %d", len(parent.Children))
		return
	}

	// 验证子节点名称
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

func TestBuildCWETreeWithView(t *testing.T) {
	server := setupIntegrationMockServer()
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
}

func TestConvertToCWE(t *testing.T) {
	client := NewAPIClient()
	fetcher := NewDataFetcherWithClient(client)

	// 测试完整数据
	data := map[string]interface{}{
		"id":          "CWE-89",
		"name":        "SQL Injection",
		"description": "SQL injection description",
		"url":         "https://example.com/cwe-89",
		"mitigations": []interface{}{"Use prepared statements", "Validate input"},
		"examples":    []interface{}{"Example 1", "Example 2"},
	}

	cwe, err := fetcher.convertToCWE(data)
	if err != nil {
		t.Errorf("convertToCWE failed: %v", err)
		return
	}

	if cwe.ID != "CWE-89" {
		t.Errorf("Expected ID to be CWE-89, got %s", cwe.ID)
	}

	if cwe.Name != "SQL Injection" {
		t.Errorf("Expected name to be 'SQL Injection', got %s", cwe.Name)
	}

	if cwe.Description != "SQL injection description" {
		t.Errorf("Expected description to match, got %s", cwe.Description)
	}

	if cwe.URL != "https://example.com/cwe-89" {
		t.Errorf("Expected URL to match, got %s", cwe.URL)
	}

	if len(cwe.Mitigations) != 2 {
		t.Errorf("Expected 2 mitigations, got %d", len(cwe.Mitigations))
	}

	if len(cwe.Examples) != 2 {
		t.Errorf("Expected 2 examples, got %d", len(cwe.Examples))
	}

	// 测试缺少ID的情况
	badData := map[string]interface{}{
		"name": "Bad Data",
	}

	_, err = fetcher.convertToCWE(badData)
	if err == nil {
		t.Error("Expected error for data without ID, got none")
	}

	// 测试数字ID的情况
	numericIDData := map[string]interface{}{
		"ID":   float64(79),
		"name": "XSS",
	}

	cwe, err = fetcher.convertToCWE(numericIDData)
	if err != nil {
		t.Errorf("convertToCWE failed with numeric ID: %v", err)
		return
	}

	if cwe.ID != "CWE-79" {
		t.Errorf("Expected ID to be CWE-79, got %s", cwe.ID)
	}
}

func TestGetCurrentVersion(t *testing.T) {
	server := setupIntegrationMockServer()
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

func TestFetchCWEByIDWithRelations(t *testing.T) {
	server := setupIntegrationMockServer()
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

// 测试DataFetcher的高级集成方法
func TestDataFetcherIntegration(t *testing.T) {
	server := setupDetailedTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试FetchWeakness
	cwe, err := fetcher.FetchWeakness("89")
	if err != nil {
		t.Errorf("FetchWeakness failed: %v", err)
		// 如果失败，直接返回，不进行后续测试
		return
	}
	if cwe == nil {
		t.Errorf("FetchWeakness returned nil CWE")
		return
	}
	if cwe.ID != "CWE-89" {
		t.Errorf("Expected ID CWE-89, got %s", cwe.ID)
	}

	// 测试FetchCategory
	category, err := fetcher.FetchCategory("20")
	if err != nil {
		t.Errorf("FetchCategory failed: %v", err)
		return
	}
	if category == nil {
		t.Errorf("FetchCategory returned nil CWE")
		return
	}
	if category.ID != "CWE-20" {
		t.Errorf("Expected ID CWE-20, got %s", category.ID)
	}

	// 测试FetchView
	view, err := fetcher.FetchView("1000")
	if err != nil {
		t.Errorf("FetchView failed: %v", err)
		return
	}
	if view == nil {
		t.Errorf("FetchView returned nil CWE")
		return
	}
	if view.ID != "CWE-1000" {
		t.Errorf("Expected ID CWE-1000, got %s", view.ID)
	}

	// 测试FetchMultiple
	registry, err := fetcher.FetchMultiple([]string{"79", "89"})
	if err != nil {
		t.Errorf("FetchMultiple failed: %v", err)
		return
	}
	if registry == nil {
		t.Errorf("FetchMultiple returned nil registry")
		return
	}
	if len(registry.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(registry.Entries))
	}

	// 测试PopulateChildrenRecursive
	if view != nil {
		err = fetcher.PopulateChildrenRecursive(view, "")
		if err != nil {
			t.Errorf("PopulateChildrenRecursive failed: %v", err)
			return
		}
		if len(view.Children) < 1 {
			t.Errorf("Expected at least 1 child, got %d", len(view.Children))
		}
	}

	// 测试BuildCWETreeWithView
	tree, err := fetcher.BuildCWETreeWithView("1000")
	if err != nil {
		t.Errorf("BuildCWETreeWithView failed: %v", err)
		return
	}
	if tree == nil {
		t.Errorf("BuildCWETreeWithView returned nil tree")
		return
	}
	if tree.Root == nil {
		t.Error("Tree root should not be nil")
		return
	}
	if tree.Root.ID != "CWE-1000" {
		t.Errorf("Expected root ID CWE-1000, got %s", tree.Root.ID)
	}

	// 测试FetchCWEByIDWithRelations
	relationCWE, err := fetcher.FetchCWEByIDWithRelations("1000", "")
	if err != nil {
		t.Errorf("FetchCWEByIDWithRelations failed: %v", err)
		return
	}
	if relationCWE == nil {
		t.Errorf("FetchCWEByIDWithRelations returned nil CWE")
		return
	}
	if relationCWE.ID != "CWE-1000" {
		t.Errorf("Expected ID CWE-1000, got %s", relationCWE.ID)
	}
	if len(relationCWE.Children) == 0 {
		t.Error("Expected children to be populated")
	}
}

// setupFetchMultipleTestServerIntegration 创建用于测试FetchMultiple方法的测试服务器
func setupFetchMultipleTestServerIntegration() *httptest.Server {
	mux := http.NewServeMux()

	// 定义多个CWE同时获取的端点 - 支持不同格式的ID
	// 不带前缀的ID列表
	mux.HandleFunc("/cwe/79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cwe79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS vulnerability",
				"severity":    "High",
				"mitigations": []string{"Use context-sensitive escaping"},
				"examples":    []string{"Example XSS code"},
			},
			"cwe89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection vulnerability",
				"severity":    "High",
				"mitigations": []string{"Use parameterized queries"},
				"examples":    []string{"Example SQL injection code"},
			},
		})
	})

	// 带前缀的ID列表
	mux.HandleFunc("/cwe/CWE-79,CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cwe79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS vulnerability",
				"severity":    "High",
			},
			"cwe89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection vulnerability",
				"severity":    "High",
			},
		})
	})

	// 混合前缀的ID列表
	mux.HandleFunc("/cwe/CWE-79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cwe79": map[string]interface{}{
				"id":          "CWE-79",
				"name":        "Cross-site Scripting",
				"description": "XSS vulnerability",
			},
			"cwe89": map[string]interface{}{
				"id":          "CWE-89",
				"name":        "SQL Injection",
				"description": "SQL injection vulnerability",
			},
		})
	})

	// 带有不同数据格式的ID列表
	mux.HandleFunc("/cwe/20,21", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cwe20": map[string]interface{}{
				"id":          "CWE-20",
				"name":        "Improper Input Validation",
				"description": "The product does not validate input properly.",
				"url":         "https://cwe.mitre.org/data/definitions/20.html",
			},
			"cwe21": map[string]interface{}{
				"ID":          21,
				"Name":        "Pathname Traversal and Equivalence Errors",
				"Description": "Weaknesses in this category can be used to access files outside of a restricted directory.",
				"summary":     "Path traversal issues",
			},
		})
	})

	// 不存在的ID列表
	mux.HandleFunc("/cwe/9999,9998", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// 空ID列表，将返回错误
	mux.HandleFunc("/cwe/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	// 带有错误格式的响应
	mux.HandleFunc("/cwe/error,format", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cwe1": "not an object",
			"cwe2": 42,
		})
	})

	// 服务器错误
	mux.HandleFunc("/cwe/server,error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	return server
}

// TestFetchMultipleComprehensiveIntegration 全面测试FetchMultiple方法
func TestFetchMultipleComprehensiveIntegration(t *testing.T) {
	server := setupFetchMultipleTestServerIntegration()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试标准用例
	ids := []string{"79", "89"}
	registry, err := fetcher.FetchMultiple(ids)
	if err != nil {
		t.Fatalf("FetchMultiple failed: %v", err)
	}

	// 验证注册表内容
	if registry == nil {
		t.Fatal("FetchMultiple returned nil registry")
	}
	if len(registry.Entries) != 2 {
		t.Errorf("Expected 2 entries in registry, got %d", len(registry.Entries))
	}

	// 验证具体条目
	cwe79, err := registry.GetByID("CWE-79")
	if err != nil {
		t.Errorf("GetByID failed for CWE-79: %v", err)
	} else {
		if cwe79.Name != "Cross-site Scripting" {
			t.Errorf("Expected name 'Cross-site Scripting', got %s", cwe79.Name)
		}
		if cwe79.Severity != "High" {
			t.Errorf("Expected severity 'High', got %s", cwe79.Severity)
		}
	}

	cwe89, err := registry.GetByID("CWE-89")
	if err != nil {
		t.Errorf("GetByID failed for CWE-89: %v", err)
	} else {
		if cwe89.Name != "SQL Injection" {
			t.Errorf("Expected name 'SQL Injection', got %s", cwe89.Name)
		}
	}

	// 测试带有CWE前缀的ID
	ids = []string{"CWE-79", "CWE-89"}
	registry, err = fetcher.FetchMultiple(ids)
	if err != nil {
		t.Errorf("FetchMultiple with CWE prefixed IDs failed: %v", err)
	} else if len(registry.Entries) != 2 {
		t.Errorf("Expected 2 entries in registry, got %d", len(registry.Entries))
	}

	// 测试混合前缀的ID
	ids = []string{"CWE-79", "89"}
	registry, err = fetcher.FetchMultiple(ids)
	if err != nil {
		t.Errorf("FetchMultiple with mixed prefix IDs failed: %v", err)
	} else if len(registry.Entries) != 2 {
		t.Errorf("Expected 2 entries in registry, got %d", len(registry.Entries))
	}

	// 测试不存在的ID
	ids = []string{"9999", "9998"}
	_, err = fetcher.FetchMultiple(ids)
	if err == nil {
		t.Error("FetchMultiple should fail with nonexistent IDs")
	}

	// 测试空ID列表
	_, err = fetcher.FetchMultiple([]string{})
	if err == nil {
		t.Error("FetchMultiple should fail with empty ID list")
	}

	// 测试错误格式的响应
	ids = []string{"error", "format"}
	_, err = fetcher.FetchMultiple(ids)
	if err == nil {
		t.Error("FetchMultiple should fail with error format response")
	}

	// 测试服务器错误
	ids = []string{"server", "error"}
	_, err = fetcher.FetchMultiple(ids)
	if err == nil {
		t.Error("FetchMultiple should fail with server error")
	}
}

// setupBuildTreeTestServerIntegration 创建用于测试BuildCWETreeWithView方法的测试服务器
func setupBuildTreeTestServerIntegration() *httptest.Server {
	mux := http.NewServeMux()

	// 视图信息端点 - 同时支持数字ID和CWE前缀格式
	mux.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "Top level view for research concepts.",
		})
	})

	mux.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "Top level view for research concepts.",
		})
	})

	// 无效视图ID
	mux.HandleFunc("/cwe/view/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// 子节点列表 - 同时支持数字ID和CWE前缀格式
	mux.HandleFunc("/cwe/1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "21"})
	})

	mux.HandleFunc("/cwe/CWE-1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "21"})
	})

	// 子节点的weakness信息
	mux.HandleFunc("/cwe/weakness/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate input properly.",
		})
	})

	mux.HandleFunc("/cwe/weakness/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-20",
			"name":        "Improper Input Validation",
			"description": "The product does not validate input properly.",
		})
	})

	// 子节点的category信息 - 21是一个category
	mux.HandleFunc("/cwe/weakness/21", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/cwe/weakness/CWE-21", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/cwe/category/21", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-21",
			"name":        "Pathname Traversal and Equivalence Errors",
			"description": "Weaknesses in this category can be used to access files outside of a restricted directory.",
		})
	})

	mux.HandleFunc("/cwe/category/CWE-21", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-21",
			"name":        "Pathname Traversal and Equivalence Errors",
			"description": "Weaknesses in this category can be used to access files outside of a restricted directory.",
		})
	})

	// 子节点的子节点
	mux.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"89"})
	})

	mux.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"89"})
	})

	mux.HandleFunc("/cwe/21/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	mux.HandleFunc("/cwe/CWE-21/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// 孙节点信息
	mux.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "SQL injection vulnerability",
		})
	})

	mux.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-89",
			"name":        "SQL Injection",
			"description": "SQL injection vulnerability",
		})
	})

	mux.HandleFunc("/cwe/89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	mux.HandleFunc("/cwe/CWE-89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	server := httptest.NewServer(mux)
	return server
}

// TestBuildCWETreeWithViewComprehensiveIntegration 测试完整的树构建流程
func TestBuildCWETreeWithViewComprehensiveIntegration(t *testing.T) {
	server := setupBuildTreeTestServerIntegration()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试成功构建树
	registry, err := fetcher.BuildCWETreeWithView("1000")
	if err != nil {
		t.Fatalf("BuildCWETreeWithView failed: %v", err)
	}

	// 验证根节点
	if registry.Root == nil {
		t.Fatal("Registry root is nil")
	}
	if registry.Root.ID != "CWE-1000" {
		t.Errorf("Expected root ID CWE-1000, got %s", registry.Root.ID)
	}
	if registry.Root.Name != "Research Concepts" {
		t.Errorf("Expected root name 'Research Concepts', got %s", registry.Root.Name)
	}

	// 验证注册表中的条目数
	if len(registry.Entries) != 4 { // root + 2 children + 1 grandchild
		t.Errorf("Expected 4 entries in registry, got %d", len(registry.Entries))
	}

	// 验证树结构
	if len(registry.Root.Children) != 2 {
		t.Errorf("Expected 2 children under root, got %d", len(registry.Root.Children))
	}

	// 验证是否有CWE-20和CWE-21作为直接子节点
	var cwe20, cwe21 *CWE
	for _, child := range registry.Root.Children {
		if child.ID == "CWE-20" {
			cwe20 = child
		} else if child.ID == "CWE-21" {
			cwe21 = child
		}
	}

	if cwe20 == nil {
		t.Error("CWE-20 not found as child of root")
	} else {
		// 验证CWE-20的子节点
		if len(cwe20.Children) != 1 {
			t.Errorf("Expected 1 child under CWE-20, got %d", len(cwe20.Children))
		} else if cwe20.Children[0].ID != "CWE-89" {
			t.Errorf("Expected CWE-89 as child of CWE-20, got %s", cwe20.Children[0].ID)
		}
	}

	if cwe21 == nil {
		t.Error("CWE-21 not found as child of root")
	} else {
		// 验证CWE-21没有子节点
		if len(cwe21.Children) != 0 {
			t.Errorf("Expected 0 children under CWE-21, got %d", len(cwe21.Children))
		}
	}

	// 通过ID获取节点
	cwe89, err := registry.GetByID("CWE-89")
	if err != nil {
		t.Errorf("GetByID failed for CWE-89: %v", err)
	} else if cwe89.Name != "SQL Injection" {
		t.Errorf("Expected name 'SQL Injection', got %s", cwe89.Name)
	}
}
