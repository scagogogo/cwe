package cwe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// setupBuildTreeTestServer 创建用于测试BuildCWETreeWithView方法的测试服务器
func setupBuildTreeTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// 视图信息端点 - 同时支持数字ID和CWE前缀格式
	mux.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-1000",
				"name": "Research Concepts",
				"description": "Top level view for research concepts."
			}]
		}`)
	})

	mux.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-1000",
				"name": "Research Concepts",
				"description": "Top level view for research concepts."
			}]
		}`)
	})

	// 无效视图ID
	mux.HandleFunc("/cwe/view/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// 子节点列表 - 同时支持数字ID和CWE前缀格式
	mux.HandleFunc("/cwe/1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["20", "21"]`)
	})

	mux.HandleFunc("/cwe/CWE-1000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["20", "21"]`)
	})

	// 带视图参数的子节点列表
	mux.HandleFunc("/cwe/1000/children?view=1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["20", "21"]`)
	})

	// 子节点的weakness信息
	mux.HandleFunc("/cwe/weakness/20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-20",
				"name": "Improper Input Validation",
				"description": "The product does not validate input properly."
			}]
		}`)
	})

	mux.HandleFunc("/cwe/weakness/CWE-20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-20",
				"name": "Improper Input Validation",
				"description": "The product does not validate input properly."
			}]
		}`)
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
		fmt.Fprintf(w, `{
			"categories": [{
				"id": "CWE-21",
				"name": "Pathname Traversal and Equivalence Errors",
				"description": "Weaknesses in this category can be used to access files outside of a restricted directory."
			}]
		}`)
	})

	mux.HandleFunc("/cwe/category/CWE-21", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"categories": [{
				"id": "CWE-21",
				"name": "Pathname Traversal and Equivalence Errors",
				"description": "Weaknesses in this category can be used to access files outside of a restricted directory."
			}]
		}`)
	})

	// 子节点的子节点
	mux.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["89"]`)
	})

	mux.HandleFunc("/cwe/CWE-20/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["89"]`)
	})

	mux.HandleFunc("/cwe/21/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[]`)
	})

	mux.HandleFunc("/cwe/CWE-21/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[]`)
	})

	// 孙节点信息
	mux.HandleFunc("/cwe/weakness/89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-89",
				"name": "SQL Injection",
				"description": "SQL injection vulnerability"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/weakness/CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-89",
				"name": "SQL Injection",
				"description": "SQL injection vulnerability"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[]`)
	})

	mux.HandleFunc("/cwe/CWE-89/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[]`)
	})

	// 处理网络错误情况
	mux.HandleFunc("/cwe/error/children", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc("/cwe/CWE-error/children", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	fmt.Printf("BuildTree test server started at: %s\n", server.URL)
	return server
}

// TestBuildCWETreeWithViewComprehensive 测试完整的树构建流程
func TestBuildCWETreeWithViewComprehensive(t *testing.T) {
	server := setupBuildTreeTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	// 为测试环境设置更宽松的速率限制，避免测试超时
	client.GetHTTPClient().GetRateLimiter().SetInterval(10 * time.Millisecond)
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

	// 验证节点数量
	expectedCount := 4 // Root + 2 children + 1 grandchild
	if len(registry.Entries) != expectedCount {
		t.Errorf("Expected %d entries in registry, got %d", expectedCount, len(registry.Entries))
	}

	// 验证特定节点是否存在
	_, err = registry.GetByID("CWE-1000")
	if err != nil {
		t.Errorf("Root node CWE-1000 not found in registry: %v", err)
	}

	_, err = registry.GetByID("CWE-20")
	if err != nil {
		t.Errorf("Node CWE-20 not found in registry: %v", err)
	}

	_, err = registry.GetByID("CWE-21")
	if err != nil {
		t.Errorf("Node CWE-21 not found in registry: %v", err)
	}

	_, err = registry.GetByID("CWE-89")
	if err != nil {
		t.Errorf("Node CWE-89 not found in registry: %v", err)
	}

	// 验证树结构
	root := registry.Root
	if len(root.Children) != 2 {
		t.Errorf("Expected 2 children under root, got %d", len(root.Children))
	}

	// 查找CWE-20节点并验证其子节点
	var cwe20 *CWE
	for _, child := range root.Children {
		if child.ID == "CWE-20" {
			cwe20 = child
			break
		}
	}

	if cwe20 == nil {
		t.Error("CWE-20 node not found among root children")
	} else if len(cwe20.Children) != 1 {
		t.Errorf("Expected 1 child under CWE-20, got %d", len(cwe20.Children))
	} else if cwe20.Children[0].ID != "CWE-89" {
		t.Errorf("Expected CWE-89 as child of CWE-20, got %s", cwe20.Children[0].ID)
	}

	// 查找CWE-21节点并验证其没有子节点
	var cwe21 *CWE
	for _, child := range root.Children {
		if child.ID == "CWE-21" {
			cwe21 = child
			break
		}
	}

	if cwe21 == nil {
		t.Error("CWE-21 node not found among root children")
	} else if len(cwe21.Children) != 0 {
		t.Errorf("Expected 0 children under CWE-21, got %d", len(cwe21.Children))
	}
}

// TestBuildCWETreeWithInvalidView 测试构建树时的错误处理
func TestBuildCWETreeWithInvalidView(t *testing.T) {
	server := setupBuildTreeTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试无效的视图ID格式
	_, err := fetcher.BuildCWETreeWithView("invalid-format")
	if err == nil {
		t.Error("BuildCWETreeWithView should fail with invalid view ID format")
	}

	// 测试不存在的视图
	_, err = fetcher.BuildCWETreeWithView("invalid")
	if err == nil {
		t.Error("BuildCWETreeWithView should fail with nonexistent view")
	}

	// 测试空视图ID
	_, err = fetcher.BuildCWETreeWithView("")
	if err == nil {
		t.Error("BuildCWETreeWithView should fail with empty view ID")
	}
}

// TestPopulateTree 单独测试populateTree方法
func TestPopulateTree(t *testing.T) {
	server := setupBuildTreeTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	// 为测试环境设置更宽松的速率限制，避免测试超时
	client.GetHTTPClient().GetRateLimiter().SetInterval(10 * time.Millisecond)
	fetcher := NewDataFetcherWithClient(client)

	// 创建基本的注册表和根节点
	registry := NewRegistry()
	root := NewCWE("CWE-1000", "Research Concepts")
	registry.Register(root)

	// 测试populateTree方法
	err := fetcher.populateTree(registry, root, "1000")
	if err != nil {
		t.Errorf("populateTree failed: %v", err)
	}

	// 验证节点数量和结构
	if len(registry.Entries) != 4 { // root + 2 children + 1 grandchild
		t.Errorf("Expected 4 entries after populateTree, got %d", len(registry.Entries))
	}

	// 验证子节点是否正确添加
	if len(root.Children) != 2 {
		t.Errorf("Expected 2 children under root, got %d", len(root.Children))
	}

	// 测试错误处理 - 使用错误ID
	errorNode := NewCWE("CWE-error", "Error Node")
	err = fetcher.populateTree(registry, errorNode, "1000")
	if err == nil {
		t.Error("populateTree should fail with error node")
	}
}

// TestBuildTreeWithCycle 测试循环引用情况
func TestBuildTreeWithCycle(t *testing.T) {
	// 创建一个自定义的测试服务器，模拟循环引用
	mux := http.NewServeMux()

	// 视图信息
	mux.HandleFunc("/cwe/view/999", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-999",
				"name": "Cycle View",
				"description": "A view with cyclic dependencies."
			}]
		}`)
	})

	mux.HandleFunc("/cwe/view/CWE-999", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-999",
				"name": "Cycle View",
				"description": "A view with cyclic dependencies."
			}]
		}`)
	})

	// A -> B -> C -> A 形成循环
	mux.HandleFunc("/cwe/999/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["101"]`)
	})

	mux.HandleFunc("/cwe/CWE-999/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["101"]`)
	})

	mux.HandleFunc("/cwe/weakness/101", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-101",
				"name": "Node A",
				"description": "Description for A"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/weakness/CWE-101", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-101",
				"name": "Node A",
				"description": "Description for A"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/101/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["102"]`)
	})

	mux.HandleFunc("/cwe/CWE-101/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["102"]`)
	})

	mux.HandleFunc("/cwe/weakness/102", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-102",
				"name": "Node B",
				"description": "Description for B"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/weakness/CWE-102", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-102",
				"name": "Node B",
				"description": "Description for B"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/102/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["103"]`)
	})

	mux.HandleFunc("/cwe/CWE-102/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["103"]`)
	})

	mux.HandleFunc("/cwe/weakness/103", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-103",
				"name": "Node C",
				"description": "Description for C"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/weakness/CWE-103", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"weaknesses": [{
				"id": "CWE-103",
				"name": "Node C",
				"description": "Description for C"
			}]
		}`)
	})

	// 循环: C -> A
	mux.HandleFunc("/cwe/103/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["101"]`)
	})

	mux.HandleFunc("/cwe/CWE-103/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `["101"]`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试处理循环引用
	registry, err := fetcher.BuildCWETreeWithView("999")
	if err != nil {
		t.Fatalf("BuildCWETreeWithView with cycle failed: %v", err)
	}

	// 验证能否处理循环引用 - 这里我们期望registry包含所有节点，但不会无限递归
	if len(registry.Entries) != 4 { // 999 + 101 + 102 + 103
		t.Errorf("Expected 4 entries with cycle, got %d", len(registry.Entries))
	}

	// 检查是否能找到所有节点
	_, err = registry.GetByID("CWE-999")
	if err != nil {
		t.Errorf("Node CWE-999 not found in registry: %v", err)
	}

	_, err = registry.GetByID("CWE-101")
	if err != nil {
		t.Errorf("Node CWE-101 not found in registry: %v", err)
	}

	_, err = registry.GetByID("CWE-102")
	if err != nil {
		t.Errorf("Node CWE-102 not found in registry: %v", err)
	}

	_, err = registry.GetByID("CWE-103")
	if err != nil {
		t.Errorf("Node CWE-103 not found in registry: %v", err)
	}
}

// TestBuildTreeEdgeCases 测试边缘情况
func TestBuildTreeEdgeCases(t *testing.T) {
	// 创建一个自定义的测试服务器，模拟各种边缘情况
	mux := http.NewServeMux()

	// 视图信息端点 - 格式错误的JSON
	mux.HandleFunc("/cwe/view/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"views": [{"id": "CWE-malformed", "name": "Malformed JSON`)) // 缺少结束引号和括号
	})

	// 视图信息端点 - 缺少ID字段
	mux.HandleFunc("/cwe/view/noid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"name": "Missing ID",
				"description": "This view is missing ID field"
			}]
		}`)
	})

	// 空子节点列表
	mux.HandleFunc("/cwe/view/2000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-2000",
				"name": "Empty View",
				"description": "A view with no children"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/view/CWE-2000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-2000",
				"name": "Empty View",
				"description": "A view with no children"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/2000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[]`)
	})

	mux.HandleFunc("/cwe/CWE-2000/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[]`)
	})

	// 服务器错误
	mux.HandleFunc("/cwe/view/servererror", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"views": [{
				"id": "CWE-error",
				"name": "Server Error",
				"description": "A view that will cause server error"
			}]
		}`)
	})

	mux.HandleFunc("/cwe/servererror/children", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc("/cwe/CWE-servererror/children", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试格式错误的JSON
	_, err := fetcher.BuildCWETreeWithView("malformed")
	if err == nil {
		t.Error("BuildCWETreeWithView should fail with malformed JSON")
	}

	// 测试缺少ID字段
	_, err = fetcher.BuildCWETreeWithView("noid")
	if err == nil {
		t.Error("BuildCWETreeWithView should fail with missing ID")
	}

	// 测试空子节点列表
	registry, err := fetcher.BuildCWETreeWithView("2000")
	if err != nil {
		t.Errorf("BuildCWETreeWithView should succeed with empty children: %v", err)
	} else {
		if len(registry.Root.Children) != 0 {
			t.Errorf("Expected 0 children for empty view, got %d", len(registry.Root.Children))
		}
	}

	// 测试服务器错误
	_, err = fetcher.BuildCWETreeWithView("servererror")
	if err == nil {
		t.Error("BuildCWETreeWithView should fail with server error")
	}
}
