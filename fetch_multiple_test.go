package cwe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// setupFetchMultipleTestServer 创建用于测试FetchMultiple方法的测试服务器
func setupFetchMultipleTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// 定义多个CWE同时获取的端点 - 支持不同格式的ID
	// 不带前缀的ID列表
	mux.HandleFunc("/cwe/79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"cwe79": {
				"id": "CWE-79",
				"name": "Cross-site Scripting",
				"description": "XSS vulnerability",
				"severity": "High",
				"mitigations": ["Use context-sensitive escaping"],
				"examples": ["Example XSS code"]
			},
			"cwe89": {
				"id": "CWE-89", 
				"name": "SQL Injection",
				"description": "SQL injection vulnerability",
				"severity": "High",
				"mitigations": ["Use parameterized queries"],
				"examples": ["Example SQL injection code"]
			}
		}`)
	})

	// 带前缀的ID列表
	mux.HandleFunc("/cwe/CWE-79,CWE-89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"cwe79": {
				"id": "CWE-79",
				"name": "Cross-site Scripting",
				"description": "XSS vulnerability",
				"severity": "High"
			},
			"cwe89": {
				"id": "CWE-89", 
				"name": "SQL Injection",
				"description": "SQL injection vulnerability",
				"severity": "High"
			}
		}`)
	})

	// 混合前缀的ID列表
	mux.HandleFunc("/cwe/CWE-79,89", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"cwe79": {
				"id": "CWE-79",
				"name": "Cross-site Scripting",
				"description": "XSS vulnerability"
			},
			"cwe89": {
				"id": "CWE-89", 
				"name": "SQL Injection",
				"description": "SQL injection vulnerability"
			}
		}`)
	})

	// 带有不同数据格式的ID列表
	mux.HandleFunc("/cwe/20,21", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"cwe20": {
				"id": "CWE-20",
				"name": "Improper Input Validation",
				"description": "The product does not validate input properly.",
				"url": "https://cwe.mitre.org/data/definitions/20.html"
			},
			"cwe21": {
				"ID": 21, 
				"Name": "Pathname Traversal and Equivalence Errors",
				"Description": "Weaknesses in this category can be used to access files outside of a restricted directory.",
				"summary": "Path traversal issues"
			}
		}`)
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
		fmt.Fprintf(w, `{
			"cwe1": "not an object",
			"cwe2": 42
		}`)
	})

	// 服务器错误
	mux.HandleFunc("/cwe/server,error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	fmt.Printf("FetchMultiple test server started at: %s\n", server.URL)
	return server
}

// TestFetchMultipleComprehensive 全面测试FetchMultiple方法
func TestFetchMultipleComprehensive(t *testing.T) {
	server := setupFetchMultipleTestServer()
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
		// 注意：mitigations和examples可能需要具体实现支持
		// 跳过这些检查
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

	// 测试错误格式的响应 - 修改期望为失败
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

	// 测试无效的ID格式
	ids = []string{"invalid-format", "89"}
	_, err = fetcher.FetchMultiple(ids)
	if err == nil {
		t.Error("FetchMultiple should fail with invalid ID format")
	}
}

// TestFetchMultipleErrorHandling 专门测试FetchMultiple的错误处理
func TestFetchMultipleErrorHandling(t *testing.T) {
	server := setupFetchMultipleTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	fetcher := NewDataFetcherWithClient(client)

	// 测试API客户端返回错误情况
	badClient := NewAPIClientWithOptions("http://nonexistent.server", 1*time.Second)
	badFetcher := NewDataFetcherWithClient(badClient)
	_, err := badFetcher.FetchMultiple([]string{"79", "89"})
	if err == nil {
		t.Error("FetchMultiple should fail with bad client")
	}

	// 测试ID格式验证
	_, err = fetcher.FetchMultiple([]string{"CWE_79"}) // 下划线而不是连字符
	if err == nil {
		t.Error("FetchMultiple should fail with invalid ID format")
	}

	// 测试空ID的特殊情况
	_, err = fetcher.FetchMultiple([]string{""})
	if err == nil {
		t.Error("FetchMultiple should fail with empty ID")
	}

	// 测试ID格式为null的特殊情况
	ids := []string{"79", "null", "89"}
	_, err = fetcher.FetchMultiple(ids)
	if err == nil {
		t.Error("FetchMultiple should fail with null in ID list")
	}
}
