// 该文件包含对api_client_relations.go中关系API的测试
package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// setupRelationsTestServer 创建测试父子关系API方法的服务器
func setupRelationsTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// Parents API
	// 标准响应 - 不带视图ID
	mux.HandleFunc("/cwe/89/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 带有视图ID的响应
	mux.HandleFunc("/cwe/89/parents/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 正规化的CWE ID
	mux.HandleFunc("/cwe/CWE-89/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20"})
	})

	// 无效的CWE ID
	mux.HandleFunc("/cwe/invalid/parents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// 空父节点
	mux.HandleFunc("/cwe/orphan/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	// Ancestors API
	// 标准响应 - 不带视图ID
	mux.HandleFunc("/cwe/89/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	// 带有视图ID的响应
	mux.HandleFunc("/cwe/89/ancestors/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	// 正规化的CWE ID
	mux.HandleFunc("/cwe/CWE-89/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"20", "1000"})
	})

	// 无效的CWE ID
	mux.HandleFunc("/cwe/invalid/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// 格式错误的JSON
	mux.HandleFunc("/cwe/malformed/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`["20", "1000"`)) // 缺少右括号
	})

	// Descendants API
	// 标准响应 - 不带视图ID
	mux.HandleFunc("/cwe/20/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 带有视图ID的响应
	mux.HandleFunc("/cwe/20/descendants/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 正规化的CWE ID
	mux.HandleFunc("/cwe/CWE-20/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"79", "89"})
	})

	// 无效的CWE ID
	mux.HandleFunc("/cwe/invalid/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// 服务器错误
	mux.HandleFunc("/cwe/error/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	return httptest.NewServer(mux)
}

// setupRelationsTestServerWithErrors 创建测试父子关系API方法的服务器，返回服务器错误
func setupRelationsTestServerWithErrors(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	return server
}

// TestGetParentsComprehensive 全面测试GetParents方法
func TestGetParentsComprehensive(t *testing.T) {
	server := setupRelationsTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// 标准响应 - 不带视图ID
	parents, err := client.GetParents("89", "")
	if err != nil {
		t.Errorf("GetParents failed for standard case: %v", err)
	}
	if !reflect.DeepEqual(parents, []string{"20"}) {
		t.Errorf("Expected parents [20], got %v", parents)
	}

	// 带有视图ID的响应
	parents, err = client.GetParents("89", "1000")
	if err != nil {
		t.Errorf("GetParents failed with view ID: %v", err)
	}
	if !reflect.DeepEqual(parents, []string{"20"}) {
		t.Errorf("Expected parents [20], got %v", parents)
	}

	// 正规化的CWE ID
	parents, err = client.GetParents("CWE-89", "")
	if err != nil {
		t.Errorf("GetParents failed with normalized ID: %v", err)
	}
	if !reflect.DeepEqual(parents, []string{"20"}) {
		t.Errorf("Expected parents [20], got %v", parents)
	}

	// 无效的CWE ID
	_, err = client.GetParents("invalid", "")
	if err == nil {
		t.Error("GetParents should fail for invalid ID")
	}

	// 空父节点
	parents, err = client.GetParents("orphan", "")
	if err != nil {
		t.Errorf("GetParents failed for orphan: %v", err)
	}
	if len(parents) != 0 {
		t.Errorf("Expected empty parents, got %v", parents)
	}

	// 连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetParents("89", "")
	if err == nil {
		t.Error("GetParents should fail for connection error")
	}
}

// TestGetAncestorsComprehensive 全面测试GetAncestors方法
func TestGetAncestorsComprehensive(t *testing.T) {
	server := setupRelationsTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// 标准响应 - 不带视图ID
	ancestors, err := client.GetAncestors("89", "")
	if err != nil {
		t.Errorf("GetAncestors failed for standard case: %v", err)
	}
	if !reflect.DeepEqual(ancestors, []string{"20", "1000"}) {
		t.Errorf("Expected ancestors [20, 1000], got %v", ancestors)
	}

	// 带有视图ID的响应
	ancestors, err = client.GetAncestors("89", "1000")
	if err != nil {
		t.Errorf("GetAncestors failed with view ID: %v", err)
	}
	if !reflect.DeepEqual(ancestors, []string{"20", "1000"}) {
		t.Errorf("Expected ancestors [20, 1000], got %v", ancestors)
	}

	// 正规化的CWE ID
	ancestors, err = client.GetAncestors("CWE-89", "")
	if err != nil {
		t.Errorf("GetAncestors failed with normalized ID: %v", err)
	}
	if !reflect.DeepEqual(ancestors, []string{"20", "1000"}) {
		t.Errorf("Expected ancestors [20, 1000], got %v", ancestors)
	}

	// 无效的CWE ID
	_, err = client.GetAncestors("invalid", "")
	if err == nil {
		t.Error("GetAncestors should fail for invalid ID")
	}

	// 格式错误的JSON
	_, err = client.GetAncestors("malformed", "")
	if err == nil {
		t.Error("GetAncestors should fail for malformed JSON")
	}

	// 连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetAncestors("89", "")
	if err == nil {
		t.Error("GetAncestors should fail for connection error")
	}
}

// TestGetDescendantsComprehensive 全面测试GetDescendants方法
func TestGetDescendantsComprehensive(t *testing.T) {
	server := setupRelationsTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// 标准响应 - 不带视图ID
	descendants, err := client.GetDescendants("20", "")
	if err != nil {
		t.Errorf("GetDescendants failed for standard case: %v", err)
	}
	if !reflect.DeepEqual(descendants, []string{"79", "89"}) {
		t.Errorf("Expected descendants [79, 89], got %v", descendants)
	}

	// 带有视图ID的响应
	descendants, err = client.GetDescendants("20", "1000")
	if err != nil {
		t.Errorf("GetDescendants failed with view ID: %v", err)
	}
	if !reflect.DeepEqual(descendants, []string{"79", "89"}) {
		t.Errorf("Expected descendants [79, 89], got %v", descendants)
	}

	// 正规化的CWE ID
	descendants, err = client.GetDescendants("CWE-20", "")
	if err != nil {
		t.Errorf("GetDescendants failed with normalized ID: %v", err)
	}
	if !reflect.DeepEqual(descendants, []string{"79", "89"}) {
		t.Errorf("Expected descendants [79, 89], got %v", descendants)
	}

	// 无效的CWE ID
	_, err = client.GetDescendants("invalid", "")
	if err == nil {
		t.Error("GetDescendants should fail for invalid ID")
	}

	// 服务器错误
	_, err = client.GetDescendants("error", "")
	if err == nil {
		t.Error("GetDescendants should fail for server error")
	}

	// 连接失败
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err = badClient.GetDescendants("20", "")
	if err == nil {
		t.Error("GetDescendants should fail for connection error")
	}
}

func TestGetWeaknessRelations(t *testing.T) {
	server := setupRelationsTestServer()
	defer server.Close()

	_ = NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// ... existing code ...
}

func TestGetWeaknessRelationsWithErrors(t *testing.T) {
	server := setupRelationsTestServerWithErrors(t)
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err := client.GetWeakness("89")
	if err == nil {
		t.Error("Expected error for weakness relations")
	}
}

func TestGetCategoryRelations(t *testing.T) {
	server := setupRelationsTestServer()
	defer server.Close()

	_ = NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// ... existing code ...
}

func TestGetCategoryRelationsWithErrors(t *testing.T) {
	server := setupRelationsTestServerWithErrors(t)
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err := client.GetCategory("89")
	if err == nil {
		t.Error("Expected error for category relations")
	}
}

func TestGetViewRelations(t *testing.T) {
	server := setupRelationsTestServer()
	defer server.Close()

	_ = NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))

	// ... existing code ...
}

func TestGetViewRelationsWithErrors(t *testing.T) {
	server := setupRelationsTestServerWithErrors(t)
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout, NewHTTPRateLimiter(time.Second))
	_, err := client.GetView("89")
	if err == nil {
		t.Error("Expected error for view relations")
	}
}
