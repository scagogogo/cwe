package cwe

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// setupRelationsExtraTestServer 创建一个专门测试关系函数边缘情况的服务器
func setupRelationsExtraTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// 定义各种边缘情况测试端点

	// 1. 格式错误的JSON响应
	mux.HandleFunc("/cwe/malformed/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`["20", "1000"`)) // 缺少右括号
	})

	mux.HandleFunc("/cwe/malformed/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`["79", "80"`)) // 缺少右括号
	})

	mux.HandleFunc("/cwe/malformed/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`["20", "1000"`)) // 缺少右括号
	})

	mux.HandleFunc("/cwe/malformed/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`["79", "80"`)) // 缺少右括号
	})

	// 2. 响应内容不是数组格式
	mux.HandleFunc("/cwe/invalid-format/parents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"not": "an array"}`))
	})

	mux.HandleFunc("/cwe/invalid-format/children", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"not": "an array"}`))
	})

	mux.HandleFunc("/cwe/invalid-format/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"not": "an array"}`))
	})

	mux.HandleFunc("/cwe/invalid-format/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"not": "an array"}`))
	})

	// 3. 服务器错误
	mux.HandleFunc("/cwe/server-error/parents", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc("/cwe/server-error/children", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc("/cwe/server-error/ancestors", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc("/cwe/server-error/descendants", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	// 4. 不同格式的视图ID参数
	mux.HandleFunc("/cwe/20/parents", func(w http.ResponseWriter, r *http.Request) {
		// 检查是否有视图ID参数
		if r.URL.Query().Get("view") == "1000" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`["1000"]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/cwe/20/children", func(w http.ResponseWriter, r *http.Request) {
		// 检查是否有视图ID参数
		if r.URL.Query().Get("view") == "1000" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`["79", "89"]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/cwe/20/ancestors", func(w http.ResponseWriter, r *http.Request) {
		// 检查是否有视图ID参数
		if r.URL.Query().Get("view") == "1000" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`["1000"]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/cwe/20/descendants", func(w http.ResponseWriter, r *http.Request) {
		// 检查是否有视图ID参数
		if r.URL.Query().Get("view") == "1000" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`["79", "89"]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

// TestGetParentsExtraEdgeCases 测试GetParents函数的边缘情况
func TestGetParentsExtraEdgeCases(t *testing.T) {
	server := setupRelationsExtraTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试格式错误的JSON
	_, err := client.GetParents("malformed", "")
	if err == nil {
		t.Error("GetParents should fail with malformed JSON")
	}

	// 测试格式错误的响应（不是数组）
	_, err = client.GetParents("invalid-format", "")
	if err == nil {
		t.Error("GetParents should fail with invalid format response")
	}

	// 测试服务器错误
	_, err = client.GetParents("server-error", "")
	if err == nil {
		t.Error("GetParents should fail with server error")
	}

	// 测试带有视图ID参数
	parents, err := client.GetParents("20", "1000")
	if err != nil {
		t.Errorf("GetParents with view ID failed: %v", err)
	}
	if len(parents) == 0 {
		t.Error("GetParents with view ID returned empty result")
	}

	// 测试连接错误
	badClient := NewAPIClientWithOptions("http://nonexistent-server", DefaultTimeout)
	_, err = badClient.GetParents("20", "")
	if err == nil {
		t.Error("GetParents should fail with connection error")
	}
}

// TestGetChildrenExtraEdgeCases 测试GetChildren函数的边缘情况
func TestGetChildrenExtraEdgeCases(t *testing.T) {
	server := setupRelationsExtraTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试格式错误的JSON
	_, err := client.GetChildren("malformed", "")
	if err == nil {
		t.Error("GetChildren should fail with malformed JSON")
	}

	// 测试格式错误的响应（不是数组）
	_, err = client.GetChildren("invalid-format", "")
	if err == nil {
		t.Error("GetChildren should fail with invalid format response")
	}

	// 测试服务器错误
	_, err = client.GetChildren("server-error", "")
	if err == nil {
		t.Error("GetChildren should fail with server error")
	}

	// 测试带有视图ID参数
	children, err := client.GetChildren("20", "1000")
	if err != nil {
		t.Errorf("GetChildren with view ID failed: %v", err)
	}
	if len(children) == 0 {
		t.Error("GetChildren with view ID returned empty result")
	}

	// 测试连接错误
	badClient := NewAPIClientWithOptions("http://nonexistent-server", DefaultTimeout)
	_, err = badClient.GetChildren("20", "")
	if err == nil {
		t.Error("GetChildren should fail with connection error")
	}
}

// TestGetAncestorsExtraEdgeCases 测试GetAncestors函数的边缘情况
func TestGetAncestorsExtraEdgeCases(t *testing.T) {
	server := setupRelationsExtraTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试格式错误的JSON
	_, err := client.GetAncestors("malformed", "")
	if err == nil {
		t.Error("GetAncestors should fail with malformed JSON")
	}

	// 测试格式错误的响应（不是数组）
	_, err = client.GetAncestors("invalid-format", "")
	if err == nil {
		t.Error("GetAncestors should fail with invalid format response")
	}

	// 测试服务器错误
	_, err = client.GetAncestors("server-error", "")
	if err == nil {
		t.Error("GetAncestors should fail with server error")
	}

	// 测试带有视图ID参数
	ancestors, err := client.GetAncestors("20", "1000")
	if err != nil {
		t.Errorf("GetAncestors with view ID failed: %v", err)
	}
	if len(ancestors) == 0 {
		t.Error("GetAncestors with view ID returned empty result")
	}

	// 测试连接错误
	badClient := NewAPIClientWithOptions("http://nonexistent-server", DefaultTimeout)
	_, err = badClient.GetAncestors("20", "")
	if err == nil {
		t.Error("GetAncestors should fail with connection error")
	}
}

// TestGetDescendantsExtraEdgeCases 测试GetDescendants函数的边缘情况
func TestGetDescendantsExtraEdgeCases(t *testing.T) {
	server := setupRelationsExtraTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试格式错误的JSON
	_, err := client.GetDescendants("malformed", "")
	if err == nil {
		t.Error("GetDescendants should fail with malformed JSON")
	}

	// 测试格式错误的响应（不是数组）
	_, err = client.GetDescendants("invalid-format", "")
	if err == nil {
		t.Error("GetDescendants should fail with invalid format response")
	}

	// 测试服务器错误
	_, err = client.GetDescendants("server-error", "")
	if err == nil {
		t.Error("GetDescendants should fail with server error")
	}

	// 测试带有视图ID参数
	descendants, err := client.GetDescendants("20", "1000")
	if err != nil {
		t.Errorf("GetDescendants with view ID failed: %v", err)
	}
	if len(descendants) == 0 {
		t.Error("GetDescendants with view ID returned empty result")
	}

	// 测试连接错误
	badClient := NewAPIClientWithOptions("http://nonexistent-server", DefaultTimeout)
	_, err = badClient.GetDescendants("20", "")
	if err == nil {
		t.Error("GetDescendants should fail with connection error")
	}
}
