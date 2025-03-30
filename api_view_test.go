package cwe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setupViewTestServer 创建专门测试视图相关方法的测试服务器
func setupViewTestServer() *httptest.Server {
	handler := http.NewServeMux()

	// 正常视图响应
	handler.HandleFunc("/cwe/view/1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "Top level research view",
			"url":         "https://cwe.mitre.org/data/definitions/1000.html",
			"severity":    "Informational",
		})
	})

	// 规范化的ID响应
	handler.HandleFunc("/cwe/view/CWE-1000", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "CWE-1000",
			"name":        "Research Concepts",
			"description": "Top level research view",
			"url":         "https://cwe.mitre.org/data/definitions/1000.html",
			"severity":    "Informational",
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
			"name":        "No ID View",
			"description": "This view response is missing ID field",
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

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)

	// 测试正常获取
	view, err := client.GetView("1000")
	if err != nil {
		t.Errorf("GetView failed for normal case: %v", err)
	}
	if view["id"] != "CWE-1000" {
		t.Errorf("Expected id CWE-1000, got %s", view["id"])
	}
	if view["name"] != "Research Concepts" {
		t.Errorf("Expected name Research Concepts, got %s", view["name"])
	}

	// 测试规范化的ID
	view, err = client.GetView("CWE-1000")
	if err != nil {
		t.Errorf("GetView failed for normalized ID: %v", err)
	}
	if view["id"] != "CWE-1000" {
		t.Errorf("Expected id CWE-1000, got %s", view["id"])
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
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout)
	_, err = badClient.GetView("1000")
	if err == nil {
		t.Error("GetView should fail for connection error")
	}
}

// TestFetchViewComprehensive 全面测试FetchView方法
func TestFetchViewComprehensive(t *testing.T) {
	server := setupViewTestServer()
	defer server.Close()

	client := NewAPIClientWithOptions(server.URL, DefaultTimeout)
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
	badClient := NewAPIClientWithOptions("http://non-existent-server", DefaultTimeout)
	badFetcher := NewDataFetcherWithClient(badClient)
	_, err = badFetcher.FetchView("1000")
	if err == nil {
		t.Error("FetchView should fail for connection error")
	}
}
