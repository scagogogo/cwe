package cwe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setupCategoryTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// 处理所有分类请求的拦截器,确保能够匹配请求路径
	mux.HandleFunc("/cwe/category/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		fmt.Printf("收到请求路径: %s\n", path)

		// 检测具体的ID，注意ID已经被规范化为CWE-xxxx格式
		if strings.HasSuffix(path, "/CWE-1000") || strings.HasSuffix(path, "/1000") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "1000",
				"name": "Test Category",
				"description": "This is a test category",
				"url": "https://cwe.mitre.org/data/definitions/1000.html"
			}`))
			return
		} else if strings.HasSuffix(path, "/CWE-1001") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "CWE-1001",
				"name": "Another Test Category",
				"description": "This is another test category"
			}`))
			return
		} else if strings.HasSuffix(path, "/CWE-1002") || strings.HasSuffix(path, "/1002") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "1002",
				"name": "Number ID Category",
				"description": "This category has a numeric ID"
			}`))
			return
		} else if strings.HasSuffix(path, "/CWE-1003") || strings.HasSuffix(path, "/1003") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "1003",
				"name": "No Description Category"
			}`))
			return
		} else if strings.HasSuffix(path, "/CWE-1004") || strings.HasSuffix(path, "/1004") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "1004",
				"name": "Summary Category",
				"summary": "This category uses summary instead of description"
			}`))
			return
		} else if strings.HasSuffix(path, "/CWE-1005") || strings.HasSuffix(path, "/1005") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "1005",
				"Name": "Different Case Category",
				"Description": "This category uses different case for field names"
			}`))
			return
		} else if strings.HasSuffix(path, "/missing-id") || strings.HasSuffix(path, "/CWE-missing-id") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"name": "Missing ID Category",
				"description": "This category is missing an ID field"
			}`))
			return
		} else if strings.HasSuffix(path, "/invalid-json") || strings.HasSuffix(path, "/CWE-invalid-json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "invalid-json"
				"name": "Invalid JSON Category",
				"description": "This category has invalid JSON"
			}`))
			return
		} else if strings.HasSuffix(path, "/server-error") || strings.HasSuffix(path, "/CWE-server-error") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if strings.HasSuffix(path, "/not-found") || strings.HasSuffix(path, "/CWE-not-found") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// 默认返回404
		fmt.Printf("找不到匹配的路径，返回404: %s\n", path)
		http.NotFound(w, r)
	})

	return httptest.NewServer(mux)
}

func TestFetchCategoryComprehensive(t *testing.T) {
	server := setupCategoryTestServer()
	defer server.Close()

	// 打印服务器URL以便调试
	t.Logf("测试服务器地址: %s", server.URL)

	apiClient := NewAPIClientWithOptions(server.URL, DefaultTimeout)
	// 输出将要发送的请求
	t.Logf("将发送请求到: %s/cwe/category/CWE-xxx", server.URL)

	fetcher := NewDataFetcherWithClient(apiClient)

	// 测试正常情况
	category, err := fetcher.FetchCategory("1000")
	if err != nil {
		t.Errorf("正常FetchCategory失败: %v", err)
		return // 避免空指针异常
	}

	if category.ID != "CWE-1000" || category.Name != "Test Category" {
		t.Errorf("FetchCategory返回的数据不符: %+v", category)
	}

	// 测试ID格式不标准
	category, err = fetcher.FetchCategory("CWE-1001")
	if err != nil {
		t.Errorf("非标准ID格式FetchCategory失败: %v", err)
		return
	}
	if category.ID != "CWE-1001" || category.Name != "Another Test Category" {
		t.Errorf("非标准ID格式FetchCategory返回的数据不符: %+v", category)
	}

	// 测试ID是数字类型
	category, err = fetcher.FetchCategory("1002")
	if err != nil {
		t.Errorf("数字ID FetchCategory失败: %v", err)
		return
	}
	if category.ID != "CWE-1002" || category.Name != "Number ID Category" {
		t.Errorf("数字ID FetchCategory返回的数据不符: %+v", category)
	}

	// 测试缺少描述字段
	category, err = fetcher.FetchCategory("1003")
	if err != nil {
		t.Errorf("缺少描述的FetchCategory失败: %v", err)
		return
	}
	if category.ID != "CWE-1003" || category.Name != "No Description Category" || category.Description != "" {
		t.Errorf("缺少描述的FetchCategory返回的数据不符: %+v", category)
	}

	// 测试使用摘要替代描述
	category, err = fetcher.FetchCategory("1004")
	if err != nil {
		t.Errorf("使用摘要的FetchCategory失败: %v", err)
		return
	}
	if category.ID != "CWE-1004" || category.Description != "This category uses summary instead of description" {
		t.Errorf("使用摘要的FetchCategory返回的数据不符: %+v", category)
	}

	// 测试字段名称大小写不同
	category, err = fetcher.FetchCategory("1005")
	if err != nil {
		t.Errorf("字段名称大小写不同的FetchCategory失败: %v", err)
		return
	}
	if category.ID != "CWE-1005" || category.Name != "Different Case Category" {
		t.Errorf("字段名称大小写不同的FetchCategory返回的数据不符: %+v", category)
	}

	// 测试错误情况

	// 测试无效ID格式
	_, err = fetcher.FetchCategory("invalid-format-id")
	if err == nil {
		t.Error("无效ID格式应该返回错误")
	}

	// 测试缺少ID字段
	_, err = fetcher.FetchCategory("missing-id")
	if err == nil {
		t.Error("缺少ID字段应该返回错误")
	}

	// 测试无效JSON
	_, err = fetcher.FetchCategory("invalid-json")
	if err == nil {
		t.Error("无效JSON应该返回错误")
	}

	// 测试服务器错误
	_, err = fetcher.FetchCategory("server-error")
	if err == nil {
		t.Error("服务器错误应该返回错误")
	}

	// 测试404错误
	_, err = fetcher.FetchCategory("not-found")
	if err == nil {
		t.Error("404错误应该返回错误")
	}

	// 测试连接错误
	badClient := NewAPIClientWithOptions("http://nonexistent-server", DefaultTimeout)
	badFetcher := NewDataFetcherWithClient(badClient)
	_, err = badFetcher.FetchCategory("1000")
	if err == nil {
		t.Error("连接错误应该返回错误")
	}
}
