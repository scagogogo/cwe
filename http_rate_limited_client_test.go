package cwe

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitedHTTPClient(t *testing.T) {
	// 创建一个测试服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	// 创建一个200毫秒速率的限制器
	interval := 200 * time.Millisecond
	limiter := NewHTTPRateLimiter(interval)

	// 创建速率限制客户端
	client := NewRateLimitedHTTPClient(nil, limiter)

	// 第一个请求应该立即通过
	start := time.Now()
	_, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("第一个请求失败: %v", err)
	}
	firstDuration := time.Since(start)

	// 第一个请求应该几乎立即返回（考虑到网络延迟和测试服务器响应时间）
	if firstDuration > 100*time.Millisecond {
		t.Logf("第一个请求耗时较长，可能是网络延迟: %v", firstDuration)
	}

	// 第二个请求应该等待约200毫秒
	start = time.Now()
	_, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("第二个请求失败: %v", err)
	}
	secondDuration := time.Since(start)

	// 考虑到网络和处理开销，允许一定的误差
	// 但总时间不应小于速率限制间隔
	if secondDuration < interval {
		t.Errorf("第二个请求应至少等待 %v，但只等待了 %v", interval, secondDuration)
	}

	// 测试POST请求是否也受速率限制
	start = time.Now()
	_, err = client.Post(server.URL, "text/plain", nil)
	if err != nil {
		t.Fatalf("POST请求失败: %v", err)
	}
	postDuration := time.Since(start)

	if postDuration < interval {
		t.Errorf("POST请求应至少等待 %v，但只等待了 %v", interval, postDuration)
	}

	// 测试Do方法是否也受速率限制
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}

	start = time.Now()
	_, err = client.Do(req)
	if err != nil {
		t.Fatalf("Do请求失败: %v", err)
	}
	doDuration := time.Since(start)

	if doDuration < interval {
		t.Errorf("Do请求应至少等待 %v，但只等待了 %v", interval, doDuration)
	}

	// 测试更改速率限制器
	newLimiter := NewHTTPRateLimiter(50 * time.Millisecond)
	client.SetRateLimiter(newLimiter)

	// 验证是否成功设置了新的速率限制器
	if client.GetRateLimiter() != newLimiter {
		t.Errorf("设置新的速率限制器失败")
	}

	// 测试更改HTTP客户端
	newHTTPClient := &http.Client{Timeout: 5 * time.Second}
	client.SetClient(newHTTPClient)

	// 验证是否成功设置了新的HTTP客户端
	if client.GetClient() != newHTTPClient {
		t.Errorf("设置新的HTTP客户端失败")
	}
}
