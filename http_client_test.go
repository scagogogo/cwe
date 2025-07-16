package cwe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPClient_Get(t *testing.T) {
	// 创建测试服务器，模拟不同的响应情况
	serverCallCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCallCount++

		// 模拟第一次请求失败，返回500错误
		if serverCallCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "服务器错误"}`))
			return
		}

		// 第二次请求成功
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok", "message": "成功"}`))
	}))
	defer server.Close()

	// 创建测试客户端，使用较短的重试延迟以加快测试速度
	client := NewHttpClient(
		WithMaxRetries(2),
		WithRetryInterval(50*time.Millisecond),
		WithRateLimit(100), // 100 requests per second = 10ms interval
	)

	// 设置自定义HTTP客户端
	client.SetClient(&http.Client{Timeout: 1 * time.Second})

	// 发送请求
	resp, err := client.Get(context.Background(), server.URL)

	// 验证结果
	if err != nil {
		t.Fatalf("请求应该成功，但返回错误: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("预期状态码为200，实际为: %d", resp.StatusCode)
	}

	// 验证请求次数
	if serverCallCount != 2 {
		t.Errorf("预期服务器被调用2次，实际为: %d", serverCallCount)
	}
}

func TestHTTPClient_Post(t *testing.T) {
	// 创建测试服务器，模拟不同的响应情况
	serverCallCount := 0
	requestBodies := make([]string, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCallCount++

		// 读取请求体
		var body []byte
		buffer := make([]byte, 1024)
		n, _ := r.Body.Read(buffer)
		body = buffer[:n]
		requestBodies = append(requestBodies, string(body))

		// 模拟第一次请求失败，返回500错误
		if serverCallCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// 第二次请求成功
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// 创建测试客户端
	client := NewHttpClient(
		WithMaxRetries(2),
		WithRetryInterval(50*time.Millisecond),
		WithRateLimit(100), // 100 requests per second
	)
	client.SetClient(&http.Client{Timeout: 1 * time.Second})

	// 发送POST请求
	postBody := `{"test": "data"}`
	resp, err := client.Post(context.Background(), server.URL, []byte(postBody))

	// 验证结果
	if err != nil {
		t.Fatalf("POST请求应该成功，但返回错误: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("预期状态码为200，实际为: %d", resp.StatusCode)
	}

	// 验证请求次数
	if serverCallCount != 2 {
		t.Errorf("预期服务器被调用2次，实际为: %d", serverCallCount)
	}

	// 验证请求体在重试时被正确重用
	if len(requestBodies) != 2 {
		t.Fatalf("预期有2个请求体，实际为: %d", len(requestBodies))
	}

	if !strings.Contains(requestBodies[0], "test") || !strings.Contains(requestBodies[1], "test") {
		t.Errorf("请求体在重试时未被正确重用")
	}
}

func TestHTTPClient_MaxRetriesExceeded(t *testing.T) {
	// 创建始终返回错误的测试服务器
	serverCallCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCallCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// 创建测试客户端，只允许1次重试
	client := NewHttpClient(
		WithMaxRetries(1), // 最多重试1次(总共2次请求)
		WithRetryInterval(50*time.Millisecond),
		WithRateLimit(100),
	)
	client.SetClient(&http.Client{Timeout: 1 * time.Second})

	// 发送请求
	_, err := client.Get(context.Background(), server.URL)

	// 验证结果
	if err == nil {
		t.Fatal("预期请求应该失败，但实际成功")
	}

	if !strings.Contains(err.Error(), "达到最大重试次数") {
		t.Errorf("错误消息中应包含重试信息，实际为: %v", err)
	}

	// 验证请求次数
	if serverCallCount != 2 { // 初始请求 + 1次重试
		t.Errorf("预期服务器被调用2次，实际为: %d", serverCallCount)
	}
}

func TestHTTPClient_RateLimiter(t *testing.T) {
	// 创建测试服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 创建带有严格速率限制的客户端
	interval := 200 * time.Millisecond
	client := NewHttpClient(
		WithMaxRetries(0), // 不重试
		WithRateLimit(5),  // 5 requests per second = 200ms interval
	)
	client.SetClient(&http.Client{Timeout: 1 * time.Second})

	// 发送第一个请求
	startTime := time.Now()
	_, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("第一个请求失败: %v", err)
	}
	firstDuration := time.Since(startTime)

	// 第一个请求应该很快完成
	if firstDuration > 100*time.Millisecond {
		t.Logf("第一个请求耗时较长，可能是测试环境原因: %v", firstDuration)
	}

	// 发送第二个请求
	startTime = time.Now()
	_, err = client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("第二个请求失败: %v", err)
	}
	secondDuration := time.Since(startTime)

	// 第二个请求应该等待速率限制
	if secondDuration < interval {
		t.Errorf("预期第二个请求至少等待 %v，实际等待 %v", interval, secondDuration)
	}
}

func TestHTTPClient_DefaultClient(t *testing.T) {
	// 验证默认客户端配置
	if DefaultHTTPClient.maxRetries != 3 {
		t.Errorf("预期默认最大重试次数为3，实际为: %d", DefaultHTTPClient.maxRetries)
	}

	if DefaultHTTPClient.retryDelay != 1*time.Second {
		t.Errorf("预期默认重试间隔为1秒，实际为: %v", DefaultHTTPClient.retryDelay)
	}

	if DefaultHTTPClient.rateLimiter != DefaultRateLimiter {
		t.Error("预期默认使用DefaultRateLimiter，但实际不是")
	}

	if DefaultHTTPClient.client.Timeout != 30*time.Second {
		t.Errorf("预期默认超时为30秒，实际为: %v", DefaultHTTPClient.client.Timeout)
	}
}

func TestHTTPClient_SetMethods(t *testing.T) {
	client := NewHttpClient()

	// 测试设置/获取速率限制器
	newLimiter := NewHTTPRateLimiter(5 * time.Second)
	client.SetRateLimiter(newLimiter)
	if client.GetRateLimiter() != newLimiter {
		t.Error("设置/获取速率限制器功能有误")
	}

	// 测试设置/获取最大重试次数
	client.SetMaxRetries(5)
	if client.GetMaxRetries() != 5 {
		t.Errorf("预期最大重试次数为5，实际为: %d", client.GetMaxRetries())
	}

	// 测试设置/获取重试延迟
	client.SetRetryDelay(2 * time.Second)
	if client.GetRetryDelay() != 2*time.Second {
		t.Errorf("预期重试延迟为2秒，实际为: %v", client.GetRetryDelay())
	}

	// 测试设置/获取HTTP客户端
	newHTTPClient := &http.Client{Timeout: 60 * time.Second}
	client.SetClient(newHTTPClient)
	if client.GetClient() != newHTTPClient {
		t.Error("设置/获取HTTP客户端功能有误")
	}
}
