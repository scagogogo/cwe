package cwe

import (
	"net/http"
	"testing"
	"time"
)

func TestAPIClient_RateLimit(t *testing.T) {
	// 创建一个使用较短速率限制的客户端
	interval := 500 * time.Millisecond
	limiter := NewHTTPRateLimiter(interval)
	client := NewAPIClientWithOptions("", 3*time.Second, limiter)

	// 记录第一个请求的开始时间
	start := time.Now()

	// 第一个请求应该立即通过
	_, err := client.GetVersion()
	if err != nil {
		t.Fatalf("第一个请求失败: %v", err)
	}

	firstDuration := time.Since(start)
	if firstDuration > 100*time.Millisecond {
		t.Logf("第一个请求耗时较长: %v", firstDuration)
	}

	// 第二个请求应该等待速率限制
	start = time.Now()
	_, err = client.GetVersion()
	if err != nil {
		t.Fatalf("第二个请求失败: %v", err)
	}

	secondDuration := time.Since(start)
	if secondDuration < interval {
		t.Errorf("第二个请求应该等待至少 %v，但只等待了 %v", interval, secondDuration)
	}
}

func TestAPIClient_CustomHTTPClient(t *testing.T) {
	// 创建一个自定义的HTTP客户端
	newHTTPClient := NewHttpClient(
		WithRateLimit(10), // 每秒10个请求
		WithMaxRetries(3),
		WithRetryInterval(time.Second),
	)
	newHTTPClient.SetClient(&http.Client{Timeout: 3 * time.Second})

	client := NewAPIClient()
	client.SetHTTPClient(newHTTPClient)

	// 验证是否成功设置了新的HTTP客户端
	if client.GetHTTPClient() != newHTTPClient {
		t.Error("设置HTTP客户端失败")
	}

	// 验证客户端仍然可以正常工作
	_, err := client.GetVersion()
	if err != nil {
		t.Errorf("使用新的HTTP客户端请求失败: %v", err)
	}
}
