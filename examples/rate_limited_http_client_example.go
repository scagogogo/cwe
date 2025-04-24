package examples

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/scagogogo/cwe"
)

// RateLimitedHTTPClientExample 演示了如何使用RateLimitedHTTPClient
// 此示例将发送多个HTTP请求，展示速率限制的效果
func RateLimitedHTTPClientExample() {
	// 创建自定义速率限制客户端（2秒1个请求）
	limiter := &cwe.HTTPRateLimiter{}
	limiter.SetInterval(2 * time.Second)
	client := &cwe.RateLimitedHTTPClient{}
	client.SetRateLimiter(limiter)
	client.SetClient(http.DefaultClient)

	// 发送多个请求，观察速率限制效果
	urls := []string{
		"https://httpbin.org/get",
		"https://httpbin.org/get",
		"https://httpbin.org/get",
	}

	fmt.Println("开始发送请求，速率限制：2秒1个请求")
	for i, url := range urls {
		start := time.Now()
		fmt.Printf("正在发送第%d个请求...\n", i+1)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("请求失败: %v\n", err)
			continue
		}

		duration := time.Since(start)
		fmt.Printf("第%d个请求完成，状态码: %d，耗时: %v\n", i+1, resp.StatusCode, duration)
		resp.Body.Close()
	}

	// 演示动态调整速率限制
	fmt.Println("\n动态调整速率限制")
	limiter.SetInterval(500 * time.Millisecond) // 调整为500毫秒1个请求

	fmt.Println("已将速率限制调整为：500毫秒1个请求")
	for i, url := range urls[:2] {
		start := time.Now()
		fmt.Printf("正在发送第%d个请求...\n", i+1)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("请求失败: %v\n", err)
			continue
		}

		duration := time.Since(start)
		fmt.Printf("第%d个请求完成，状态码: %d，耗时: %v\n", i+1, resp.StatusCode, duration)
		resp.Body.Close()
	}
}
