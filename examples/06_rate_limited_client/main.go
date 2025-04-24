package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPRateLimiter 用于控制HTTP请求的发送频率
type HTTPRateLimiter struct {
	interval    time.Duration // 请求间隔时间
	lastRequest time.Time     // 上次请求的时间
	mutex       sync.Mutex    // 互斥锁，用于在并发环境下保护lastRequest
}

// NewHTTPRateLimiter 创建一个新的HTTP请求速率限制器
func NewHTTPRateLimiter(interval time.Duration) *HTTPRateLimiter {
	return &HTTPRateLimiter{
		interval:    interval,
		lastRequest: time.Now().Add(-interval), // 初始化为可以立即发送第一个请求
	}
}

// WaitForRequest 根据速率限制等待，确保距离上次请求至少间隔指定时间
func (r *HTTPRateLimiter) WaitForRequest() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRequest)

	// 如果距离上次请求的时间小于指定间隔，则等待
	if elapsed < r.interval {
		waitTime := r.interval - elapsed
		time.Sleep(waitTime)
		now = time.Now()
	}

	// 更新上次请求时间
	r.lastRequest = now
}

// SetInterval 设置请求间隔
func (r *HTTPRateLimiter) SetInterval(interval time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.interval = interval
}

// RateLimitedHTTPClient 是一个带有速率限制功能的HTTP客户端
type RateLimitedHTTPClient struct {
	client      *http.Client     // 用于发送HTTP请求的客户端
	rateLimiter *HTTPRateLimiter // 用于控制请求速率的限制器
}

// NewRateLimitedHTTPClient 创建一个新的带速率限制的HTTP客户端
func NewRateLimitedHTTPClient(client *http.Client, limiter *HTTPRateLimiter) *RateLimitedHTTPClient {
	if client == nil {
		client = http.DefaultClient
	}

	if limiter == nil {
		limiter = NewHTTPRateLimiter(10 * time.Second)
	}

	return &RateLimitedHTTPClient{
		client:      client,
		rateLimiter: limiter,
	}
}

// Get 发送HTTP GET请求，并在发送前等待速率限制器的许可
func (c *RateLimitedHTTPClient) Get(url string) (*http.Response, error) {
	c.rateLimiter.WaitForRequest()
	return c.client.Get(url)
}

// Post 发送HTTP POST请求，并在发送前等待速率限制器的许可
func (c *RateLimitedHTTPClient) Post(url, contentType string, body string) (*http.Response, error) {
	c.rateLimiter.WaitForRequest()
	return c.client.Post(url, contentType, strings.NewReader(body))
}

func main() {
	fmt.Println("===== 速率限制HTTP客户端示例 =====")

	// 创建一个2秒1个请求的速率限制器
	limiter := NewHTTPRateLimiter(2 * time.Second)

	// 创建速率限制HTTP客户端
	client := NewRateLimitedHTTPClient(nil, limiter)

	// 要请求的URLs（使用httpbin.org作为测试服务）
	urls := []string{
		"https://httpbin.org/get?param=1",
		"https://httpbin.org/get?param=2",
		"https://httpbin.org/get?param=3",
	}

	fmt.Println("\n1. 基本速率限制测试 (2秒/请求)")
	fmt.Println("----------------------------")

	for i, url := range urls {
		start := time.Now()
		fmt.Printf("发送第%d个请求: %s\n", i+1, url)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("请求失败: %v\n", err)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("读取响应失败: %v\n", err)
			continue
		}

		duration := time.Since(start)
		fmt.Printf("收到响应: 状态码=%d, 内容长度=%d字节, 耗时=%v\n\n",
			resp.StatusCode, len(body), duration)
	}

	// 调整速率限制
	fmt.Println("\n2. 动态调整速率限制 (500毫秒/请求)")
	fmt.Println("--------------------------------")
	limiter.SetInterval(500 * time.Millisecond)

	for i, url := range urls[:2] {
		start := time.Now()
		fmt.Printf("发送第%d个请求: %s\n", i+1, url)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("请求失败: %v\n", err)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("读取响应失败: %v\n", err)
			continue
		}

		duration := time.Since(start)
		fmt.Printf("收到响应: 状态码=%d, 内容长度=%d字节, 耗时=%v\n\n",
			resp.StatusCode, len(body), duration)
	}

	// 测试POST请求
	fmt.Println("\n3. POST请求速率限制测试")
	fmt.Println("---------------------")

	start := time.Now()
	fmt.Println("发送POST请求: https://httpbin.org/post")

	data := "测试数据"
	resp, err := client.Post("https://httpbin.org/post", "text/plain", data)
	if err != nil {
		log.Printf("POST请求失败: %v\n", err)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Printf("读取响应失败: %v\n", err)
		return
	}

	duration := time.Since(start)
	fmt.Printf("收到响应: 状态码=%d, 内容长度=%d字节, 耗时=%v\n\n",
		resp.StatusCode, len(body), duration)

	fmt.Println("示例完成。")
}
