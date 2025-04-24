package cwe

import (
	"io"
	"net/http"
	"net/url"
	"time"
)

// RateLimitedHTTPClient 是一个带有速率限制功能的HTTP客户端
// 它封装了标准库的http.Client，并通过HTTPRateLimiter来控制请求速率
type RateLimitedHTTPClient struct {
	client      *http.Client     // 用于发送HTTP请求的客户端
	rateLimiter *HTTPRateLimiter // 用于控制请求速率的限制器
}

// NewRateLimitedHTTPClient 创建一个新的带速率限制的HTTP客户端
// client: 可选，用于发送HTTP请求的客户端，如果为nil则使用http.DefaultClient
// limiter: 可选，用于控制请求速率的限制器，如果为nil则使用DefaultRateLimiter
func NewRateLimitedHTTPClient(client *http.Client, limiter *HTTPRateLimiter) *RateLimitedHTTPClient {
	if client == nil {
		client = http.DefaultClient
	}

	if limiter == nil {
		limiter = DefaultRateLimiter
	}

	return &RateLimitedHTTPClient{
		client:      client,
		rateLimiter: limiter,
	}
}

// Get 发送HTTP GET请求，并在发送前等待速率限制器的许可
// 该方法会阻塞直到速率限制器允许发送请求
func (c *RateLimitedHTTPClient) Get(url string) (*http.Response, error) {
	c.rateLimiter.WaitForRequest()
	return c.client.Get(url)
}

// Post 发送HTTP POST请求，并在发送前等待速率限制器的许可
// 该方法会阻塞直到速率限制器允许发送请求
func (c *RateLimitedHTTPClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	c.rateLimiter.WaitForRequest()
	return c.client.Post(url, contentType, body)
}

// PostForm 发送HTTP POST表单请求，并在发送前等待速率限制器的许可
// 该方法会阻塞直到速率限制器允许发送请求
func (c *RateLimitedHTTPClient) PostForm(url string, data url.Values) (*http.Response, error) {
	c.rateLimiter.WaitForRequest()
	return c.client.PostForm(url, data)
}

// Do 执行自定义的HTTP请求，并在发送前等待速率限制器的许可
// 该方法会阻塞直到速率限制器允许发送请求
func (c *RateLimitedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.rateLimiter.WaitForRequest()
	return c.client.Do(req)
}

// SetRateLimiter 设置新的速率限制器
func (c *RateLimitedHTTPClient) SetRateLimiter(limiter *HTTPRateLimiter) {
	c.rateLimiter = limiter
}

// GetRateLimiter 获取当前的速率限制器
func (c *RateLimitedHTTPClient) GetRateLimiter() *HTTPRateLimiter {
	return c.rateLimiter
}

// SetClient 设置新的HTTP客户端
func (c *RateLimitedHTTPClient) SetClient(client *http.Client) {
	c.client = client
}

// GetClient 获取当前的HTTP客户端
func (c *RateLimitedHTTPClient) GetClient() *http.Client {
	return c.client
}

// DefaultRateLimitedClient 是默认的带速率限制的HTTP客户端
// 它使用http.DefaultClient和DefaultRateLimiter（10秒1个请求）
var DefaultRateLimitedClient = NewRateLimitedHTTPClient(http.DefaultClient, DefaultRateLimiter)

// DefaultTimeoutRateLimitedClient 是带有超时设置的速率限制HTTP客户端
// 默认10秒超时，10秒1个请求的速率限制
var DefaultTimeoutRateLimitedClient = NewRateLimitedHTTPClient(&http.Client{
	Timeout: 10 * time.Second,
}, DefaultRateLimiter)
