package cwe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPClient 是一个综合HTTP客户端工具类
// 支持速率限制和自动重试功能
type HTTPClient struct {
	client      *http.Client     // 用于发送HTTP请求的底层客户端
	rateLimiter *HTTPRateLimiter // 速率限制器
	maxRetries  int              // 最大重试次数
	retryDelay  time.Duration    // 重试之间的延迟
}

// ClientOption 是HTTP客户端的配置选项函数类型
type ClientOption func(*HTTPClient)

// WithMaxRetries 设置最大重试次数
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *HTTPClient) {
		if maxRetries > 0 {
			c.maxRetries = maxRetries
		}
	}
}

// WithRetryInterval 设置重试间隔
func WithRetryInterval(interval time.Duration) ClientOption {
	return func(c *HTTPClient) {
		if interval > 0 {
			c.retryDelay = interval
		}
	}
}

// WithRateLimit 设置每秒最大请求数量
func WithRateLimit(requestsPerSecond float64) ClientOption {
	return func(c *HTTPClient) {
		if requestsPerSecond > 0 {
			interval := time.Duration(1000.0 / requestsPerSecond * float64(time.Millisecond))
			c.rateLimiter = NewHTTPRateLimiter(interval)
		}
	}
}

// NewHttpClient 使用选项模式创建一个新的HTTP客户端
func NewHttpClient(options ...ClientOption) *HTTPClient {
	// 创建默认客户端
	client := &HTTPClient{
		client:      &http.Client{Timeout: 30 * time.Second},
		rateLimiter: NewHTTPRateLimiter(1 * time.Second), // 默认每秒1个请求
		maxRetries:  3,                                   // 默认最多重试3次
		retryDelay:  1 * time.Second,                     // 默认重试间隔1秒
	}

	// 应用所有选项
	for _, option := range options {
		option(client)
	}

	return client
}

// Close 关闭HTTP客户端，清理资源
func (c *HTTPClient) Close() {
	// 目前没有需要清理的资源，但保留此方法以符合接口要求
}

// Get 发送HTTP GET请求，支持上下文控制
func (c *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post 发送HTTP POST请求，支持上下文控制
func (c *HTTPClient) Post(ctx context.Context, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.Do(req)
}

// GetSimple 发送简单的HTTP GET请求，支持速率限制和自动重试
func (c *HTTPClient) GetSimple(url string) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// 第一次请求和重试都需要等待速率限制
		c.rateLimiter.WaitForRequest()

		// 重试时增加延迟
		if attempt > 0 {
			time.Sleep(c.retryDelay)
		}

		resp, err = c.client.Get(url)

		// 请求成功且状态码小于500，视为成功
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		// 请求失败，关闭响应体防止资源泄露
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}

		// 达到最大重试次数，返回最后一次错误
		if attempt == c.maxRetries {
			if err != nil {
				return nil, fmt.Errorf("达到最大重试次数(%d)后请求仍然失败: %w", c.maxRetries, err)
			}
			return resp, fmt.Errorf("达到最大重试次数(%d)后请求仍然返回错误状态码: %d", c.maxRetries, resp.StatusCode)
		}
	}

	// 理论上不会执行到这里
	return nil, fmt.Errorf("未知错误")
}

// PostSimple 发送简单的HTTP POST请求，支持速率限制和自动重试
// 注意: 由于body可能不能重用，此方法会将body完全读入内存以便重试
func (c *HTTPClient) PostSimple(url, contentType string, body io.Reader) (*http.Response, error) {
	// 如果body为nil，可以直接使用不需要特殊处理
	if body == nil {
		return c.doWithRetry(func() (*http.Response, error) {
			return c.client.Post(url, contentType, nil)
		})
	}

	// 读取body内容以便重用
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %w", err)
	}

	return c.doWithRetry(func() (*http.Response, error) {
		// 每次请求都创建新的bytes.Reader
		bodyReader := bytes.NewReader(bodyBytes)
		return c.client.Post(url, contentType, bodyReader)
	})
}

// PostForm 发送HTTP POST表单请求，支持速率限制和自动重试
func (c *HTTPClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.doWithRetry(func() (*http.Response, error) {
		return c.client.PostForm(url, data)
	})
}

// Do 执行自定义的HTTP请求，支持速率限制和自动重试
// 注意: 由于req.Body可能不能重用，此方法会尝试将body读入内存以便重试
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	// 如果请求没有body，可以安全地重试
	if req.Body == nil {
		return c.doWithRetry(func() (*http.Response, error) {
			// 克隆请求以确保安全
			reqCopy := cloneRequest(req)
			return c.client.Do(reqCopy)
		})
	}

	// 读取body内容以便重用
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %w", err)
	}
	// 关闭原始请求体
	req.Body.Close()

	// 使用闭包保存原始请求和body数据
	return c.doWithRetry(func() (*http.Response, error) {
		reqCopy := cloneRequest(req)
		reqCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return c.client.Do(reqCopy)
	})
}

// doWithRetry 通用重试逻辑
func (c *HTTPClient) doWithRetry(requestFunc func() (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// 第一次请求和重试都需要等待速率限制
		c.rateLimiter.WaitForRequest()

		// 重试时增加延迟
		if attempt > 0 {
			time.Sleep(c.retryDelay)
		}

		resp, err = requestFunc()

		// 请求成功且状态码小于500，视为成功
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		// 请求失败，关闭响应体防止资源泄露
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}

		// 达到最大重试次数，返回最后一次错误
		if attempt == c.maxRetries {
			if err != nil {
				return nil, fmt.Errorf("达到最大重试次数(%d)后请求仍然失败: %w", c.maxRetries, err)
			}
			return resp, fmt.Errorf("达到最大重试次数(%d)后请求仍然返回错误状态码: %d", c.maxRetries, resp.StatusCode)
		}
	}

	// 理论上不会执行到这里
	return nil, fmt.Errorf("未知错误")
}

// cloneRequest 克隆HTTP请求对象
func cloneRequest(req *http.Request) *http.Request {
	// 创建新请求
	clone := &http.Request{
		Method:        req.Method,
		URL:           req.URL,
		Header:        make(http.Header),
		Host:          req.Host,
		ContentLength: req.ContentLength,
		Body:          req.Body, // 需要由调用方处理
	}

	// 复制头信息
	for k, v := range req.Header {
		clone.Header[k] = v
	}

	return clone
}

// SetRateLimiter 设置速率限制器
func (c *HTTPClient) SetRateLimiter(limiter *HTTPRateLimiter) {
	if limiter != nil {
		c.rateLimiter = limiter
	}
}

// GetRateLimiter 获取速率限制器
func (c *HTTPClient) GetRateLimiter() *HTTPRateLimiter {
	return c.rateLimiter
}

// SetMaxRetries 设置最大重试次数
func (c *HTTPClient) SetMaxRetries(maxRetries int) {
	if maxRetries > 0 {
		c.maxRetries = maxRetries
	}
}

// GetMaxRetries 获取最大重试次数
func (c *HTTPClient) GetMaxRetries() int {
	return c.maxRetries
}

// SetRetryDelay 设置重试间隔
func (c *HTTPClient) SetRetryDelay(delay time.Duration) {
	if delay > 0 {
		c.retryDelay = delay
	}
}

// GetRetryDelay 获取重试间隔
func (c *HTTPClient) GetRetryDelay() time.Duration {
	return c.retryDelay
}

// SetClient 设置底层HTTP客户端
func (c *HTTPClient) SetClient(client *http.Client) {
	if client != nil {
		c.client = client
	}
}

// GetClient 获取底层HTTP客户端
func (c *HTTPClient) GetClient() *http.Client {
	return c.client
}

// DefaultHTTPClient 默认的HTTP客户端实例
// - 30秒超时
// - 默认速率限制(10秒1个请求)
// - 最多重试3次
// - 重试间隔1秒
var DefaultHTTPClient = NewHttpClient()
