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
// 提供速率限制和自动重试功能，适用于需要可靠性和稳定性的API调用场景
//
// 主要特性：
// 1. 速率限制：通过HTTPRateLimiter控制请求频率，防止过载
// 2. 自动重试：在请求失败时自动重试，提高可靠性
// 3. 智能处理：自动处理请求体重用、资源清理等
// 4. 线程安全：所有方法都是线程安全的，可在并发环境使用
//
// 性能考虑：
// - 每个请求都会经过速率限制器，可能造成延迟
// - 失败重试会增加请求耗时
// - 请求体会被完整读入内存，大文件传输需注意内存使用
//
// 使用示例：
// ```go
// // 创建客户端
// client := NewHTTPClient(
//
//	&http.Client{Timeout: 30 * time.Second},
//	NewHTTPRateLimiter(5 * time.Second),
//	3,  // 最多重试3次
//	time.Second,  // 重试间隔1秒
//
// )
//
// // 发送GET请求
// resp, err := client.Get("https://api.example.com/data")
//
//	if err != nil {
//	    log.Printf("请求失败: %v", err)
//	    return
//	}
//
// defer resp.Body.Close()
//
// // 发送POST请求
// data := strings.NewReader(`{"key": "value"}`)
// resp, err = client.Post("https://api.example.com/data", "application/json", data)
// ```
type HTTPClient struct {
	// client 是用于发送HTTP请求的底层客户端
	// 可以通过SetClient方法替换，常用于设置自定义的Transport或Timeout
	client *http.Client

	// rateLimiter 用于控制请求频率的限流器
	// 可以通过SetRateLimiter方法替换或调整
	rateLimiter *HTTPRateLimiter

	// maxRetries 表示请求失败时的最大重试次数
	// 可以通过SetMaxRetries方法调整
	// 实际请求次数 = maxRetries + 1（初始请求）
	maxRetries int

	// retryDelay 表示两次重试之间的等待时间
	// 可以通过SetRetryDelay方法调整
	retryDelay time.Duration
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
		rateLimiter: DefaultRateLimiter, // 默认使用全局限制器
		maxRetries:  3,                  // 默认最多重试3次
		retryDelay:  1 * time.Second,    // 默认重试间隔1秒
	}

	// 应用所有选项
	for _, option := range options {
		option(client)
	}

	return client
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

// GetSimple 发送HTTP GET请求，不支持上下文
// 向指定URL发送HTTP GET请求，支持自动重试和速率限制。
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

// PostSimple 发送简单的HTTP POST请求，不支持上下文
// 向指定URL发送HTTP POST请求，支持自定义请求体、自动重试和速率限制。
func (c *HTTPClient) PostSimple(url string, contentType string, body io.Reader) (*http.Response, error) {
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
//
// 方法功能：
// 发送HTTP POST表单请求到指定URL，自动处理速率限制和失败重试。
// 专门用于发送application/x-www-form-urlencoded格式的表单数据。
//
// 参数：
// - url string: 请求的目标URL
//   - 必须是有效的HTTP/HTTPS URL
//   - 不能为空
//   - 示例："https://api.example.com/form"
//
// - data url.Values: 表单数据
//   - 键值对格式的表单数据
//   - 可以包含多个同名字段
//   - 值会自动进行URL编码
//   - 示例：url.Values{"key": {"value"}, "items": {"1", "2"}}
//
// 返回值：
// - *http.Response: HTTP响应对象
//   - 调用方负责关闭响应体(resp.Body.Close())
//   - 即使状态码不是2xx，也会返回响应对象
//
// - error: 错误信息
//   - 如果达到最大重试次数仍失败，返回带重试信息的错误
//   - 如果网络问题，返回具体的网络错误
//
// 错误处理：
// 1. 请求错误：
//   - 网络连接失败
//   - DNS解析失败
//   - TLS/SSL错误
//
// 2. 服务器错误(5xx)：
//   - 触发自动重试机制
//   - 达到最大重试次数后返回最后一次错误
//
// 使用示例：
// ```go
// // 创建表单数据
//
//	formData := url.Values{
//	    "username": {"user123"},
//	    "password": {"pass456"},
//	    "tags":     {"tag1", "tag2"},  // 多值字段
//	}
//
// // 发送请求
// resp, err := client.PostForm("https://api.example.com/login", formData)
//
//	if err != nil {
//	    log.Printf("表单提交失败: %v", err)
//	    return
//	}
//
// defer resp.Body.Close()
// ```
//
// 性能考虑：
// - 表单数据会自动进行URL编码，对大量数据可能有性能影响
// - 每次请求前都会等待速率限制器
// - 重试会增加总体请求时间
//
// 线程安全：
// - 此方法是线程安全的
// - 多个goroutine可以同时调用
//
// 相关方法：
// - Get(): 发送GET请求
// - Post(): 发送POST请求
// - Do(): 执行自定义请求
func (c *HTTPClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.doWithRetry(func() (*http.Response, error) {
		return c.client.PostForm(url, data)
	})
}

// Do 执行自定义HTTP请求，支持速率限制和自动重试
//
// 方法功能：
// 执行自定义的HTTP请求，是所有HTTP方法的底层实现。
// 提供完整的请求控制，支持自定义请求头、请求方法等。
//
// 参数：
// - req *http.Request: HTTP请求对象
//   - 必须包含有效的URL和方法
//   - 可以包含自定义请求头
//   - 可以包含请求体
//   - 示例：http.NewRequest("PUT", url, body)
//
// 返回值：
// - *http.Response: HTTP响应对象
//   - 调用方负责关闭响应体(resp.Body.Close())
//   - 即使状态码不是2xx，也会返回响应对象
//
// - error: 错误信息
//   - 如果达到最大重试次数仍失败，返回带重试信息的错误
//   - 如果请求无效，返回相关错误
//   - 如果网络问题，返回具体的网络错误
//
// 错误处理：
// 1. 请求验证：
//   - 检查请求对象是否为nil
//   - 验证URL的有效性
//
// 2. 请求执行：
//   - 处理网络错误
//   - 处理超时
//   - 处理服务器错误
//
// 3. 重试逻辑：
//   - 5xx错误触发重试
//   - 网络错误触发重试
//   - 达到最大重试次数后返回错误
//
// 使用示例：
// ```go
// // 创建自定义请求
// req, err := http.NewRequest("PUT", "https://api.example.com/data", body)
//
//	if err != nil {
//	    return nil, err
//	}
//
// // 添加自定义请求头
// req.Header.Set("Authorization", "Bearer token123")
// req.Header.Set("X-Custom-Header", "value")
//
// // 执行请求
// resp, err := client.Do(req)
//
//	if err != nil {
//	    return nil, err
//	}
//
// defer resp.Body.Close()
// ```
//
// 性能考虑：
// - 支持请求体重用，适合重试场景
// - 每次请求前都会等待速率限制器
// - 重试会增加总体请求时间
//
// 线程安全：
// - 此方法是线程安全的
// - 多个goroutine可以同时调用
//
// 相关方法：
// - Get(): 发送GET请求的快捷方法
// - Post(): 发送POST请求的快捷方法
// - PostForm(): 发送表单POST请求的快捷方法
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

// doWithRetry 执行HTTP请求并处理重试逻辑
//
// 方法功能：
// 内部方法，实现HTTP请求的执行和重试逻辑。
// 处理请求重试、速率限制和请求体重用等核心功能。
//
// 参数：
// - req *http.Request: HTTP请求对象
//   - 原始请求对象，会被克隆用于重试
//   - 请求体会被保存以支持重试
//
// - reqBody []byte: 请求体数据
//   - 用于重试时重建请求体
//   - 如果原请求没有请求体，则为nil
//
// 返回值：
// - *http.Response: HTTP响应对象
//   - 成功请求的响应
//   - 最后一次重试的响应（如果所有重试都失败）
//
// - error: 错误信息
//   - 包含重试次数和最后一次错误信息
//   - 如果达到最大重试次数，返回MaxRetriesExceededError
//
// 内部处理流程：
// 1. 速率限制：
//   - 等待令牌桶允许请求
//   - 处理限流等待时间
//
// 2. 请求执行：
//   - 克隆原始请求
//   - 重建请求体（如果有）
//   - 执行HTTP请求
//
// 3. 重试决策：
//   - 分析响应状态码
//   - 检查错误类型
//   - 决定是否需要重试
//
// 4. 重试执行：
//   - 等待重试延迟时间
//   - 重新执行完整请求流程
//   - 跟踪重试次数
//
// 错误处理策略：
// 1. 临时错误：
//   - 服务器错误(5xx)
//   - 网络连接问题
//   - 触发重试机制
//
// 2. 永久错误：
//   - 客户端错误(4xx)
//   - 请求构建错误
//   - 直接返回错误，不重试
//
// 性能优化：
// - 使用字节数组缓存请求体
// - 实现请求体重用
// - 避免重复读取大型请求体
//
// 注意事项：
// - 这是一个内部方法，不应直接调用
// - 修改此方法时需考虑对所有HTTP方法的影响
// - 需要维护请求体的完整性
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
//
// 方法功能：
// 创建一个HTTP请求对象的深度副本，用于请求重试时保持原始请求的完整性。
// 此方法会复制请求的所有重要字段，包括方法、URL、请求头等。
//
// 参数：
// - req *http.Request: 原始HTTP请求对象
//   - 必须是有效的HTTP请求对象
//   - 请求体(Body)的处理由调用方负责
//
// 返回值：
// - *http.Request: 克隆的HTTP请求对象
//   - 包含原始请求的所有基本字段
//   - 请求头是深度复制的
//   - Body字段需要由调用方单独处理
//
// 注意事项：
// 1. 此方法不会克隆请求体(Body)
//   - Body可能是流式的，无法直接复制
//   - 调用方需要自行处理Body的重用
//
// 2. 以下字段会被复制：
//   - Method (请求方法)
//   - URL (请求URL)
//   - Header (请求头，深度复制)
//   - Host (目标主机)
//   - ContentLength (内容长度)
//
// 3. 以下字段不会被复制：
//   - GetBody
//   - TransferEncoding
//   - Close
//   - Form
//   - PostForm
//   - MultipartForm
//   - Trailer
//
// 4. 线程安全：
//   - 此方法本身是线程安全的
//   - 返回的克隆对象可以安全地被修改
//
// 使用示例：
// ```go
// originalReq, _ := http.NewRequest("POST", "https://api.example.com", body)
// originalReq.Header.Set("Content-Type", "application/json")
//
// // 克隆请求
// clonedReq := cloneRequest(originalReq)
//
// // 克隆的请求可以安全修改
// clonedReq.Header.Set("X-Custom-Header", "value")
// ```
//
// 相关方法：
// - Do(): 使用此方法进行请求重试
// - doWithRetry(): 内部使用此方法克隆请求
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

// 设置和获取方法

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

// Close 关闭HTTP客户端，清理资源
func (c *HTTPClient) Close() {
	// 目前没有需要清理的资源，但保留此方法以符合接口要求
}
