package cwe

import (
	"net/http"
	"time"
)

// 文档： https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md

const (
	// BaseURL 是CWE REST API的根URL
	// 所有API请求将基于此URL构建
	BaseURL = "https://cwe-api.mitre.org/api/v1"

	// DefaultTimeout 是HTTP请求的默认超时时间
	// 设置为30秒，适用于大多数API调用场景
	DefaultTimeout = 30 * time.Second
)

// APIClient 表示CWE REST API客户端
// 用于与CWE REST API进行交互，执行各种查询操作
// 此客户端是线程安全的，可以在多个goroutine中并发使用
type APIClient struct {
	// client 是用于发送HTTP请求的客户端
	// 包含超时设置和速率限制功能
	client *HTTPClient

	// baseURL 是API的基础URL
	// 所有的API请求都将基于此URL构建
	baseURL string
}

// NewAPIClient 创建一个新的API客户端
//
// 方法功能:
// 使用默认配置创建一个新的CWE API客户端实例。默认配置包括:
// - 使用BaseURL常量作为API基础URL
// - 使用30秒超时
// - 默认使用10秒1个请求的速率限制
// - 失败时最多重试3次，重试间隔1秒
//
// 返回值:
// - *APIClient: 配置完成的API客户端实例
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// version, err := client.GetVersion()
//
//	if err != nil {
//	    log.Fatalf("获取CWE版本失败: %v", err)
//	}
//
// fmt.Printf("当前CWE版本: %s\n", version)
// ```
func NewAPIClient() *APIClient {
	return &APIClient{
		client: NewHttpClient(
			WithMaxRetries(3),
			WithRetryInterval(time.Second),
		),
		baseURL: BaseURL,
	}
}

// NewAPIClientWithOptions 使用自定义选项创建API客户端
//
// 方法功能:
// 使用自定义配置创建一个新的CWE API客户端实例。
// 如果参数为空或无效值，则使用默认值代替。
//
// 参数:
// - baseURL: string - 自定义API基础URL。如为空字符串，则使用默认BaseURL
// - timeout: time.Duration - HTTP请求超时时间。如<=0，则使用默认30秒
// - rateLimiter: *HTTPRateLimiter - 可选的自定义速率限制器。使用nil将使用默认限制器
//
// 返回值:
// - *APIClient: 根据指定配置创建的API客户端实例
//
// 使用示例:
// ```go
// // 创建自定义配置的客户端
// client := cwe.NewAPIClientWithOptions(
//
//	"https://custom-cwe-api.example.com/api/v1",
//	60 * time.Second,
//
// )
// ```
func NewAPIClientWithOptions(baseURL string, timeout time.Duration, rateLimiter ...*HTTPRateLimiter) *APIClient {
	if baseURL == "" {
		baseURL = BaseURL
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	options := []ClientOption{
		WithMaxRetries(3),
		WithRetryInterval(time.Second),
	}

	// 如果提供了自定义的速率限制器，将其添加到选项中
	if len(rateLimiter) > 0 && rateLimiter[0] != nil {
		options = append(options, func(c *HTTPClient) {
			c.SetRateLimiter(rateLimiter[0])
		})
	}

	// 创建自定义http.Client并传递给HTTPClient
	httpClient := NewHttpClient(options...)
	httpClient.SetClient(&http.Client{Timeout: timeout})

	return &APIClient{
		client:  httpClient,
		baseURL: baseURL,
	}
}

// GetHTTPClient 获取内部使用的HTTP客户端
//
// 方法功能:
// 获取API客户端内部使用的HTTP客户端，以便用户可以检查或修改HTTP客户端的属性
//
// 返回值:
// - *HTTPClient: 内部使用的HTTP客户端
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// httpClient := client.GetHTTPClient()
//
// // 获取并修改速率限制器
// rateLimiter := httpClient.GetRateLimiter()
// rateLimiter.SetInterval(5 * time.Second) // 修改为每5秒一个请求
// ```
func (c *APIClient) GetHTTPClient() *HTTPClient {
	return c.client
}

// SetHTTPClient 设置内部使用的HTTP客户端
//
// 方法功能:
// 替换API客户端内部使用的HTTP客户端，以便用户可以自定义HTTP请求行为
//
// 参数:
// - client: *HTTPClient - 新的HTTP客户端
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
//
// // 创建自定义的HTTP客户端
// customClient := cwe.NewHTTPClient(
//
//	&http.Client{Timeout: 60 * time.Second},
//	customRateLimiter,
//	5, // 最多重试5次
//	2 * time.Second, // 重试间隔2秒
//
// )
//
// // 设置自定义的HTTP客户端
// client.SetHTTPClient(customClient)
// ```
func (c *APIClient) SetHTTPClient(client *HTTPClient) {
	if client != nil {
		c.client = client
	}
}

// GetRateLimiter 获取API客户端使用的速率限制器
//
// 方法功能:
// 提供直接访问API客户端内部使用的速率限制器的方法，便于调整速率限制设置
//
// 返回值:
// - *HTTPRateLimiter: 速率限制器实例
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// limiter := client.GetRateLimiter()
//
// // 修改速率限制为每5秒一个请求
// limiter.SetInterval(5 * time.Second)
// ```
func (c *APIClient) GetRateLimiter() *HTTPRateLimiter {
	return c.client.GetRateLimiter()
}

// SetRateLimiter 设置API客户端使用的速率限制器
//
// 方法功能:
// 替换API客户端内部使用的速率限制器，便于动态调整速率限制策略
//
// 参数:
// - limiter: *HTTPRateLimiter - 新的速率限制器
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
//
// // 创建并设置新的速率限制器（每2秒一个请求）
// newLimiter := cwe.NewHTTPRateLimiter(2 * time.Second)
// client.SetRateLimiter(newLimiter)
// ```
func (c *APIClient) SetRateLimiter(limiter *HTTPRateLimiter) {
	c.client.SetRateLimiter(limiter)
}

// GetClient 获取底层的HTTP客户端
//
// 方法功能：
// 返回APIClient使用的底层HTTPClient实例。
// 这个方法主要用于测试和调试目的。
//
// 返回值：
// - *HTTPClient: 底层的HTTP客户端实例
func (c *APIClient) GetClient() *HTTPClient {
	return c.client
}
