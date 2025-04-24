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

// APIClient 表示CWE REST API的客户端
// 用于与CWE REST API进行交互，执行各种查询操作
// 此客户端是线程安全的，可以在多个goroutine中并发使用
type APIClient struct {
	// client 是用于发送HTTP请求的客户端
	// 包含超时设置和其他HTTP相关配置
	client *http.Client

	// baseURL 是API的基础URL
	// 所有的API请求都将基于此URL构建
	baseURL string
}

// NewAPIClient 创建一个新的API客户端
//
// 方法功能:
// 使用默认配置创建一个新的CWE API客户端实例。默认配置包括:
// - 使用BaseURL常量作为API基础URL
// - 使用DefaultTimeout常量(30秒)作为HTTP请求超时时间
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
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: BaseURL,
	}
}

// NewAPIClientWithOptions 使用自定义选项创建API客户端
//
// 方法功能:
// 使用自定义配置创建一个新的CWE API客户端实例。允许指定自定义的API基础URL和HTTP请求超时时间。
// 如果参数为空或无效值，则使用默认值代替。
//
// 参数:
// - baseURL: string - 自定义API基础URL。如为空字符串，则使用默认BaseURL
// - timeout: time.Duration - 自定义HTTP请求超时时间。如小于等于0，则使用默认DefaultTimeout
//
// 返回值:
// - *APIClient: 根据指定配置创建的API客户端实例
//
// 使用示例:
// ```go
// // 使用自定义URL和60秒超时
// client := cwe.NewAPIClientWithOptions("https://custom-cwe-api.example.com/api/v1", 60*time.Second)
//
// // 使用默认URL但自定义超时
// client := cwe.NewAPIClientWithOptions("", 10*time.Second)
// ```
func NewAPIClientWithOptions(baseURL string, timeout time.Duration) *APIClient {
	if baseURL == "" {
		baseURL = BaseURL
	}

	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &APIClient{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
	}
}
