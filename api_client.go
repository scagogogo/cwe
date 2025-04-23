package cwe

import (
	"net/http"
	"time"
)

// 文档： https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md

const (
	// BaseURL 是CWE REST API的根URL
	BaseURL = "https://cwe-api.mitre.org/api/v1"

	// DefaultTimeout 是HTTP请求的默认超时时间
	DefaultTimeout = 30 * time.Second
)

// APIClient 表示CWE REST API的客户端
type APIClient struct {
	// HTTP客户端
	client *http.Client

	// API根URL
	baseURL string
}

// NewAPIClient 创建一个新的API客户端
func NewAPIClient() *APIClient {
	return &APIClient{
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: BaseURL,
	}
}

// NewAPIClientWithOptions 使用自定义选项创建API客户端
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
