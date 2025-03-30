package cwe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// GetVersion 获取当前CWE版本信息
func (c *APIClient) GetVersion() (string, error) {
	url := fmt.Sprintf("%s/cwe/version", c.baseURL)

	resp, err := c.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("获取CWE版本失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应体失败: %w", err)
	}

	var versionData map[string]interface{}
	if err := json.Unmarshal(body, &versionData); err != nil {
		return "", fmt.Errorf("解析JSON响应失败: %w", err)
	}

	if version, ok := versionData["version"].(string); ok {
		return version, nil
	}

	return "", fmt.Errorf("响应中没有找到版本信息")
}

// GetCWEs 通过ID列表获取多个CWE
func (c *APIClient) GetCWEs(ids []string) (map[string]interface{}, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("必须提供至少一个CWE ID")
	}

	idsStr := strings.Join(ids, ",")
	url := fmt.Sprintf("%s/cwe/%s", c.baseURL, idsStr)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取CWE信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	return result, nil
}

// GetWeakness 获取特定ID的弱点信息
func (c *APIClient) GetWeakness(id string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/cwe/weakness/%s", c.baseURL, id)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取弱点信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	// 检查响应中是否包含ID字段
	if _, exists := result["id"]; !exists {
		return nil, fmt.Errorf("响应中缺少ID字段")
	}

	return result, nil
}

// GetCategory 获取特定ID的类别信息
func (c *APIClient) GetCategory(id string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/cwe/category/%s", c.baseURL, id)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取类别信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	// 检查响应中是否包含ID字段
	if _, exists := result["id"]; !exists {
		return nil, fmt.Errorf("响应中缺少ID字段")
	}

	return result, nil
}

// GetView 获取特定ID的视图信息
func (c *APIClient) GetView(id string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/cwe/view/%s", c.baseURL, id)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取视图信息失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	// 检查响应中是否包含ID字段
	if _, exists := result["id"]; !exists {
		return nil, fmt.Errorf("响应中缺少ID字段")
	}

	return result, nil
}

// GetParents 获取特定CWE的父节点
func (c *APIClient) GetParents(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/parents", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取父节点失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result []string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	return result, nil
}

// GetChildren 获取特定CWE的子节点
func (c *APIClient) GetChildren(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/children", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取子节点失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result []string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	return result, nil
}

// GetAncestors 获取特定CWE的祖先节点
func (c *APIClient) GetAncestors(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/ancestors", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取祖先节点失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result []string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	return result, nil
}

// GetDescendants 获取特定CWE的后代节点
func (c *APIClient) GetDescendants(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/descendants", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取后代节点失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var result []string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	return result, nil
}
