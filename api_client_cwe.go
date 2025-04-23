package cwe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

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
