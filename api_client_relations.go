package cwe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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

// GetAncestors 获取特定CWE的所有祖先节点
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

// GetDescendants 获取特定CWE的所有后代节点
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
