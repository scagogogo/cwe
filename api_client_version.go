package cwe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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
