package cwe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GetVersion 获取当前CWE版本信息
//
// 方法功能:
// 从CWE API获取当前版本信息。该方法查询官方CWE API以获取最新的CWE版本标识符。
// 该方法是线程安全的，可以在并发环境中使用。
//
// 参数: 无
//
// 返回值:
// - string: 当前CWE版本标识符，例如"4.12"
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取CWE版本失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
// - 响应中没有version字段: 返回"响应中没有找到版本信息"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// version, err := client.GetVersion()
//
//	if err != nil {
//	    log.Fatalf("无法获取CWE版本: %v", err)
//	}
//
// fmt.Printf("当前CWE版本: %s\n", version)
// ```
//
// 数据样例:
// - 成功响应: {"version":"4.12","release_date":"2023-02-28"}
// - 返回值: "4.12"
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
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
