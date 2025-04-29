package cwe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetCWEs 通过ID列表获取多个CWE
//
// 方法功能:
// 根据提供的CWE ID列表从API获取多个CWE的详细信息。该方法允许一次请求多个CWE，提高查询效率。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - ids: []string - 要获取的CWE ID列表，不可为空，每个ID应符合CWE标准格式(如"CWE-79")
//
// 返回值:
// - map[string]*CWEWeakness: 包含所有请求的CWE信息的映射，键为CWE ID，值为对应的CWE结构体指针
// - error: 如遇到网络问题、无效参数、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 空ID列表: 返回"必须提供至少一个CWE ID"
// - 网络连接失败: 返回"获取CWE信息失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// cwes, err := client.GetCWEs([]string{"CWE-79", "CWE-89"})
//
//	if err != nil {
//	    log.Fatalf("获取CWE信息失败: %v", err)
//	}
//
// // 访问特定CWE信息
// xss, ok := cwes["CWE-79"]
//
//	if ok {
//	    fmt.Printf("XSS漏洞描述: %s\n", xss.Description)
//	}
//
// ```
//
// 数据样例:
// - 请求: ids = ["CWE-79", "CWE-89"]
// - 返回值(简化):
// ```
//
//	{
//	  "CWE-79": {
//	    "id": "CWE-79",
//	    "name": "Improper Neutralization of Input During Web Page Generation",
//	    "description": "...",
//	    ...
//	  },
//	  "CWE-89": {
//	    "id": "CWE-89",
//	    "name": "Improper Neutralization of Special Elements used in an SQL Command",
//	    "description": "...",
//	    ...
//	  }
//	}
//
// ```
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetWeakness(), GetCategory(), GetView()
func (c *APIClient) GetCWEs(ids []string) (map[string]*CWEWeakness, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("必须提供至少一个CWE ID")
	}

	idsStr := strings.Join(ids, ",")
	url := fmt.Sprintf("%s/cwe/%s", c.baseURL, idsStr)

	resp, err := c.client.Get(context.Background(), url)
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

	var cwesResp CWEsResponse
	if err := json.Unmarshal(body, &cwesResp); err != nil {
		// 如果解析为标准响应格式失败，尝试解析为原始映射
		var rawResult map[string]interface{}
		if jsonErr := json.Unmarshal(body, &rawResult); jsonErr != nil {
			return nil, fmt.Errorf("解析JSON响应失败: %w", err)
		}

		// 将原始映射转换为CWEWeakness映射
		result := make(map[string]*CWEWeakness)
		for id, data := range rawResult {
			if dataMap, ok := data.(map[string]interface{}); ok {
				cwe := &CWEWeakness{
					ID:      id,
					RawData: dataMap,
				}

				// 尝试获取基本字段
				if name, ok := dataMap["name"].(string); ok {
					cwe.Name = name
				}
				if desc, ok := dataMap["description"].(string); ok {
					cwe.Description = desc
				}
				if severity, ok := dataMap["severity"].(string); ok {
					cwe.Severity = severity
				}
				if url, ok := dataMap["url"].(string); ok {
					cwe.URL = url
				}

				result[id] = cwe
			}
		}
		return result, nil
	}

	// 使用标准格式的响应
	if cwesResp.CWEs != nil {
		return cwesResp.CWEs, nil
	}

	// 如果两种格式都解析失败，返回错误
	return nil, fmt.Errorf("响应格式无法识别")
}

// GetWeakness 获取特定ID的弱点信息
//
// 方法功能:
// 根据提供的ID从API获取特定CWE弱点(Weakness)的详细信息。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要获取的CWE弱点ID，格式应为"CWE-数字"或纯数字(如"CWE-79"或"79")
//
// 返回值:
// - *CWEWeakness: 包含请求的CWE弱点详细信息的结构体指针
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取弱点信息失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
// - 响应中缺少ID字段: 返回"响应中缺少ID字段"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// xss, err := client.GetWeakness("79") // 也可使用"CWE-79"
//
//	if err != nil {
//	    log.Fatalf("获取XSS弱点信息失败: %v", err)
//	}
//
// fmt.Printf("XSS漏洞名称: %s\n", xss.Name)
// fmt.Printf("XSS漏洞描述: %s\n", xss.Description)
// ```
//
// 数据样例:
// - 请求: id = "79"
// - 返回值(简化):
// ```
//
//	{
//	  "id": "CWE-79",
//	  "name": "Improper Neutralization of Input During Web Page Generation",
//	  "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
//	  "extended_description": "...",
//	  "likelihood_of_exploit": "High",
//	  ...
//	}
//
// ```
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetCWEs(), GetCategory(), GetView()
func (c *APIClient) GetWeakness(id string) (*CWEWeakness, error) {
	url := fmt.Sprintf("%s/cwe/weakness/%s", c.baseURL, id)

	resp, err := c.client.Get(context.Background(), url)
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

	var weaknessResp WeaknessResponse
	if err := json.Unmarshal(body, &weaknessResp); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	// 检查响应中是否包含弱点信息
	if len(weaknessResp.Weaknesses) == 0 {
		return nil, fmt.Errorf("响应中不包含弱点信息")
	}

	// 获取第一个弱点信息
	weakness := weaknessResp.Weaknesses[0]

	// 检查响应中是否包含ID字段
	if weakness.ID == "" {
		return nil, fmt.Errorf("响应中缺少ID字段")
	}

	return weakness, nil
}

// GetCategory 获取特定ID的类别信息
//
// 方法功能:
// 根据提供的ID从API获取特定CWE类别(Category)的详细信息。
// 类别在CWE中是对相关弱点的分组。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要获取的CWE类别ID，格式应为"CWE-数字"或纯数字(如"CWE-699"或"699")
//
// 返回值:
// - *CWECategory: 包含请求的CWE类别详细信息的结构体指针
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取类别信息失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
// - 响应中缺少ID字段: 返回"响应中缺少ID字段"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// category, err := client.GetCategory("699") // 软件开发错误类别
//
//	if err != nil {
//	    log.Fatalf("获取类别信息失败: %v", err)
//	}
//
// fmt.Printf("类别名称: %s\n", category.Name)
// fmt.Printf("类别描述: %s\n", category.Description)
// ```
//
// 数据样例:
// - 请求: id = "699"
// - 返回值(简化):
// ```
//
//	{
//	  "id": "CWE-699",
//	  "name": "Software Development",
//	  "description": "Weaknesses in this category are related to software development.",
//	  "members": ["CWE-355", "CWE-710", ...],
//	  ...
//	}
//
// ```
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetCWEs(), GetWeakness(), GetView()
func (c *APIClient) GetCategory(id string) (*CWECategory, error) {
	url := fmt.Sprintf("%s/cwe/category/%s", c.baseURL, id)

	resp, err := c.client.Get(context.Background(), url)
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

	var categoryResp CategoryResponse
	if err := json.Unmarshal(body, &categoryResp); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	// 检查响应中是否包含类别信息
	if len(categoryResp.Categories) == 0 {
		return nil, fmt.Errorf("响应中不包含类别信息")
	}

	// 获取第一个类别信息
	category := categoryResp.Categories[0]

	// 检查响应中是否包含ID字段
	if category.ID == "" {
		return nil, fmt.Errorf("响应中缺少ID字段")
	}

	return category, nil
}

// GetView 获取特定ID的视图信息
//
// 方法功能:
// 根据提供的ID从API获取特定CWE视图(View)的详细信息。
// 视图在CWE中表示从特定角度或上下文查看弱点的方式，如"研发视图"或"架构概念视图"。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要获取的CWE视图ID，格式应为"CWE-数字"或纯数字(如"CWE-1000"或"1000")
//
// 返回值:
// - *CWEView: 包含请求的CWE视图详细信息的结构体指针
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取视图信息失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
// - 响应中缺少ID字段: 返回"响应中缺少ID字段"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
// view, err := client.GetView("1000") // 研发视图
//
//	if err != nil {
//	    log.Fatalf("获取视图信息失败: %v", err)
//	}
//
// fmt.Printf("视图名称: %s\n", view.Name)
// fmt.Printf("视图描述: %s\n", view.Description)
// ```
//
// 数据样例:
// - 请求: id = "1000"
// - 返回值(简化):
// ```
//
//	{
//	  "id": "CWE-1000",
//	  "name": "Research Concepts",
//	  "description": "This view organizes weaknesses around concepts that are frequently used in research.",
//	  "members": ["CWE-118", "CWE-120", ...],
//	  ...
//	}
//
// ```
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetCWEs(), GetWeakness(), GetCategory()
func (c *APIClient) GetView(id string) (*CWEView, error) {
	url := fmt.Sprintf("%s/cwe/view/%s", c.baseURL, id)

	resp, err := c.client.Get(context.Background(), url)
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

	var viewResp ViewResponse
	if err := json.Unmarshal(body, &viewResp); err != nil {
		return nil, fmt.Errorf("解析JSON响应失败: %w", err)
	}

	// 检查响应中是否包含视图信息
	if len(viewResp.Views) == 0 {
		return nil, fmt.Errorf("响应中不包含视图信息")
	}

	// 获取第一个视图信息
	view := viewResp.Views[0]

	// 检查响应中是否包含ID字段
	if view.ID == "" {
		return nil, fmt.Errorf("响应中缺少ID字段")
	}

	return view, nil
}
