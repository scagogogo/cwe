package cwe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GetParents 获取特定CWE的父节点
//
// 方法功能:
// 获取给定CWE ID的直接父节点列表。可以选择性地指定视图ID来限制结果范围。
// 父节点是指在CWE层次结构中直接包含当前CWE的节点。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要查询的CWE ID，格式应为"CWE-数字"或纯数字(如"CWE-79"或"79")
// - viewID: string - 可选的视图ID，用于限制结果范围。如不需要，可传入空字符串
//
// 返回值:
// - []string: 父节点CWE ID的字符串数组
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取父节点失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
//
// // 获取CWE-79的所有父节点
// parents, err := client.GetParents("79", "")
//
//	if err != nil {
//	    log.Fatalf("获取父节点失败: %v", err)
//	}
//
// // 获取CWE-79在研发视图(1000)中的父节点
// parents, err := client.GetParents("79", "1000")
//
//	if err != nil {
//	    log.Fatalf("获取父节点失败: %v", err)
//	}
//
//	for _, parentID := range parents {
//	    fmt.Printf("父节点: %s\n", parentID)
//	}
//
// ```
//
// 数据样例:
// - 请求: id = "79", viewID = ""
// - 返回值: ["CWE-74", "CWE-725", "CWE-990"]
//
// - 请求: id = "79", viewID = "1000"
// - 返回值: ["CWE-74"]
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetChildren(), GetAncestors(), GetDescendants()
func (c *APIClient) GetParents(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/parents", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(context.Background(), url)
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
//
// 方法功能:
// 获取给定CWE ID的直接子节点列表。可以选择性地指定视图ID来限制结果范围。
// 子节点是指在CWE层次结构中直接被当前CWE包含的节点。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要查询的CWE ID，格式应为"CWE-数字"或纯数字(如"CWE-707"或"707")
// - viewID: string - 可选的视图ID，用于限制结果范围。如不需要，可传入空字符串
//
// 返回值:
// - []string: 子节点CWE ID的字符串数组
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取子节点失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
//
// // 获取CWE-707的所有子节点
// children, err := client.GetChildren("707", "")
//
//	if err != nil {
//	    log.Fatalf("获取子节点失败: %v", err)
//	}
//
// // 获取CWE-707在研发视图(1000)中的子节点
// children, err := client.GetChildren("707", "1000")
//
//	if err != nil {
//	    log.Fatalf("获取子节点失败: %v", err)
//	}
//
//	for _, childID := range children {
//	    fmt.Printf("子节点: %s\n", childID)
//	}
//
// ```
//
// 数据样例:
// - 请求: id = "707", viewID = ""
// - 返回值: ["CWE-20", "CWE-116", "CWE-119", "CWE-254"]
//
// - 请求: id = "707", viewID = "1000"
// - 返回值: ["CWE-20", "CWE-116", "CWE-119"]
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetParents(), GetAncestors(), GetDescendants()
func (c *APIClient) GetChildren(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/children", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(context.Background(), url)
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
//
// 方法功能:
// 获取给定CWE ID的所有祖先节点列表。可以选择性地指定视图ID来限制结果范围。
// 祖先节点包括父节点、父节点的父节点等，直到顶层节点。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要查询的CWE ID，格式应为"CWE-数字"或纯数字(如"CWE-79"或"79")
// - viewID: string - 可选的视图ID，用于限制结果范围。如不需要，可传入空字符串
//
// 返回值:
// - []string: 祖先节点CWE ID的字符串数组，按照层次顺序排列，从近到远
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取祖先节点失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
//
// // 获取CWE-79的所有祖先节点
// ancestors, err := client.GetAncestors("79", "")
//
//	if err != nil {
//	    log.Fatalf("获取祖先节点失败: %v", err)
//	}
//
// // 获取CWE-79在研发视图(1000)中的祖先节点
// ancestors, err := client.GetAncestors("79", "1000")
//
//	if err != nil {
//	    log.Fatalf("获取祖先节点失败: %v", err)
//	}
//
//	for _, ancestorID := range ancestors {
//	    fmt.Printf("祖先节点: %s\n", ancestorID)
//	}
//
// ```
//
// 数据样例:
// - 请求: id = "79", viewID = ""
// - 返回值: ["CWE-74", "CWE-725", "CWE-990", "CWE-707", "CWE-1000"]
//
// - 请求: id = "79", viewID = "1000"
// - 返回值: ["CWE-74", "CWE-707", "CWE-1000"]
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetParents(), GetChildren(), GetDescendants()
func (c *APIClient) GetAncestors(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/ancestors", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(context.Background(), url)
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
//
// 方法功能:
// 获取给定CWE ID的所有后代节点列表。可以选择性地指定视图ID来限制结果范围。
// 后代节点包括子节点、子节点的子节点等，直到叶子节点。
// 该方法是线程安全的，可在并发环境中使用。
//
// 参数:
// - id: string - 要查询的CWE ID，格式应为"CWE-数字"或纯数字(如"CWE-707"或"707")
// - viewID: string - 可选的视图ID，用于限制结果范围。如不需要，可传入空字符串
//
// 返回值:
// - []string: 后代节点CWE ID的字符串数组
// - error: 如遇到网络问题、API返回非200状态码或响应解析错误时返回相应错误
//
// 错误处理:
// - 网络连接失败: 返回"获取后代节点失败: <原始错误>"
// - API返回非200状态码: 返回"API请求失败，状态码: <状态码>"
// - 响应解析失败: 返回"解析JSON响应失败: <原始错误>"
//
// 使用示例:
// ```go
// client := cwe.NewAPIClient()
//
// // 获取CWE-707的所有后代节点
// descendants, err := client.GetDescendants("707", "")
//
//	if err != nil {
//	    log.Fatalf("获取后代节点失败: %v", err)
//	}
//
// // 获取CWE-707在研发视图(1000)中的后代节点
// descendants, err := client.GetDescendants("707", "1000")
//
//	if err != nil {
//	    log.Fatalf("获取后代节点失败: %v", err)
//	}
//
// fmt.Printf("后代节点数量: %d\n", len(descendants))
//
//	for _, descendantID := range descendants[:5] {
//	    fmt.Printf("后代节点: %s\n", descendantID)
//	}
//
// ```
//
// 数据样例:
// - 请求: id = "707", viewID = ""
// - 返回值: ["CWE-20", "CWE-116", "CWE-119", "CWE-74", "CWE-79", ...]
//
// - 请求: id = "707", viewID = "1000"
// - 返回值: ["CWE-20", "CWE-116", "CWE-119", "CWE-74", "CWE-79", ...]
//
// 相关信息:
// - API文档: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
// - 相关方法: GetParents(), GetChildren(), GetAncestors()
func (c *APIClient) GetDescendants(id string, viewID string) ([]string, error) {
	url := fmt.Sprintf("%s/cwe/%s/descendants", c.baseURL, id)
	if viewID != "" {
		url = fmt.Sprintf("%s?view=%s", url, viewID)
	}

	resp, err := c.client.Get(context.Background(), url)
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
