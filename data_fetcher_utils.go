package cwe

import (
	"fmt"
	"strings"
)

// 辅助方法：从API响应转换为CWE结构
func (f *DataFetcher) convertToCWE(data map[string]interface{}) (*CWE, error) {
	// 提取基本信息
	var id, name, description, url, severity string

	// 获取ID
	if idValue, ok := data["id"].(string); ok {
		id = idValue
	} else if idValue, ok := data["ID"].(string); ok {
		id = idValue
	} else if idValue, ok := data["ID"].(float64); ok {
		id = fmt.Sprintf("CWE-%.0f", idValue)
	} else {
		return nil, fmt.Errorf("无法从数据中提取ID")
	}

	// 确保ID格式为CWE-xxx
	if !strings.HasPrefix(id, "CWE-") {
		id = "CWE-" + id
	}

	// 获取名称
	if nameValue, ok := data["name"].(string); ok {
		name = nameValue
	} else if nameValue, ok := data["Name"].(string); ok {
		name = nameValue
	} else {
		name = "未知名称"
	}

	// 获取描述
	if descValue, ok := data["description"].(string); ok {
		description = descValue
	} else if descValue, ok := data["Description"].(string); ok {
		description = descValue
	} else if summary, ok := data["summary"].(string); ok {
		description = summary
	}

	// 获取URL
	if urlValue, ok := data["url"].(string); ok {
		url = urlValue
	} else {
		// 构造一个可能的URL
		numericID := strings.TrimPrefix(id, "CWE-")
		url = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", numericID)
	}

	// 获取严重性
	if severityValue, ok := data["severity"].(string); ok {
		severity = severityValue
	} else if severityValue, ok := data["Severity"].(string); ok {
		severity = severityValue
	}

	// 创建CWE实例
	cwe := NewCWE(id, name)
	cwe.Description = description
	cwe.URL = url
	cwe.Severity = severity

	// 尝试提取缓解措施
	if mitigations, ok := data["mitigations"].([]interface{}); ok {
		for _, m := range mitigations {
			if mitigation, ok := m.(string); ok {
				cwe.Mitigations = append(cwe.Mitigations, mitigation)
			}
		}
	}

	// 尝试提取示例
	if examples, ok := data["examples"].([]interface{}); ok {
		for _, e := range examples {
			if example, ok := e.(string); ok {
				cwe.Examples = append(cwe.Examples, example)
			}
		}
	}

	return cwe, nil
}
