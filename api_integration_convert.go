package cwe

import (
	"fmt"
)

// convertToCWE 将API响应转换为CWE
func convertToCWE(response interface{}) CWE {
	switch cwe := response.(type) {
	case map[string]interface{}:
		if typeVal, ok := cwe["Type"].(string); ok {
			switch typeVal {
			case "Weakness":
				return convertToWeakness(cwe)
			case "Category":
				return convertToCategory(cwe)
			case "View":
				return convertToView(cwe)
			}
		}
	}
	return nil
}

// convertToWeakness 将API响应转换为Weakness结构
func convertToWeakness(response map[string]interface{}) *Weakness {
	weakness := &Weakness{
		ID:          getStringOrDefault(response, "ID", ""),
		Name:        getStringOrDefault(response, "Name", ""),
		Description: getStringOrDefault(response, "Description", ""),
		Extended:    getStringOrDefault(response, "Extended_Description", ""),
		Status:      getStringOrDefault(response, "Status", ""),
		Relations:   make([]*Relation, 0),
	}

	if relations, ok := response["Related_Weaknesses"].([]interface{}); ok {
		for _, rel := range relations {
			if relData, ok := rel.(map[string]interface{}); ok {
				relation := &Relation{
					TargetID:   getStringOrDefault(relData, "CWE_ID", ""),
					Type:       getStringOrDefault(relData, "Nature", ""),
					View:       getStringOrDefault(relData, "View_ID", ""),
					Ordinal:    getStringOrDefault(relData, "Ordinal", ""),
					TargetName: "", // 通过后续调用填充
				}
				weakness.Relations = append(weakness.Relations, relation)
			}
		}
	}

	return weakness
}

// convertToCategory 将API响应转换为Category结构
func convertToCategory(response map[string]interface{}) *Category {
	category := &Category{
		ID:          getStringOrDefault(response, "ID", ""),
		Name:        getStringOrDefault(response, "Name", ""),
		Description: getStringOrDefault(response, "Description", ""),
		Extended:    getStringOrDefault(response, "Extended_Description", ""),
		Status:      getStringOrDefault(response, "Status", ""),
		Relations:   make([]*Relation, 0),
	}

	if memberships, ok := response["Category_Members"].([]interface{}); ok {
		for _, rel := range memberships {
			if relData, ok := rel.(map[string]interface{}); ok {
				relation := &Relation{
					TargetID:   getStringOrDefault(relData, "CWE_ID", ""),
					Type:       "HasMember",
					View:       getStringOrDefault(relData, "View_ID", ""),
					TargetName: "", // 通过后续调用填充
				}
				category.Relations = append(category.Relations, relation)
			}
		}
	}

	return category
}

// convertToView 将API响应转换为View结构
func convertToView(response map[string]interface{}) *View {
	view := &View{
		ID:          getStringOrDefault(response, "ID", ""),
		Name:        getStringOrDefault(response, "Name", ""),
		Description: getStringOrDefault(response, "Description", ""),
		Extended:    getStringOrDefault(response, "Extended_Description", ""),
		Status:      getStringOrDefault(response, "Status", ""),
		Relations:   make([]*Relation, 0),
		Type:        getStringOrDefault(response, "Type", ""),
		Objective:   getStringOrDefault(response, "Objective", ""),
		Audience:    getStringOrDefault(response, "Filter", ""),
	}

	if memberships, ok := response["Members"].([]interface{}); ok {
		for _, rel := range memberships {
			if relData, ok := rel.(map[string]interface{}); ok {
				relation := &Relation{
					TargetID:   getStringOrDefault(relData, "CWE_ID", ""),
					Type:       "HasMember",
					View:       view.ID,
					TargetName: "", // 通过后续调用填充
				}
				view.Relations = append(view.Relations, relation)
			}
		}
	}

	return view
}

// getStringOrDefault 从map中获取字符串，如果不存在则返回默认值
func getStringOrDefault(data map[string]interface{}, key, defaultValue string) string {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%v", v)
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return defaultValue
}
