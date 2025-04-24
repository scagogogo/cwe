package cwe

import (
	"fmt"
	"strings"
)

// FetchMultiple 获取多个CWE并转换为Registry
func (f *DataFetcher) FetchMultiple(ids []string) (*Registry, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("必须提供至少一个CWE ID")
	}

	// 规范化IDs
	normalizedIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		normalized, err := ParseCWEID(id)
		if err != nil {
			return nil, err
		}
		normalizedIDs = append(normalizedIDs, normalized)
	}

	// 从API获取数据
	data, err := f.client.GetCWEs(normalizedIDs)
	if err != nil {
		return nil, err
	}

	// 创建Registry
	registry := NewRegistry()

	// 处理返回的数据
	for _, item := range data {
		itemData, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		cwe, err := f.convertToCWE(itemData)
		if err != nil {
			continue
		}

		registry.Register(cwe)
	}

	return registry, nil
}

// PopulateChildrenRecursive 递归获取并填充子节点
func (f *DataFetcher) PopulateChildrenRecursive(cwe *CWE, viewID string) error {
	// 获取当前节点的直接子节点
	childrenIDs, err := f.client.GetChildren(cwe.ID, viewID)
	if err != nil {
		return err
	}

	// 没有子节点，直接返回
	if len(childrenIDs) == 0 {
		return nil
	}

	// 为每个子节点ID获取完整数据
	for _, childID := range childrenIDs {
		// 检查是否已经是标准格式
		if !strings.HasPrefix(childID, "CWE-") {
			childID = "CWE-" + childID
		}

		// 尝试获取子节点
		child, err := f.FetchWeakness(childID)
		if err != nil {
			// 如果不是weakness，尝试作为category获取
			child, err = f.FetchCategory(childID)
			if err != nil {
				// 跳过无法获取的节点
				continue
			}
		}

		// 添加为子节点
		cwe.AddChild(child)

		// 递归处理子节点的子节点
		err = f.PopulateChildrenRecursive(child, viewID)
		if err != nil {
			// 处理错误但继续其他节点
			continue
		}
	}

	return nil
}
