package cwe

import (
	"strings"
)

// FindByID 在CWE树中查找特定ID的节点
func FindByID(root *CWE, id string) *CWE {
	if root == nil {
		return nil
	}

	if root.ID == id {
		return root
	}

	for _, child := range root.Children {
		if found := FindByID(child, id); found != nil {
			return found
		}
	}

	return nil
}

// FindByKeyword 在CWE树中查找名称或描述包含关键词的节点
func FindByKeyword(root *CWE, keyword string) []*CWE {
	result := make([]*CWE, 0)

	if root == nil {
		return result
	}

	keyword = strings.ToLower(keyword)

	// 递归搜索树
	var search func(node *CWE)
	search = func(node *CWE) {
		// 检查当前节点
		if strings.Contains(strings.ToLower(node.Name), keyword) ||
			strings.Contains(strings.ToLower(node.Description), keyword) {
			result = append(result, node)
		}

		// 检查子节点
		for _, child := range node.Children {
			search(child)
		}
	}

	search(root)
	return result
}
