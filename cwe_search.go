package cwe

import (
	"strings"
)

// FindByID 在CWE树中查找特定ID的节点
//
// 方法功能:
// 递归搜索CWE树，查找与指定ID匹配的CWE节点。
// 搜索从根节点开始，依次检查每个节点及其子节点。
// 该方法使用深度优先搜索算法，适用于任何深度的CWE树。
//
// 参数:
// - root: *CWE - 搜索的起始节点，通常是CWE树的根节点
// - id: string - 要查找的CWE ID，通常格式为"CWE-数字"(如"CWE-79")
//
// 返回值:
// - *CWE: 如找到匹配ID的节点则返回该节点，否则返回nil
//
// 使用示例:
// ```go
// // 假设已有构建好的CWE树，根节点为rootCWE
// xss := FindByID(rootCWE, "CWE-79")
//
//	if xss != nil {
//	    fmt.Printf("找到XSS漏洞: %s - %s\n", xss.ID, xss.Name)
//	    fmt.Printf("描述: %s\n", xss.Description)
//	} else {
//
//	    fmt.Println("未找到XSS漏洞")
//	}
//
// ```
//
// 边界情况:
// - 如root为nil，返回nil
// - 如树中不存在匹配ID的节点，返回nil
// - 如树中存在循环引用，可能导致栈溢出
//
// 相关方法:
// - FindByKeyword(): 根据关键词在CWE树中查找节点
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
//
// 方法功能:
// 在CWE树中搜索名称或描述中包含指定关键词的所有节点。
// 搜索不区分大小写，且会检查每个节点及其所有子节点。
// 该方法使用深度优先搜索算法，适用于查找与特定主题相关的所有CWE。
//
// 参数:
// - root: *CWE - 搜索的起始节点，通常是CWE树的根节点
// - keyword: string - 要查找的关键词，不区分大小写
//
// 返回值:
// - []*CWE: 包含所有匹配节点的切片，如没有匹配项则返回空切片
//
// 使用示例:
// ```go
// // 查找与"injection"相关的所有CWE
// injectionCWEs := FindByKeyword(rootCWE, "injection")
//
// fmt.Printf("找到%d个与注入相关的CWE:\n", len(injectionCWEs))
//
//	for _, cwe := range injectionCWEs {
//	    fmt.Printf("- %s: %s\n", cwe.ID, cwe.Name)
//	}
//
// // 查找与"memory"相关的所有CWE
// memoryCWEs := FindByKeyword(rootCWE, "memory")
// fmt.Printf("找到%d个与内存相关的CWE\n", len(memoryCWEs))
// ```
//
// 边界情况:
// - 如root为nil，返回空切片
// - 如keyword为空字符串，可能会匹配大量节点
// - 如树中存在循环引用，可能导致栈溢出
//
// 性能考虑:
// - 对于大型CWE树，此方法可能需要遍历大量节点，性能可能较低
// - 搜索时会将所有文本转换为小写，这可能对多语言支持有影响
//
// 相关方法:
// - FindByID(): 根据ID在CWE树中查找节点
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
