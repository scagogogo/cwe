package cwe

import (
	"fmt"
	"sort"
	"strings"
)

// BuildCWETreeWithView 根据视图ID构建完整的CWE树
func (f *DataFetcher) BuildCWETreeWithView(viewID string) (*Registry, error) {
	normalizedViewID, err := ParseCWEID(viewID)
	if err != nil {
		return nil, err
	}

	// 获取视图信息
	view, err := f.FetchView(normalizedViewID)
	if err != nil {
		return nil, fmt.Errorf("获取视图失败: %w", err)
	}

	registry := NewRegistry()
	registry.Register(view)
	registry.Root = view

	// 获取树中所有节点并添加到注册表
	err = f.populateTree(registry, view, normalizedViewID)
	if err != nil {
		return nil, fmt.Errorf("填充CWE树失败: %w", err)
	}

	return registry, nil
}

// 辅助方法：递归填充CWE树
func (f *DataFetcher) populateTree(registry *Registry, node *CWE, viewID string) error {
	// 获取当前节点的直接子节点
	childrenIDs, err := f.client.GetChildren(node.ID, viewID)
	if err != nil {
		return err
	}

	// 没有子节点，直接返回
	if len(childrenIDs) == 0 {
		return nil
	}

	// 为每个子节点ID获取完整数据并填充树
	for _, childID := range childrenIDs {
		// 检查是否已经是标准格式
		if !strings.HasPrefix(childID, "CWE-") {
			childID = "CWE-" + childID
		}

		// 检查是否已经在注册表中
		existingChild, err := registry.GetByID(childID)
		if err == nil {
			// 已存在，直接添加关系
			node.AddChild(existingChild)
			continue
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

		// 添加到注册表
		registry.Register(child)

		// 添加为子节点
		node.AddChild(child)

		// 递归处理子节点
		err = f.populateTree(registry, child, viewID)
		if err != nil {
			// 处理错误但继续其他节点
			continue
		}
	}

	return nil
}

// BuildCWETree 构建CWE树
func (f *DataFetcher) BuildCWETree(ids []string) (map[string]*CWE, []*TreeNode, error) {
	// 获取CWEs
	registry, err := f.FetchMultiple(ids)
	if err != nil {
		return nil, nil, err
	}

	// 构建根节点列表
	rootNodes := make([]*TreeNode, 0)
	cweMap := make(map[string]*CWE)

	// 填充CWE映射
	for id, cwe := range registry.Entries {
		cweMap[id] = cwe
	}

	// 为每个CWE创建树节点
	nodeMap := make(map[string]*TreeNode)
	for id, cwe := range registry.Entries {
		node := NewTreeNode(cwe)
		nodeMap[id] = node
	}

	// 建立树结构
	for id, cwe := range registry.Entries {
		// 检查此CWE是否有父节点，如果没有，它就是根节点
		isRoot := cwe.Parent == nil
		if !isRoot && cwe.Parent.ID != "" {
			if parentNode, exists := nodeMap[cwe.Parent.ID]; exists {
				parentNode.AddChild(nodeMap[id])
			}
		}

		if isRoot {
			rootNodes = append(rootNodes, nodeMap[id])
		}
	}

	// 按CWE ID排序所有节点的子节点
	sortAllNodes(rootNodes)

	return cweMap, rootNodes, nil
}

// isParentRelation 判断关系类型是否是父子关系
func isParentRelation(relationType string) bool {
	parentRelations := map[string]bool{
		"ChildOf":                  true,
		"ParentOf":                 false,
		"MemberOf":                 true,
		"HasMember":                false,
		"CanPrecede":               false,
		"CanFollow":                true,
		"RequiredBy":               false,
		"Requires":                 true,
		"StartsWith":               false,
		"StartedFrom":              true,
		"StopsWith":                false,
		"StoppedBy":                true,
		"CanAlsoBe":                false,
		"PeerOf":                   false,
		"Equivalence":              false,
		"Is":                       false,
		"IsA":                      true,
		"HasCorrespondingWeakness": false,
	}

	isParent, exists := parentRelations[relationType]
	return exists && isParent
}

// sortAllNodes 递归排序树中所有节点的子节点
func sortAllNodes(nodes []*TreeNode) {
	for _, node := range nodes {
		// 根据CWE ID排序子节点
		sort.Slice(node.Children, func(i, j int) bool {
			return strings.Compare(node.Children[i].CWE.ID, node.Children[j].CWE.ID) < 0
		})

		// 递归排序子节点的子节点
		sortAllNodes(node.Children)
	}
}
