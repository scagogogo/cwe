package cwe

import (
	"sort"
)

// BuildTree 构建CWE树
func (fetcher *DataFetcher) BuildTree(ids []string) (map[string]CWE, []*TreeNode, error) {
	fetchedCWEs, err := fetcher.FetchMultiple(ids)
	if err != nil {
		return nil, nil, err
	}

	// 构建根节点列表
	rootNodes := make([]*TreeNode, 0)
	cweMap := make(map[string]CWE)

	// 填充CWE映射
	for _, cwe := range fetchedCWEs {
		cweMap[cwe.GetID()] = cwe
	}

	// 为每个CWE创建树节点
	nodeMap := make(map[string]*TreeNode)
	for _, cwe := range fetchedCWEs {
		node := &TreeNode{
			CWE:      cwe,
			Children: make([]*TreeNode, 0),
		}
		nodeMap[cwe.GetID()] = node
	}

	// 建立树结构
	for _, cwe := range fetchedCWEs {
		// 检查此CWE是否有父节点，如果没有，它就是根节点
		isRoot := true
		for _, relation := range cwe.GetRelations() {
			if isParentRelation(relation.Type) {
				if parentNode, exists := nodeMap[relation.TargetID]; exists {
					isRoot = false
					parentNode.Children = append(parentNode.Children, nodeMap[cwe.GetID()])
				}
			}
		}

		if isRoot {
			rootNodes = append(rootNodes, nodeMap[cwe.GetID()])
		}
	}

	// 按CWE ID排序所有节点的子节点
	sortAllNodes(rootNodes)

	return cweMap, rootNodes, nil
}

// 判断关系类型是否是父子关系
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
			return node.Children[i].CWE.GetID() < node.Children[j].CWE.GetID()
		})

		// 递归排序子节点的子节点
		sortAllNodes(node.Children)
	}
}
