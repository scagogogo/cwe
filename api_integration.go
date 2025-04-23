package cwe

import (
	"fmt"
	"sort"
	"strings"
)

// DataFetcher 提供从API获取CWE数据并转换为本地数据结构的功能
type DataFetcher struct {
	client *APIClient
}

// NewDataFetcher 创建新的数据获取器
func NewDataFetcher() *DataFetcher {
	return &DataFetcher{
		client: NewAPIClient(),
	}
}

// NewDataFetcherWithClient 使用自定义API客户端创建数据获取器
func NewDataFetcherWithClient(client *APIClient) *DataFetcher {
	return &DataFetcher{
		client: client,
	}
}

// FetchWeakness 获取特定ID的弱点并转换为CWE结构
func (f *DataFetcher) FetchWeakness(id string) (*CWE, error) {
	// 尝试规范化ID
	normalizedID, err := ParseCWEID(id)
	if err != nil {
		return nil, err
	}

	// 从API获取数据
	data, err := f.client.GetWeakness(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(data)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

// FetchCategory 获取特定ID的类别并转换为CWE结构
func (f *DataFetcher) FetchCategory(id string) (*CWE, error) {
	// 尝试规范化ID
	normalizedID, err := ParseCWEID(id)
	if err != nil {
		return nil, err
	}

	// 从API获取数据
	data, err := f.client.GetCategory(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(data)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

// FetchView 获取特定ID的视图并转换为CWE结构
func (f *DataFetcher) FetchView(id string) (*CWE, error) {
	// 尝试规范化ID
	normalizedID, err := ParseCWEID(id)
	if err != nil {
		return nil, err
	}

	// 从API获取数据
	data, err := f.client.GetView(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(data)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

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

// GetCurrentVersion 获取当前CWE版本
func (f *DataFetcher) GetCurrentVersion() (string, error) {
	return f.client.GetVersion()
}

// FetchCWEByIDWithRelations 获取一个CWE，并包含其关系
func (f *DataFetcher) FetchCWEByIDWithRelations(id string, viewID string) (*CWE, error) {
	// 首先获取主要CWE
	cwe, err := f.FetchWeakness(id)
	if err != nil {
		// 尝试作为类别
		cwe, err = f.FetchCategory(id)
		if err != nil {
			// 尝试作为视图
			cwe, err = f.FetchView(id)
			if err != nil {
				return nil, fmt.Errorf("无法获取ID为%s的CWE: %w", id, err)
			}
		}
	}

	// 获取并设置子节点
	err = f.PopulateChildrenRecursive(cwe, viewID)
	if err != nil {
		// 只记录错误，但继续处理
		fmt.Printf("警告: 填充子节点时出错: %v\n", err)
	}

	return cwe, nil
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
