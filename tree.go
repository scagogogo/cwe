package cwe

// TreeNode 定义了CWE树的节点结构
//
// TreeNode与CWE结构体的区别:
// - CWE结构体直接表示CWE条目，并通过Parent/Children字段定义单一的树状关系
// - TreeNode是CWE的包装器，允许同一个CWE在不同的树结构中出现多次
// - TreeNode主要用于API返回和展示用途，提供更灵活的树结构表示
type TreeNode struct {
	// CWE 当前节点包含的CWE条目
	// 不可为nil，是TreeNode的核心数据
	CWE *CWE

	// Children 当前节点的子节点列表
	// 可以为空，表示叶子节点
	Children []*TreeNode
}

// NewTreeNode 创建新的树节点
//
// 功能描述:
//   - 初始化并返回一个包装指定CWE的新TreeNode结构体
//   - 自动初始化Children切片为空切片(非nil)
//   - 此方法用于构建CWE的树状展示结构，适用于API返回和UI展示
//
// 参数:
//   - cwe: *CWE, 要包装的CWE节点，不可为nil
//     如果传入nil，虽然不会引发立即错误，但后续使用时可能导致空指针异常
//
// 返回值:
//   - *TreeNode: 初始化后的TreeNode结构体指针
//
// 线程安全:
//   - 此方法是线程安全的，可并发调用
//
// 使用示例:
//
//	// 创建一个CWE节点
//	cwe := cwe.NewCWE("CWE-79", "跨站脚本")
//
//	// 为此CWE创建树节点
//	node := cwe.NewTreeNode(cwe)
//
//	// 使用此节点
//	fmt.Printf("节点ID: %s\n", node.CWE.ID)
//	fmt.Printf("子节点数量: %d\n", len(node.Children))
func NewTreeNode(cwe *CWE) *TreeNode {
	return &TreeNode{
		CWE:      cwe,
		Children: make([]*TreeNode, 0),
	}
}

// AddChild 添加子节点
//
// 功能描述:
//   - 将指定的TreeNode添加为当前节点的子节点
//   - 在内部，使用append将子节点添加到Children切片末尾
//   - 与CWE.AddChild不同，此方法不会修改CWE之间的Parent关系
//
// 参数:
//   - child: *TreeNode, 要添加的子节点，不应为nil
//     如果传入nil，虽然不会引发立即错误，但后续使用时可能导致空指针异常
//
// 副作用:
//   - 修改当前节点的Children切片，添加新的子节点
//   - 不修改child节点的任何属性
//
// 性能考虑:
//   - 操作时间复杂度为O(1)(平均情况)，但在Children切片需要扩容时可能为O(n)
//
// 线程安全:
//   - 此方法不是线程安全的，并发调用需要外部同步
//
// 使用示例:
//
//	// 创建根节点
//	rootCWE := cwe.NewCWE("CWE-1000", "研究视图")
//	root := cwe.NewTreeNode(rootCWE)
//
//	// 创建子节点
//	childCWE := cwe.NewCWE("CWE-79", "跨站脚本")
//	child := cwe.NewTreeNode(childCWE)
//
//	// 添加子节点
//	root.AddChild(child)
//
//	// 验证添加结果
//	if len(root.Children) > 0 {
//	    fmt.Printf("根节点现在有%d个子节点\n", len(root.Children))
//	    fmt.Printf("第一个子节点是: %s\n", root.Children[0].CWE.ID)
//	}
//
// 相关方法:
//   - CWE.AddChild: 在CWE实体之间建立父子关系的方法
//   - TreeNode结构常用于DataFetcher.BuildCWETree方法的返回值
func (n *TreeNode) AddChild(child *TreeNode) {
	n.Children = append(n.Children, child)
}
