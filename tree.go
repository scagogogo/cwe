package cwe

// TreeNode 定义了CWE树的节点结构
type TreeNode struct {
	CWE      *CWE
	Children []*TreeNode
}

// NewTreeNode 创建新的树节点
func NewTreeNode(cwe *CWE) *TreeNode {
	return &TreeNode{
		CWE:      cwe,
		Children: make([]*TreeNode, 0),
	}
}

// AddChild 添加子节点
func (n *TreeNode) AddChild(child *TreeNode) {
	n.Children = append(n.Children, child)
}
