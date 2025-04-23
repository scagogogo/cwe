package cwe

// TreeNode 定义了CWE树的节点结构
type TreeNode struct {
	CWE      CWE
	Children []*TreeNode
}
