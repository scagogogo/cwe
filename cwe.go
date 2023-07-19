package cwe

// CWE 表示一个CWE节点
type CWE struct {

	// 此节点的父节点
	Parent *CWE

	// 当前CWE对应的详情页的网址，比如
	URL string

	// CWE的ID，比如CWE-1001
	ID string

	// CWE的名字
	Name string

	Children []*CWE
}
