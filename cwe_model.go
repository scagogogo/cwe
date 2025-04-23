// Package cwe 的数据类型和核心功能
package cwe

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
)

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

	// 子节点列表
	Children []*CWE

	// 描述信息
	Description string

	// 严重性级别
	Severity string

	// 相关的缓解措施
	Mitigations []string

	// 相关的例子
	Examples []string
}

// NewCWE 创建一个新的CWE实例
func NewCWE(id, name string) *CWE {
	return &CWE{
		ID:          id,
		Name:        name,
		Children:    make([]*CWE, 0),
		Mitigations: make([]string, 0),
		Examples:    make([]string, 0),
	}
}

// AddChild 添加一个子节点
func (c *CWE) AddChild(child *CWE) {
	child.Parent = c
	c.Children = append(c.Children, child)
}

// GetNumericID 获取CWE ID的数字部分
func (c *CWE) GetNumericID() (int, error) {
	re := regexp.MustCompile(`CWE-(\d+)`)
	matches := re.FindStringSubmatch(c.ID)
	if len(matches) < 2 {
		return 0, errors.New("invalid CWE ID format")
	}
	var id int
	_, err := fmt.Sscanf(matches[1], "%d", &id)
	return id, err
}

// IsRoot 判断是否为根节点
func (c *CWE) IsRoot() bool {
	return c.Parent == nil
}

// IsLeaf 判断是否为叶子节点
func (c *CWE) IsLeaf() bool {
	return len(c.Children) == 0
}

// GetRoot 获取根节点
func (c *CWE) GetRoot() *CWE {
	current := c
	for current.Parent != nil {
		current = current.Parent
	}
	return current
}

// GetPath 获取从根到当前节点的路径
func (c *CWE) GetPath() []*CWE {
	path := make([]*CWE, 0)
	current := c

	// 从当前节点向上构建路径
	for current != nil {
		path = append([]*CWE{current}, path...)
		current = current.Parent
	}

	return path
}

// ToJSON 将CWE转换为JSON
func (c *CWE) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

// ToXML 将CWE转换为XML
func (c *CWE) ToXML() ([]byte, error) {
	// 创建一个没有Parent字段的临时结构来避免循环引用
	type SafeCWE struct {
		XMLName     xml.Name `xml:"CWE"`
		ID          string   `xml:"ID"`
		Name        string   `xml:"Name"`
		Description string   `xml:"Description,omitempty"`
		URL         string   `xml:"URL,omitempty"`
		Severity    string   `xml:"Severity,omitempty"`
		Mitigations []string `xml:"Mitigations>Mitigation,omitempty"`
		Examples    []string `xml:"Examples>Example,omitempty"`
		// 不包含Parent，避免循环引用
		Children []*SafeCWE `xml:"Children>Child,omitempty"`
	}

	// 递归转换CWE结构
	var convert func(*CWE) *SafeCWE
	convert = func(cwe *CWE) *SafeCWE {
		if cwe == nil {
			return nil
		}

		safe := &SafeCWE{
			ID:          cwe.ID,
			Name:        cwe.Name,
			Description: cwe.Description,
			URL:         cwe.URL,
			Severity:    cwe.Severity,
			Mitigations: cwe.Mitigations,
			Examples:    cwe.Examples,
			Children:    make([]*SafeCWE, 0, len(cwe.Children)),
		}

		for _, child := range cwe.Children {
			safe.Children = append(safe.Children, convert(child))
		}

		return safe
	}

	return xml.Marshal(convert(c))
}
