package cwe

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"
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

// FindByID 在CWE树中查找特定ID的节点
func FindByID(root *CWE, id string) *CWE {
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

// ParseCWEID 验证并规范化CWE ID格式
func ParseCWEID(id string) (string, error) {
	// 移除空格
	id = strings.TrimSpace(id)

	// 空字符串检查
	if id == "" {
		return "", errors.New("无法解析空的CWE ID")
	}

	// 检查是否已经是正确格式：CWE-数字
	if match, _ := regexp.MatchString(`^CWE-\d+$`, id); match {
		// 提取数字部分并移除前导零
		re := regexp.MustCompile(`^CWE-0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
		return id, nil
	}

	// 检查小写的cwe前缀
	if match, _ := regexp.MatchString(`^[cC][wW][eE]-\d+$`, id); match {
		re := regexp.MustCompile(`^[cC][wW][eE]-0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
	}

	// 检查带空格的格式：CWE 数字
	if match, _ := regexp.MatchString(`^[cC][wW][eE]\s+\d+$`, id); match {
		re := regexp.MustCompile(`^[cC][wW][eE]\s+0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
	}

	// 检查其他格式：CWE-空格-数字
	if match, _ := regexp.MatchString(`^[cC][wW][eE]-\s*\d+$`, id); match {
		re := regexp.MustCompile(`^[cC][wW][eE]-\s*0*(\d+)$`)
		matches := re.FindStringSubmatch(id)
		if len(matches) >= 2 {
			return fmt.Sprintf("CWE-%s", matches[1]), nil
		}
	}

	// 尝试提取纯数字 - 仅接受连续的数字
	re := regexp.MustCompile(`^0*(\d+)$`)
	matches := re.FindStringSubmatch(id)
	if len(matches) >= 2 {
		return fmt.Sprintf("CWE-%s", matches[1]), nil
	}

	// 上述模式都不匹配，则返回错误
	return "", errors.New("无法解析CWE ID")
}

// Registry 表示CWE注册表，用于存储和管理CWE条目
type Registry struct {
	Entries map[string]*CWE // 使用ID作为键
	Root    *CWE            // 根节点
}

// NewRegistry 创建新的CWE注册表
func NewRegistry() *Registry {
	return &Registry{
		Entries: make(map[string]*CWE),
	}
}

// Register 注册一个CWE到注册表
func (r *Registry) Register(cwe *CWE) error {
	if cwe == nil {
		return errors.New("无法注册空的CWE")
	}

	if cwe.ID == "" {
		return errors.New("CWE必须有ID")
	}

	// 检查是否已存在
	if _, exists := r.Entries[cwe.ID]; exists {
		return fmt.Errorf("ID为%s的CWE已存在", cwe.ID)
	}

	r.Entries[cwe.ID] = cwe
	return nil
}

// GetByID 从注册表中获取指定ID的CWE
func (r *Registry) GetByID(id string) (*CWE, error) {
	if cwe, exists := r.Entries[id]; exists {
		return cwe, nil
	}
	return nil, fmt.Errorf("未找到ID为%s的CWE", id)
}

// BuildHierarchy 根据父子关系构建CWE层次结构
func (r *Registry) BuildHierarchy(parentChildMap map[string][]string) error {
	// 先确保所有引用的CWE都已注册
	for parentID, childIDs := range parentChildMap {
		if _, exists := r.Entries[parentID]; !exists {
			return fmt.Errorf("父节点%s未注册", parentID)
		}

		for _, childID := range childIDs {
			if _, exists := r.Entries[childID]; !exists {
				return fmt.Errorf("子节点%s未注册", childID)
			}
		}
	}

	// 构建层次结构
	for parentID, childIDs := range parentChildMap {
		parent := r.Entries[parentID]

		for _, childID := range childIDs {
			child := r.Entries[childID]
			parent.AddChild(child)
		}
	}

	return nil
}

// ExportToJSON 将CWE注册表导出为JSON
func (r *Registry) ExportToJSON() ([]byte, error) {
	return json.Marshal(r.Entries)
}

// ImportFromJSON 从JSON数据导入CWE到当前Registry
func (r *Registry) ImportFromJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty JSON data")
	}

	// 解析JSON数据
	var entriesMap map[string]*CWE
	err := json.Unmarshal(data, &entriesMap)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if len(entriesMap) == 0 {
		return fmt.Errorf("no entries found in JSON data")
	}

	// 清空当前注册表
	r.Entries = make(map[string]*CWE)

	// 导入CWE条目
	for id, cwe := range entriesMap {
		if cwe.ID == "" {
			return fmt.Errorf("entry without ID found")
		}
		// 确保ID匹配
		if id != cwe.ID {
			cwe.ID = id
		}
		r.Register(cwe)
	}

	return nil
}
