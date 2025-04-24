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
// CWE (Common Weakness Enumeration) 是一个公共弱点列举系统，用于识别和分类软件和硬件的安全弱点
type CWE struct {
	// Parent 当前节点的父节点
	// 若为nil，则表示当前节点为根节点
	Parent *CWE

	// URL 当前CWE对应的详情页的网址
	// 例如: "https://cwe.mitre.org/data/definitions/1.html"
	URL string

	// ID CWE的唯一标识符
	// 格式为"CWE-数字"，例如"CWE-1001"
	// 此字段不可为空，是CWE条目的主键
	ID string

	// Name CWE的名称
	// 描述当前CWE条目的简短标题
	// 例如: "Improper Neutralization of Special Elements in Output Used by a Downstream Component"
	Name string

	// Children 当前CWE的子节点列表
	// 表示在CWE分类层次结构中，当前CWE包含的弱点类型
	Children []*CWE

	// Description CWE的详细描述信息
	// 对当前安全弱点的详细解释，包括成因、影响等
	Description string

	// Severity CWE的严重性级别
	// 可能的值: "High", "Medium", "Low"等
	// 表示此类弱点可能造成的安全影响程度
	Severity string

	// Mitigations 相关的缓解措施列表
	// 包含了针对此类弱点的防御和修复建议
	Mitigations []string

	// Examples 相关的示例列表
	// 包含了此类弱点的具体实例或攻击场景
	Examples []string
}

// NewCWE 创建一个新的CWE实例
//
// 功能描述:
//   - 初始化并返回一个新的CWE结构体指针
//   - 自动初始化Children、Mitigations和Examples切片为空切片(非nil)
//
// 参数:
//   - id: string, CWE的唯一标识符，格式应为"CWE-数字"，如"CWE-79"，不可为空
//   - name: string, CWE的名称，描述当前CWE条目的简短标题，不可为空
//
// 返回值:
//   - *CWE: 初始化后的CWE结构体指针
//
// 使用示例:
//
//	cwe := NewCWE("CWE-79", "跨站脚本")
//	cwe.Description = "允许攻击者将恶意脚本注入到网页中"
//	cwe.Severity = "High"
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
//
// 功能描述:
//   - 将指定的CWE节点添加为当前节点的子节点
//   - 同时设置子节点的Parent字段指向当前节点，建立双向关联
//   - 此操作会修改传入的child参数，设置其Parent字段
//
// 参数:
//   - child: *CWE, 要添加的子节点，不可为nil
//
// 线程安全:
//   - 此方法不是线程安全的，并发调用需要外部同步
//
// 使用示例:
//
//	parent := NewCWE("CWE-1000", "软件安全问题")
//	child := NewCWE("CWE-79", "跨站脚本")
//	parent.AddChild(child)
//	// 此时child.Parent == parent，且parent.Children包含child
func (c *CWE) AddChild(child *CWE) {
	child.Parent = c
	c.Children = append(c.Children, child)
}

// GetNumericID 获取CWE ID的数字部分
//
// 功能描述:
//   - 从CWE的ID字段(格式为"CWE-数字")中提取数字部分
//   - 使用正则表达式匹配"CWE-"后面的数字
//
// 返回值:
//   - int: 提取的数字部分，如"CWE-79"返回79
//   - error: 解析过程中的错误，包括:
//   - ID格式不正确(不符合"CWE-数字"格式)
//   - 数字部分无法解析为整数
//
// 错误处理:
//   - 当ID格式不正确时，返回错误"invalid CWE ID format"
//   - 当数字部分无法解析为整数时，返回fmt.Sscanf的错误
//
// 使用示例:
//
//	cwe := NewCWE("CWE-79", "跨站脚本")
//	id, err := cwe.GetNumericID()
//	if err != nil {
//	    log.Fatalf("无法获取CWE ID: %v", err)
//	}
//	fmt.Printf("数字ID: %d\n", id) // 输出: 数字ID: 79
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
//
// 功能描述:
//   - 判断当前CWE节点是否为根节点
//   - 根节点定义为没有父节点(Parent为nil)的节点
//
// 返回值:
//   - bool: 如果当前节点是根节点返回true，否则返回false
//
// 使用示例:
//
//	root := NewCWE("CWE-1000", "软件安全问题")
//	child := NewCWE("CWE-79", "跨站脚本")
//	root.AddChild(child)
//
//	fmt.Println(root.IsRoot()) // 输出: true
//	fmt.Println(child.IsRoot()) // 输出: false
func (c *CWE) IsRoot() bool {
	return c.Parent == nil
}

// IsLeaf 判断是否为叶子节点
//
// 功能描述:
//   - 判断当前CWE节点是否为叶子节点
//   - 叶子节点定义为没有子节点的节点(Children切片长度为0)
//
// 返回值:
//   - bool: 如果当前节点是叶子节点返回true，否则返回false
//
// 使用示例:
//
//	parent := NewCWE("CWE-1000", "软件安全问题")
//	child := NewCWE("CWE-79", "跨站脚本")
//	parent.AddChild(child)
//
//	fmt.Println(parent.IsLeaf()) // 输出: false
//	fmt.Println(child.IsLeaf()) // 输出: true
func (c *CWE) IsLeaf() bool {
	return len(c.Children) == 0
}

// GetRoot 获取根节点
//
// 功能描述:
//   - 从当前CWE节点开始，沿着Parent字段向上查找，直至找到根节点
//   - 根节点定义为Parent为nil的节点
//   - 如果当前节点已经是根节点，则返回当前节点
//
// 返回值:
//   - *CWE: 当前节点所在树的根节点
//
// 性能说明:
//   - 时间复杂度为O(h)，其中h为树的高度
//   - 在层次很深的树中，此操作可能较慢
//
// 使用示例:
//
//	root := NewCWE("CWE-1000", "软件安全问题")
//	mid := NewCWE("CWE-200", "信息暴露")
//	leaf := NewCWE("CWE-79", "跨站脚本")
//
//	root.AddChild(mid)
//	mid.AddChild(leaf)
//
//	foundRoot := leaf.GetRoot()
//	fmt.Println(foundRoot.ID) // 输出: CWE-1000
func (c *CWE) GetRoot() *CWE {
	current := c
	for current.Parent != nil {
		current = current.Parent
	}
	return current
}

// GetPath 获取从根到当前节点的路径
//
// 功能描述:
//   - 从当前CWE节点开始，构建一个从根节点到当前节点的路径
//   - 返回的切片中，第一个元素是根节点，最后一个元素是当前节点
//
// 返回值:
//   - []*CWE: 包含从根节点到当前节点路径上所有节点的切片
//   - 如果当前节点是根节点，则切片只包含当前节点
//   - 切片中的节点顺序为从根到当前节点
//
// 性能说明:
//   - 时间复杂度为O(h)，其中h为从当前节点到根节点的高度
//   - 空间复杂度为O(h)
//
// 使用示例:
//
//	root := NewCWE("CWE-1000", "软件安全问题")
//	mid := NewCWE("CWE-200", "信息暴露")
//	leaf := NewCWE("CWE-79", "跨站脚本")
//
//	root.AddChild(mid)
//	mid.AddChild(leaf)
//
//	path := leaf.GetPath()
//	// path包含[root, mid, leaf]
//	for _, node := range path {
//	    fmt.Println(node.ID)
//	}
//	// 输出:
//	// CWE-1000
//	// CWE-200
//	// CWE-79
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
//
// 功能描述:
//   - 将当前CWE节点序列化为JSON格式的字节数组
//   - 使用encoding/json包进行序列化
//   - 注意：如果存在循环引用(例如通过Parent字段)，可能导致无限递归
//
// 返回值:
//   - []byte: 序列化后的JSON数据
//   - error: 序列化过程中发生的错误
//
// 错误处理:
//   - 当序列化失败时，返回encoding/json.Marshal的错误
//   - 可能的错误包括循环引用、不支持的字段类型等
//
// 使用示例:
//
//	cwe := NewCWE("CWE-79", "跨站脚本")
//	cwe.Description = "允许攻击者将恶意脚本注入到网页中"
//	cwe.Severity = "High"
//
//	jsonData, err := cwe.ToJSON()
//	if err != nil {
//	    log.Fatalf("JSON序列化失败: %v", err)
//	}
//	fmt.Println(string(jsonData))
//	// 输出类似: {"ID":"CWE-79","Name":"跨站脚本","Description":"允许攻击者将恶意脚本注入到网页中","Severity":"High",...}
func (c *CWE) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

// ToXML 将CWE转换为XML
//
// 功能描述:
//   - 将当前CWE节点及其子节点序列化为XML格式的字节数组
//   - 使用encoding/xml包进行序列化
//   - 特别处理了循环引用问题，通过创建一个SafeCWE临时结构来避免Parent字段导致的无限递归
//
// 返回值:
//   - []byte: 序列化后的XML数据
//   - error: 序列化过程中发生的错误
//
// XML格式说明:
//   - 根元素为<CWE>
//   - 基本字段如ID、Name等作为子元素
//   - Mitigations和Examples作为列表元素，包含在<Mitigations>和<Examples>标签内
//   - 子节点包含在<Children>标签内，每个子节点使用<Child>标签
//
// 错误处理:
//   - 当XML序列化失败时，返回encoding/xml.Marshal的错误
//
// 使用示例:
//
//	parent := NewCWE("CWE-1000", "软件安全问题")
//	child := NewCWE("CWE-79", "跨站脚本")
//	parent.AddChild(child)
//
//	xmlData, err := parent.ToXML()
//	if err != nil {
//	    log.Fatalf("XML序列化失败: %v", err)
//	}
//	fmt.Println(string(xmlData))
//	/* 输出类似:
//	<CWE>
//	  <ID>CWE-1000</ID>
//	  <Name>软件安全问题</Name>
//	  <Children>
//	    <Child>
//	      <ID>CWE-79</ID>
//	      <Name>跨站脚本</Name>
//	    </Child>
//	  </Children>
//	</CWE>
//	*/
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
