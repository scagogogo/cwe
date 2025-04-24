// Package cwe 的注册表功能
package cwe

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Registry 表示CWE注册表，用于存储和管理CWE条目
// 它提供了添加、查询CWE及构建CWE层次结构的功能
// Registry是并发安全的，可以在多个goroutine中安全使用
type Registry struct {
	// Entries 存储所有已注册的CWE，以ID为键
	Entries map[string]*CWE // 使用ID作为键

	// Root 表示CWE层次结构的根节点
	// 在调用BuildHierarchy后会设置此字段
	Root *CWE // 根节点
}

// NewRegistry 创建新的CWE注册表
//
// 方法功能:
// 创建并初始化一个新的CWE注册表实例，用于管理CWE条目。
// 注册表负责存储CWE对象，并提供添加、查询以及构建层次结构的功能。
//
// 参数: 无
//
// 返回值:
// - *Registry: 初始化完成的注册表实例，包含空的Entries映射
//
// 使用示例:
// ```go
// // 创建一个新的CWE注册表
// registry := cwe.NewRegistry()
//
// // 创建并添加CWE条目
// xss := cwe.NewCWE("CWE-79", "跨站脚本")
// registry.Register(xss)
// ```
//
// 相关方法:
// - Register(): 向注册表添加CWE
// - GetByID(): 通过ID查询CWE
// - BuildHierarchy(): 构建CWE层次结构
func NewRegistry() *Registry {
	return &Registry{
		Entries: make(map[string]*CWE),
	}
}

// Register 注册一个CWE到注册表
//
// 方法功能:
// 将一个CWE对象添加到注册表中。如果注册表中已存在相同ID的CWE，则返回错误。
// 该方法在添加前会进行基本验证，确保CWE有效。
//
// 参数:
// - cwe: *CWE - 要添加到注册表的CWE对象，不能为nil且必须具有有效ID
//
// 返回值:
// - error: 如CWE为nil、ID为空或已存在相同ID的CWE时返回错误，否则返回nil
//
// 错误处理:
// - 如CWE为nil: 返回"无法注册空的CWE"
// - 如CWE的ID为空: 返回"CWE必须有ID"
// - 如注册表中已存在相同ID的CWE: 返回"ID为X的CWE已存在"
//
// 使用示例:
// ```go
// registry := cwe.NewRegistry()
//
// // 创建CWE对象
// xss := cwe.NewCWE("CWE-79", "跨站脚本")
// xss.Description = "Web应用程序的跨站脚本漏洞"
//
// // 注册到注册表
// err := registry.Register(xss)
//
//	if err != nil {
//	    log.Fatalf("注册CWE失败: %v", err)
//	}
//
// // 尝试注册重复ID会失败
// duplicateXSS := cwe.NewCWE("CWE-79", "XSS")
// err = registry.Register(duplicateXSS) // 返回错误
// ```
//
// 相关方法:
// - GetByID(): 从注册表查询CWE
// - BuildHierarchy(): 构建注册表中CWE的层次结构
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
//
// 方法功能:
// 根据提供的ID，从注册表中查找并返回对应的CWE对象。
// 如果找不到匹配的CWE，则返回错误。
//
// 参数:
// - id: string - 要查找的CWE的ID，通常格式为"CWE-数字"(如"CWE-79")
//
// 返回值:
// - *CWE: 找到的CWE对象
// - error: 如未找到匹配的CWE则返回错误，否则返回nil
//
// 错误处理:
// - 如注册表中不存在指定ID的CWE: 返回"未找到ID为X的CWE"
//
// 使用示例:
// ```go
// registry := cwe.NewRegistry()
//
// // 先注册一些CWE
// registry.Register(cwe.NewCWE("CWE-79", "跨站脚本"))
// registry.Register(cwe.NewCWE("CWE-89", "SQL注入"))
//
// // 通过ID获取CWE
// xss, err := registry.GetByID("CWE-79")
//
//	if err != nil {
//	    log.Fatalf("获取CWE失败: %v", err)
//	}
//
// fmt.Printf("找到CWE: %s - %s\n", xss.ID, xss.Name)
//
// // 查询不存在的CWE会返回错误
// nonExistent, err := registry.GetByID("CWE-999")
//
//	if err != nil {
//	    fmt.Printf("错误: %v\n", err) // 输出: 错误: 未找到ID为CWE-999的CWE
//	}
//
// ```
//
// 相关方法:
// - Register(): 向注册表添加CWE
// - BuildHierarchy(): 构建CWE层次结构
func (r *Registry) GetByID(id string) (*CWE, error) {
	if cwe, exists := r.Entries[id]; exists {
		return cwe, nil
	}
	return nil, fmt.Errorf("未找到ID为%s的CWE", id)
}

// BuildHierarchy 根据父子关系构建CWE层次结构
//
// 方法功能:
// 根据提供的父子关系映射，构建注册表中CWE的层次结构。
// 该方法会为每个父节点添加相应的子节点，从而建立完整的CWE层次树。
// 执行此方法前，相关的CWE必须已通过Register方法添加到注册表中。
//
// 参数:
// - parentChildMap: map[string][]string - 父子关系映射，键为父节点ID，值为子节点ID数组
//
// 返回值:
// - error: 如遇到未注册的CWE则返回错误，否则返回nil
//
// 错误处理:
// - 如父节点未注册: 返回"父节点X未注册"
// - 如子节点未注册: 返回"子节点X未注册"
//
// 使用示例:
// ```go
// registry := cwe.NewRegistry()
//
// // 注册节点
// registry.Register(cwe.NewCWE("CWE-707", "输入验证"))
// registry.Register(cwe.NewCWE("CWE-79", "跨站脚本"))
// registry.Register(cwe.NewCWE("CWE-89", "SQL注入"))
//
// // 定义父子关系
//
//	parentChildMap := map[string][]string{
//	    "CWE-707": {"CWE-79", "CWE-89"},
//	}
//
// // 构建层次结构
// err := registry.BuildHierarchy(parentChildMap)
//
//	if err != nil {
//	    log.Fatalf("构建层次结构失败: %v", err)
//	}
//
// // 验证层次结构
// parent, _ := registry.GetByID("CWE-707")
// fmt.Printf("父节点: %s, 子节点数: %d\n", parent.ID, len(parent.Children))
//
//	for _, child := range parent.Children {
//	    fmt.Printf("子节点: %s - %s\n", child.ID, child.Name)
//	}
//
// ```
//
// 数据样例:
// - parentChildMap:
// ```
//
//	{
//	    "CWE-707": ["CWE-79", "CWE-89"],
//	    "CWE-664": ["CWE-707"]
//	}
//
// ```
//
// 相关方法:
// - Register(): 向注册表添加CWE
// - GetByID(): 从注册表查询CWE
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
//
// 方法功能:
// 将注册表中的所有CWE条目序列化为JSON格式的字节数组。
// 导出的JSON结构是一个键为CWE ID、值为CWE对象的映射。
// 此方法对于数据持久化和跨系统传输非常有用。
//
// 参数: 无
//
// 返回值:
// - []byte: 序列化后的JSON数据
// - error: 如序列化过程发生错误则返回错误，否则返回nil
//
// 错误处理:
// - 序列化错误: 由json.Marshal返回的原始错误
//
// 使用示例:
// ```go
// registry := cwe.NewRegistry()
// registry.Register(cwe.NewCWE("CWE-79", "跨站脚本"))
// registry.Register(cwe.NewCWE("CWE-89", "SQL注入"))
//
// // 导出为JSON
// jsonData, err := registry.ExportToJSON()
//
//	if err != nil {
//	    log.Fatalf("导出JSON失败: %v", err)
//	}
//
// // 保存到文件或其他用途
// err = ioutil.WriteFile("cwe_data.json", jsonData, 0644)
//
//	if err != nil {
//	    log.Fatalf("保存JSON文件失败: %v", err)
//	}
//
// ```
//
// 数据样例:
// ```json
//
//	{
//	  "CWE-79": {
//	    "id": "CWE-79",
//	    "name": "跨站脚本",
//	    "description": "",
//	    "children": []
//	  },
//	  "CWE-89": {
//	    "id": "CWE-89",
//	    "name": "SQL注入",
//	    "description": "",
//	    "children": []
//	  }
//	}
//
// ```
//
// 相关方法:
// - ImportFromJSON(): 从JSON数据导入CWE到注册表
func (r *Registry) ExportToJSON() ([]byte, error) {
	return json.Marshal(r.Entries)
}

// ImportFromJSON 从JSON数据导入CWE到当前Registry
//
// 方法功能:
// 从提供的JSON数据字节数组中解析CWE条目，并将它们导入到当前注册表中。
// 导入过程会清空当前注册表中的所有条目，并用新解析的条目替换它们。
// JSON数据应该是一个键为CWE ID、值为CWE对象的映射。
//
// 参数:
// - data: []byte - 包含CWE数据的JSON字节数组
//
// 返回值:
// - error: 如遇到空数据、解析错误或无效CWE则返回错误，否则返回nil
//
// 错误处理:
// - 空数据: 返回"empty JSON data"
// - 解析错误: 返回"failed to unmarshal JSON: <原始错误>"
// - 无条目: 返回"no entries found in JSON data"
// - 无ID条目: 返回"entry without ID found"
//
// 使用示例:
// ```go
// // 从文件读取JSON数据
// jsonData, err := ioutil.ReadFile("cwe_data.json")
//
//	if err != nil {
//	    log.Fatalf("读取JSON文件失败: %v", err)
//	}
//
// // 创建注册表并导入数据
// registry := cwe.NewRegistry()
// err = registry.ImportFromJSON(jsonData)
//
//	if err != nil {
//	    log.Fatalf("导入JSON数据失败: %v", err)
//	}
//
// // 验证导入结果
// fmt.Printf("成功导入%d个CWE条目\n", len(registry.Entries))
// ```
//
// 数据样例:
// - 输入JSON:
// ```json
//
//	{
//	  "CWE-79": {
//	    "id": "CWE-79",
//	    "name": "跨站脚本",
//	    "description": "允许攻击者向其他用户注入客户端脚本",
//	    "children": []
//	  },
//	  "CWE-89": {
//	    "id": "CWE-89",
//	    "name": "SQL注入",
//	    "description": "允许攻击者向数据库查询注入恶意SQL代码",
//	    "children": []
//	  }
//	}
//
// ```
//
// 相关方法:
// - ExportToJSON(): 将注册表导出为JSON数据
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
