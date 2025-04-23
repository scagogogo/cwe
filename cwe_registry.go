// Package cwe 的注册表功能
package cwe

import (
	"encoding/json"
	"errors"
	"fmt"
)

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
