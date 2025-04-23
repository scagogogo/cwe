package cwe

import (
	"fmt"
	"strings"
)

// FetchWeakness 根据ID获取单一弱点
func (f *DataFetcher) FetchWeakness(id string) (*Weakness, error) {
	cwe, err := f.client.GetWeakness(id)
	if err != nil {
		return nil, err
	}
	return convertToCWE(cwe), nil
}

// FetchCategory 根据ID获取单一类别
func (f *DataFetcher) FetchCategory(id string) (*Category, error) {
	cwe, err := f.client.GetCategory(id)
	if err != nil {
		return nil, err
	}
	return convertToCWE(cwe), nil
}

// FetchView 根据ID获取单一视图
func (f *DataFetcher) FetchView(id string) (*View, error) {
	cwe, err := f.client.GetView(id)
	if err != nil {
		return nil, err
	}
	return convertToCWE(cwe), nil
}

// FetchMultiple 获取多个CWE并转换为Registry
func (f *DataFetcher) FetchMultiple(ids []string) (*Registry, error) {
	cwes, err := f.client.GetMultipleWeaknesses(ids)
	if err != nil {
		return nil, err
	}

	result := &Registry{
		RootWeaknesses: make(map[string]*Weakness),
		RootCategories: make(map[string]*Category),
		RootViews:      make(map[string]*View),
		AllWeaknesses:  make(map[string]*Weakness),
		AllCategories:  make(map[string]*Category),
		AllViews:       make(map[string]*View),
	}

	for _, cwe := range cwes {
		c := convertToCWE(cwe)
		switch c.GetType() {
		case TypeWeakness:
			w := c.(*Weakness)
			result.AllWeaknesses[w.ID] = w
			if strings.EqualFold(w.Status, "Draft") {
				continue
			}
			result.RootWeaknesses[w.ID] = w
		case TypeCategory:
			c := c.(*Category)
			result.AllCategories[c.ID] = c
			if strings.EqualFold(c.Status, "Draft") {
				continue
			}
			result.RootCategories[c.ID] = c
		case TypeView:
			v := c.(*View)
			result.AllViews[v.ID] = v
			if strings.EqualFold(v.Status, "Draft") {
				continue
			}
			result.RootViews[v.ID] = v
		}
	}

	return result, nil
}

// FetchCWEByIDWithRelations 获取单个CWE的所有关系
func (f *DataFetcher) FetchCWEByIDWithRelations(id string) (CWE, error) {
	// 标准化CWE ID
	if !strings.HasPrefix(strings.ToUpper(id), "CWE-") {
		id = fmt.Sprintf("CWE-%s", id)
	}

	// 确定CWE类型并获取数据
	cweType, err := f.client.GetCWEType(id)
	if err != nil {
		return nil, fmt.Errorf("无法确定CWE类型: %v", err)
	}

	var cwe CWE
	switch cweType {
	case "weakness":
		cwe, err = f.FetchWeakness(id)
	case "category":
		cwe, err = f.FetchCategory(id)
	case "view":
		cwe, err = f.FetchView(id)
	default:
		return nil, fmt.Errorf("未知的CWE类型: %s", cweType)
	}

	if err != nil {
		return nil, err
	}

	// 处理关系
	err = f.PopulateRelations(cwe, nil)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

// PopulateRelations 填充CWE的关系
func (f *DataFetcher) PopulateRelations(cwe CWE, visited map[string]bool) error {
	if visited == nil {
		visited = make(map[string]bool)
	}

	id := cwe.GetID()
	if visited[id] {
		return nil
	}
	visited[id] = true

	return nil
}
