package cwe

import "fmt"

// FetchWeakness 获取特定ID的弱点并转换为CWE结构
func (f *DataFetcher) FetchWeakness(id string) (*CWE, error) {
	// 尝试规范化ID
	normalizedID, err := ParseCWEID(id)
	if err != nil {
		return nil, err
	}

	// 从API获取数据
	weakness, err := f.client.GetWeakness(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(weakness)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

// FetchCategory 获取特定ID的类别并转换为CWE结构
func (f *DataFetcher) FetchCategory(id string) (*CWE, error) {
	// 尝试规范化ID
	normalizedID, err := ParseCWEID(id)
	if err != nil {
		return nil, err
	}

	// 从API获取数据
	category, err := f.client.GetCategory(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertCategoryToCWE(category)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

// FetchView 获取特定ID的视图并转换为CWE结构
func (f *DataFetcher) FetchView(id string) (*CWE, error) {
	// 尝试规范化ID
	normalizedID, err := ParseCWEID(id)
	if err != nil {
		return nil, err
	}

	// 从API获取数据
	view, err := f.client.GetView(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertViewToCWE(view)
	if err != nil {
		return nil, err
	}

	return cwe, nil
}

// FetchCWEByIDWithRelations 获取一个CWE，并包含其关系
func (f *DataFetcher) FetchCWEByIDWithRelations(id string, viewID string) (*CWE, error) {
	// 首先获取主要CWE
	cwe, err := f.FetchWeakness(id)
	if err != nil {
		// 尝试作为类别
		cwe, err = f.FetchCategory(id)
		if err != nil {
			// 尝试作为视图
			cwe, err = f.FetchView(id)
			if err != nil {
				return nil, fmt.Errorf("无法获取ID为%s的CWE: %w", id, err)
			}
		}
	}

	// 获取并设置子节点
	err = f.PopulateChildrenRecursive(cwe, viewID)
	if err != nil {
		// 只记录错误，但继续处理
		fmt.Printf("警告: 填充子节点时出错: %v\n", err)
	}

	return cwe, nil
}

// convertToCWE 将API返回的弱点转换为CWE结构
func (f *DataFetcher) convertToCWE(weakness *CWEWeakness) (*CWE, error) {
	if weakness == nil {
		return nil, fmt.Errorf("弱点信息为空")
	}

	cwe := NewCWE(weakness.ID, weakness.Name)
	cwe.Description = weakness.Description
	cwe.URL = weakness.URL
	cwe.Severity = weakness.Severity

	// 处理缓解措施
	if len(weakness.Mitigations) > 0 {
		mitigations := make([]string, 0, len(weakness.Mitigations))
		for _, m := range weakness.Mitigations {
			mitigations = append(mitigations, m.Description)
		}
		cwe.Mitigations = mitigations
	}

	// 处理示例
	if len(weakness.ObservedExamples) > 0 {
		examples := make([]string, 0, len(weakness.ObservedExamples))
		for _, e := range weakness.ObservedExamples {
			examples = append(examples, e.Description)
		}
		cwe.Examples = examples
	}

	return cwe, nil
}

// convertCategoryToCWE 将API返回的类别转换为CWE结构
func (f *DataFetcher) convertCategoryToCWE(category *CWECategory) (*CWE, error) {
	if category == nil {
		return nil, fmt.Errorf("类别信息为空")
	}

	cwe := NewCWE(category.ID, category.Name)
	cwe.Description = category.Description
	cwe.URL = category.URL

	return cwe, nil
}

// convertViewToCWE 将API返回的视图转换为CWE结构
func (f *DataFetcher) convertViewToCWE(view *CWEView) (*CWE, error) {
	if view == nil {
		return nil, fmt.Errorf("视图信息为空")
	}

	cwe := NewCWE(view.ID, view.Name)
	cwe.Description = view.Description
	cwe.URL = view.URL

	return cwe, nil
}
