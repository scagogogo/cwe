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
	data, err := f.client.GetWeakness(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(data)
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
	data, err := f.client.GetCategory(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(data)
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
	data, err := f.client.GetView(normalizedID)
	if err != nil {
		return nil, err
	}

	// 创建CWE实例
	cwe, err := f.convertToCWE(data)
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
