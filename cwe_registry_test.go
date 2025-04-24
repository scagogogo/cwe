package cwe

import (
	"encoding/json"
	"testing"
)

// cwe_registry.go的核心功能测试

// TestNewRegistry 测试创建新的CWE注册表
func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()

	if registry == nil {
		t.Fatal("NewRegistry返回了nil")
	}

	if registry.Entries == nil {
		t.Error("Entries映射应该被初始化，但得到了nil")
	}

	if len(registry.Entries) != 0 {
		t.Errorf("新创建的注册表应该有0个条目，但有 %d 个", len(registry.Entries))
	}
}

// TestRegistryRegister 测试向注册表注册CWE
func TestRegistryRegister(t *testing.T) {
	registry := NewRegistry()

	// 注册正常的CWE
	cwe1 := NewCWE("CWE-123", "测试CWE1")
	err := registry.Register(cwe1)
	if err != nil {
		t.Errorf("注册有效CWE应该成功，但得到错误: %v", err)
	}

	// 验证注册成功
	if len(registry.Entries) != 1 {
		t.Errorf("注册后注册表应该有1个条目，但有 %d 个", len(registry.Entries))
	}

	if registry.Entries["CWE-123"] != cwe1 {
		t.Error("注册表中的CWE与注册的CWE不匹配")
	}

	// 测试注册nil CWE
	err = registry.Register(nil)
	if err == nil {
		t.Error("注册nil CWE应该返回错误，但没有")
	}

	// 测试注册无ID的CWE
	cweNoID := NewCWE("", "无ID的CWE")
	err = registry.Register(cweNoID)
	if err == nil {
		t.Error("注册无ID的CWE应该返回错误，但没有")
	}

	// 测试注册重复ID的CWE
	cweDuplicate := NewCWE("CWE-123", "重复ID的CWE")
	err = registry.Register(cweDuplicate)
	if err == nil {
		t.Error("注册重复ID的CWE应该返回错误，但没有")
	}

	// 验证注册表内容未被错误操作修改
	if len(registry.Entries) != 1 {
		t.Errorf("错误操作后注册表应该仍有1个条目，但有 %d 个", len(registry.Entries))
	}
}

// TestRegistryGetByID 测试通过ID获取CWE
func TestRegistryGetByID(t *testing.T) {
	registry := NewRegistry()

	// 添加测试CWE
	cwe1 := NewCWE("CWE-123", "测试CWE1")
	cwe2 := NewCWE("CWE-456", "测试CWE2")
	registry.Register(cwe1)
	registry.Register(cwe2)

	// 测试获取已存在的CWE
	result, err := registry.GetByID("CWE-123")
	if err != nil {
		t.Errorf("获取已存在的CWE应该成功，但得到错误: %v", err)
	}

	if result != cwe1 {
		t.Error("获取的CWE与注册的CWE不匹配")
	}

	// 测试获取不存在的CWE
	_, err = registry.GetByID("CWE-999")
	if err == nil {
		t.Error("获取不存在的CWE应该返回错误，但没有")
	}

	// 测试空ID
	_, err = registry.GetByID("")
	if err == nil {
		t.Error("使用空ID获取CWE应该返回错误，但没有")
	}
}

// TestRegistryBuildHierarchy 测试构建CWE层次结构
func TestRegistryBuildHierarchy(t *testing.T) {
	registry := NewRegistry()

	// 创建CWE节点
	root := NewCWE("CWE-1000", "根节点")
	mid1 := NewCWE("CWE-100", "中间节点1")
	mid2 := NewCWE("CWE-200", "中间节点2")
	leaf1 := NewCWE("CWE-101", "叶节点1")
	leaf2 := NewCWE("CWE-102", "叶节点2")
	leaf3 := NewCWE("CWE-201", "叶节点3")

	// 注册所有节点
	registry.Register(root)
	registry.Register(mid1)
	registry.Register(mid2)
	registry.Register(leaf1)
	registry.Register(leaf2)
	registry.Register(leaf3)

	// 设置层次关系
	parentChildMap := map[string][]string{
		"CWE-1000": {"CWE-100", "CWE-200"},
		"CWE-100":  {"CWE-101", "CWE-102"},
		"CWE-200":  {"CWE-201"},
	}

	// 构建层次结构
	err := registry.BuildHierarchy(parentChildMap)
	if err != nil {
		t.Errorf("构建层次结构应该成功，但得到错误: %v", err)
	}

	// 验证层次关系
	// 根节点有两个子节点
	if len(root.Children) != 2 {
		t.Errorf("根节点应该有2个子节点，但有 %d 个", len(root.Children))
	}

	// 确认mid1是root的子节点
	found := false
	for _, child := range root.Children {
		if child == mid1 {
			found = true
			break
		}
	}
	if !found {
		t.Error("mid1应该是root的子节点，但未找到")
	}

	// 确认mid1有两个子节点
	if len(mid1.Children) != 2 {
		t.Errorf("mid1应该有2个子节点，但有 %d 个", len(mid1.Children))
	}

	// 确认leaf1是mid1的子节点
	found = false
	for _, child := range mid1.Children {
		if child == leaf1 {
			found = true
			break
		}
	}
	if !found {
		t.Error("leaf1应该是mid1的子节点，但未找到")
	}

	// 确认父子关系正确设置
	if mid1.Parent != root {
		t.Error("mid1的父节点应该是root，但不是")
	}

	if leaf1.Parent != mid1 {
		t.Error("leaf1的父节点应该是mid1，但不是")
	}

	// 测试未注册的节点
	badParentChildMap := map[string][]string{
		"CWE-1000": {"CWE-999"}, // CWE-999未注册
	}

	err = registry.BuildHierarchy(badParentChildMap)
	if err == nil {
		t.Error("使用未注册的节点构建层次结构应该返回错误，但没有")
	}
}

// TestExportToJSON 测试将Registry导出为JSON
func TestExportToJSON(t *testing.T) {
	registry := NewRegistry()

	// 添加CWE
	cwe1 := NewCWE("CWE-123", "测试CWE1")
	cwe2 := NewCWE("CWE-456", "测试CWE2")
	registry.Register(cwe1)
	registry.Register(cwe2)

	// 导出为JSON
	jsonData, err := registry.ExportToJSON()
	if err != nil {
		t.Errorf("导出JSON应该成功，但得到错误: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("导出的JSON数据为空")
	}

	// 解析JSON验证内容
	var parsed map[string]*CWE
	err = json.Unmarshal(jsonData, &parsed)
	if err != nil {
		t.Errorf("解析导出的JSON应该成功，但得到错误: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("解析后应该有2个CWE条目，但有 %d 个", len(parsed))
	}

	// 验证CWE ID是否存在
	if _, exists := parsed["CWE-123"]; !exists {
		t.Error("导出的JSON中应该包含CWE-123，但未找到")
	}

	if _, exists := parsed["CWE-456"]; !exists {
		t.Error("导出的JSON中应该包含CWE-456，但未找到")
	}
}

// TestRegistryImportFromJSON 测试从JSON导入Registry
func TestRegistryImportFromJSON(t *testing.T) {
	// 准备测试数据
	jsonData := []byte(`{
		"CWE-123": {
			"ID": "CWE-123",
			"Name": "测试CWE1",
			"Description": "这是一个测试描述"
		},
		"CWE-456": {
			"ID": "CWE-456",
			"Name": "测试CWE2",
			"Description": "这是另一个测试描述"
		}
	}`)

	registry := NewRegistry()

	// 从JSON导入
	err := registry.ImportFromJSON(jsonData)
	if err != nil {
		t.Errorf("导入JSON应该成功，但得到错误: %v", err)
	}

	// 验证导入结果
	if len(registry.Entries) != 2 {
		t.Errorf("导入后应该有2个CWE条目，但有 %d 个", len(registry.Entries))
	}

	// 检查第一个CWE
	cwe1, err := registry.GetByID("CWE-123")
	if err != nil {
		t.Errorf("获取导入的CWE-123失败: %v", err)
	}

	if cwe1.Name != "测试CWE1" {
		t.Errorf("CWE-123的名称应该是'测试CWE1'，但得到 '%s'", cwe1.Name)
	}

	if cwe1.Description != "这是一个测试描述" {
		t.Errorf("CWE-123的描述应该是'这是一个测试描述'，但得到 '%s'", cwe1.Description)
	}

	// 测试导入无效JSON
	invalidJSON := []byte(`{这不是有效的JSON`)
	err = registry.ImportFromJSON(invalidJSON)
	if err == nil {
		t.Error("导入无效JSON应该返回错误，但没有")
	}

	// 测试导入空JSON
	emptyJSON := []byte(`{}`)
	err = registry.ImportFromJSON(emptyJSON)
	if err == nil {
		t.Error("导入空JSON应该返回错误，但没有")
	}

	// 测试导入空数据
	err = registry.ImportFromJSON(nil)
	if err == nil {
		t.Error("导入nil数据应该返回错误，但没有")
	}
}

// TestImportExportJSONRoundTrip 测试导入导出的循环一致性
func TestImportExportJSONRoundTrip(t *testing.T) {
	// 创建一个原始Registry
	original := NewRegistry()

	cwe1 := NewCWE("CWE-100", "Test CWE 100")
	cwe1.Description = "Description 100"
	cwe1.Severity = "High"

	cwe2 := NewCWE("CWE-200", "Test CWE 200")
	cwe2.Description = "Description 200"
	cwe2.Severity = "Medium"

	original.Register(cwe1)
	original.Register(cwe2)

	// 导出为JSON
	jsonData, err := original.ExportToJSON()
	if err != nil {
		t.Fatalf("ExportToJSON failed: %v", err)
	}

	// 创建一个新的Registry并导入JSON数据
	imported := NewRegistry()
	err = imported.ImportFromJSON(jsonData)
	if err != nil {
		t.Fatalf("ImportFromJSON failed: %v", err)
	}

	// 验证导入后的Registry与原始Registry一致
	if len(imported.Entries) != len(original.Entries) {
		t.Errorf("Imported registry has %d entries, expected %d", len(imported.Entries), len(original.Entries))
	}

	// 检查每个CWE是否正确导入
	for id, origCWE := range original.Entries {
		importedCWE, err := imported.GetByID(id)
		if err != nil {
			t.Errorf("Failed to get CWE %s from imported registry: %v", id, err)
			continue
		}

		if importedCWE.Name != origCWE.Name {
			t.Errorf("CWE %s: Name mismatch. Expected '%s', got '%s'", id, origCWE.Name, importedCWE.Name)
		}

		if importedCWE.Description != origCWE.Description {
			t.Errorf("CWE %s: Description mismatch. Expected '%s', got '%s'", id, origCWE.Description, importedCWE.Description)
		}

		if importedCWE.Severity != origCWE.Severity {
			t.Errorf("CWE %s: Severity mismatch. Expected '%s', got '%s'", id, origCWE.Severity, importedCWE.Severity)
		}
	}
}
