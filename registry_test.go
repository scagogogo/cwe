package cwe

import (
	"testing"
)

// TestRegisterComprehensive 全面测试Register方法的各种情况
func TestRegisterComprehensive(t *testing.T) {
	registry := NewRegistry()

	// 测试正常注册
	cwe1 := NewCWE("CWE-100", "Test CWE 100")
	err := registry.Register(cwe1)
	if err != nil {
		t.Errorf("Register failed for normal case: %v", err)
	}
	if len(registry.Entries) != 1 {
		t.Errorf("Expected 1 entry in registry, got %d", len(registry.Entries))
	}
	if registry.Entries["CWE-100"] != cwe1 {
		t.Error("Registry did not store the correct CWE")
	}

	// 测试注册nil CWE
	err = registry.Register(nil)
	if err == nil {
		t.Error("Register should fail for nil CWE")
	}

	// 测试注册无ID的CWE
	cweNoID := NewCWE("", "No ID")
	err = registry.Register(cweNoID)
	if err == nil {
		t.Error("Register should fail for CWE without ID")
	}

	// 测试注册重复ID的CWE
	cweDuplicate := NewCWE("CWE-100", "Duplicate ID")
	err = registry.Register(cweDuplicate)
	if err == nil {
		t.Error("Register should fail for duplicate ID")
	}

	// 验证注册表内容未被修改
	if len(registry.Entries) != 1 {
		t.Errorf("Expected registry to still have 1 entry, got %d", len(registry.Entries))
	}
	if registry.Entries["CWE-100"] != cwe1 {
		t.Error("Registry should not have replaced the original CWE")
	}
}

// TestRegistryBuildHierarchy 测试构建CWE层次结构
func TestRegistryBuildHierarchyComprehensive(t *testing.T) {
	registry := NewRegistry()

	// 创建CWE
	root := NewCWE("CWE-1000", "Root")
	mid := NewCWE("CWE-20", "Middle")
	leaf := NewCWE("CWE-89", "Leaf")
	unrelated := NewCWE("CWE-999", "Unrelated")

	// 注册所有CWE
	registry.Register(root)
	registry.Register(mid)
	registry.Register(leaf)
	registry.Register(unrelated)

	// 建立层次关系
	parentChildMap := map[string][]string{
		"CWE-1000": {"CWE-20"},
		"CWE-20":   {"CWE-89"},
	}

	err := registry.BuildHierarchy(parentChildMap)
	if err != nil {
		t.Errorf("BuildHierarchy failed: %v", err)
	}

	// 验证层次关系
	if root.Children[0] != mid {
		t.Error("Root should have mid as child")
	}
	if mid.Parent != root {
		t.Error("Mid should have root as parent")
	}
	if mid.Children[0] != leaf {
		t.Error("Mid should have leaf as child")
	}
	if leaf.Parent != mid {
		t.Error("Leaf should have mid as parent")
	}
	if unrelated.Parent != nil {
		t.Error("Unrelated should not have a parent")
	}
	if len(unrelated.Children) != 0 {
		t.Error("Unrelated should not have children")
	}

	// 测试未注册的父节点
	badParentMap := map[string][]string{
		"CWE-9999": {"CWE-89"}, // 不存在的父节点
	}
	err = registry.BuildHierarchy(badParentMap)
	if err == nil {
		t.Error("BuildHierarchy should fail for unregistered parent")
	}

	// 测试未注册的子节点
	badChildMap := map[string][]string{
		"CWE-1000": {"CWE-9999"}, // 不存在的子节点
	}
	err = registry.BuildHierarchy(badChildMap)
	if err == nil {
		t.Error("BuildHierarchy should fail for unregistered child")
	}
}
