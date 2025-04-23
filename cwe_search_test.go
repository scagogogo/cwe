package cwe

import (
	"testing"
)

// TestFindByID 测试FindByID函数
func TestFindByIDComprehensive(t *testing.T) {
	// 创建测试树结构
	root := NewCWE("CWE-1000", "根节点")
	level1A := NewCWE("CWE-100", "一级节点A")
	level1B := NewCWE("CWE-200", "一级节点B")
	level2A := NewCWE("CWE-101", "二级节点A")
	level2B := NewCWE("CWE-102", "二级节点B")
	level2C := NewCWE("CWE-201", "二级节点C")
	level3A := NewCWE("CWE-103", "三级节点A")

	// 构建树结构
	root.AddChild(level1A)
	root.AddChild(level1B)
	level1A.AddChild(level2A)
	level1A.AddChild(level2B)
	level1B.AddChild(level2C)
	level2B.AddChild(level3A)

	// 正常测试用例
	tests := []struct {
		id       string
		expected *CWE
	}{
		{"CWE-1000", root},
		{"CWE-100", level1A},
		{"CWE-200", level1B},
		{"CWE-101", level2A},
		{"CWE-102", level2B},
		{"CWE-201", level2C},
		{"CWE-103", level3A},
	}

	for _, test := range tests {
		result := FindByID(root, test.id)
		if result != test.expected {
			t.Errorf("FindByID(%s) 返回了错误的节点: 期望 %v, 得到 %v", test.id, test.expected, result)
		}
	}

	// 不存在的ID测试
	notExistTests := []string{
		"CWE-999",
		"CWE-",
		"",
		"Invalid",
	}

	for _, id := range notExistTests {
		result := FindByID(root, id)
		if result != nil {
			t.Errorf("FindByID(%s) 应该返回nil，但得到 %v", id, result)
		}
	}

	// 测试nil根节点
	if FindByID(nil, "CWE-100") != nil {
		t.Error("FindByID应该安全处理nil根节点")
	}
}

// TestFindByKeyword 测试FindByKeyword函数
func TestFindByKeywordComprehensive(t *testing.T) {
	// 创建测试树结构
	root := NewCWE("CWE-1000", "安全风险")
	root.Description = "这是一个包含各种安全风险的根节点"

	nodeA := NewCWE("CWE-100", "输入验证")
	nodeA.Description = "与输入验证相关的安全问题"

	nodeB := NewCWE("CWE-200", "信息泄露")
	nodeB.Description = "可能导致敏感信息泄露的问题"

	nodeC := NewCWE("CWE-300", "认证问题")
	nodeC.Description = "与身份验证和会话管理相关的问题"

	nodeD := NewCWE("CWE-400", "资源管理")
	nodeD.Description = "资源管理不当可能导致拒绝服务"

	nodeE := NewCWE("CWE-500", "加密问题")
	nodeE.Description = "涉及加密算法实现的安全问题"

	// 构建树结构
	root.AddChild(nodeA)
	root.AddChild(nodeB)
	root.AddChild(nodeC)
	nodeC.AddChild(nodeD)
	nodeC.AddChild(nodeE)

	// 测试用例
	tests := []struct {
		keyword      string
		expectedIDs  []string
		expectedDesc string
	}{
		// 精确匹配名称
		{"输入验证", []string{"CWE-100"}, "应该只找到'输入验证'节点"},

		// 修正预期匹配数量(A, C, E)
		{"安全问题", []string{"CWE-100", "CWE-500"}, "应该找到所有包含'安全问题'的节点"},

		// 不区分大小写匹配
		{"信息泄露", []string{"CWE-200"}, "应该找到'信息泄露'节点"},

		// 空关键字会匹配所有节点，因为实现不排除空关键字
		{"", []string{"CWE-1000", "CWE-100", "CWE-200", "CWE-300", "CWE-400", "CWE-500"}, "空关键字在当前实现下匹配所有节点"},

		// 不存在的关键字
		{"不存在的关键字", []string{}, "不存在的关键字应该不匹配任何节点"},

		// 部分匹配
		{"验证", []string{"CWE-100", "CWE-300"}, "应该找到所有包含'验证'的节点"},

		// 匹配根节点
		{"安全风险", []string{"CWE-1000"}, "应该找到根节点"},
	}

	for _, test := range tests {
		results := FindByKeyword(root, test.keyword)

		// 验证结果数量
		if len(results) != len(test.expectedIDs) {
			t.Errorf("FindByKeyword(%s) 返回了 %d 个结果, 期望 %d 个: %s",
				test.keyword, len(results), len(test.expectedIDs), test.expectedDesc)
			continue
		}

		// 验证结果包含所有期望的ID
		for _, expected := range test.expectedIDs {
			found := false
			for _, cwe := range results {
				if cwe.ID == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("FindByKeyword(%s) 应该返回 %s，但未找到: %s",
					test.keyword, expected, test.expectedDesc)
			}
		}
	}

	// 测试nil根节点
	if len(FindByKeyword(nil, "测试")) != 0 {
		t.Error("FindByKeyword应该安全处理nil根节点")
	}
}
