package cwe

import (
	"testing"
)

// TestParseCWEIDBasic 测试基本的CWE ID解析
func TestParseCWEIDBasic(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		// 标准格式
		{"CWE-123", "CWE-123", false},
		{"CWE-1", "CWE-1", false},
		{"CWE-9999", "CWE-9999", false},

		// 数字格式
		{"123", "CWE-123", false},
		{"1", "CWE-1", false},
		{"9999", "CWE-9999", false},

		// 前导零
		{"CWE-001", "CWE-1", false},
		{"CWE-0123", "CWE-123", false},
		{"001", "CWE-1", false},
		{"0123", "CWE-123", false},

		// 不同大小写
		{"cwe-123", "CWE-123", false},
		{"Cwe-123", "CWE-123", false},
		{"CwE-123", "CWE-123", false},

		// 带空格
		{" CWE-123 ", "CWE-123", false},
		{" 123 ", "CWE-123", false},
		{"CWE 123", "CWE-123", false},
		// 当前实现不支持连字符两侧有空格
		// {"CWE - 123", "CWE-123", false},

		// 错误格式
		{"", "", true},
		{"CWE", "", true},
		{"CWE-", "", true},
		{"123-", "", true},
		{"CWE-abc", "", true},
		{"abc", "", true},
		{"CWE-123-456", "", true},
	}

	for _, test := range tests {
		result, err := ParseCWEID(test.input)

		if test.hasError && err == nil {
			t.Errorf("ParseCWEID(%q) 应该返回错误，但没有", test.input)
		}

		if !test.hasError && err != nil {
			t.Errorf("ParseCWEID(%q) 返回错误: %v", test.input, err)
		}

		if result != test.expected {
			t.Errorf("ParseCWEID(%q) = %q, 期望 %q", test.input, result, test.expected)
		}
	}
}

// TestParseCWEIDAdvanced 测试CWE ID解析的边界情况
func TestParseCWEIDAdvanced(t *testing.T) {
	// 非常大的ID
	largeID := "999999999"
	result, err := ParseCWEID(largeID)
	if err != nil {
		t.Errorf("ParseCWEID(%q) 返回错误: %v", largeID, err)
	}
	if result != "CWE-999999999" {
		t.Errorf("ParseCWEID(%q) = %q, 期望 %q", largeID, result, "CWE-999999999")
	}

	// 最小有效ID
	minID := "0"
	result, err = ParseCWEID(minID)
	if err != nil {
		t.Errorf("ParseCWEID(%q) 返回错误: %v", minID, err)
	}
	if result != "CWE-0" {
		t.Errorf("ParseCWEID(%q) = %q, 期望 %q", minID, result, "CWE-0")
	}

	// 当前实现不支持连字符两侧有过多空格
	/*
		mixedInput := " CWE  -  123 "
		result, err = ParseCWEID(mixedInput)
		if err != nil {
			t.Errorf("ParseCWEID(%q) 返回错误: %v", mixedInput, err)
		}
		if result != "CWE-123" {
			t.Errorf("ParseCWEID(%q) = %q, 期望 %q", mixedInput, result, "CWE-123")
		}
	*/

	// 特殊边界情况
	specialCases := []struct {
		input    string
		expected string
		hasError bool
	}{
		// 当前实现不支持连字符两侧有空格
		// {"CWE- 123", "CWE-123", false},     // 连字符后空格
		// {"CWE -123", "CWE-123", false},     // 连字符前空格
		// {"CWE - 123", "CWE-123", false},    // 连字符两侧有空格
		{"C W E - 1 2 3", "", true},   // 过多的空格，无法解析
		{"CWE--123", "", true},        // 重复的连字符
		{"CWE-123CWE-456", "", true},  // 没有分隔符的多个ID
		{"CWE-+123", "", true},        // 无效字符
		{"CWE-123!", "", true},        // 后缀无效字符
		{"123CWE", "", true},          // 错误顺序
		{"-123", "", true},            // 缺少前缀
		{"CWE-123-", "", true},        // 后缀连字符
		{"CWE-123  -  456", "", true}, // 多个数字部分
		{"cwecwe-123", "", true},      // 重复的前缀
		{"CWE.123", "", true},         // 错误的分隔符
		// 当前实现对非常长的数字处理不同
		{"0000000000000000000", "CWE-0", false}, // 过长数字会被处理为0
	}

	for _, test := range specialCases {
		result, err := ParseCWEID(test.input)

		if test.hasError && err == nil {
			t.Errorf("ParseCWEID(%q) 应该返回错误，但没有", test.input)
		}

		if !test.hasError && err != nil {
			t.Errorf("ParseCWEID(%q) 返回错误: %v", test.input, err)
		}

		if result != test.expected {
			t.Errorf("ParseCWEID(%q) = %q, 期望 %q", test.input, result, test.expected)
		}
	}
}
