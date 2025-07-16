package cwe

import (
	"testing"
)

// TestConvertToCWEBasic 测试基本的CWE数据转换
func TestConvertToCWEBasic(t *testing.T) {
	client := NewAPIClient()
	fetcher := NewDataFetcherWithClient(client)

	// 测试完整数据
	weakness := &CWEWeakness{
		ID:          "CWE-89",
		Name:        "SQL Injection",
		Description: "SQL injection description",
		URL:         "https://example.com/cwe-89",
		Severity:    "High",
		Mitigations: []CWEMitigation{
			{Description: "Use prepared statements"},
			{Description: "Validate input"},
		},
		ObservedExamples: []CWEObservedExample{
			{Description: "Example 1"},
			{Description: "Example 2"},
		},
	}

	cwe, err := fetcher.convertToCWE(weakness)
	if err != nil {
		t.Errorf("convertToCWE failed: %v", err)
		return
	}

	if cwe.ID != "CWE-89" {
		t.Errorf("Expected ID to be CWE-89, got %s", cwe.ID)
	}

	if cwe.Name != "SQL Injection" {
		t.Errorf("Expected name to be 'SQL Injection', got %s", cwe.Name)
	}

	if cwe.Description != "SQL injection description" {
		t.Errorf("Expected description to match, got %s", cwe.Description)
	}

	if cwe.URL != "https://example.com/cwe-89" {
		t.Errorf("Expected URL to match, got %s", cwe.URL)
	}

	if len(cwe.Mitigations) != 2 {
		t.Errorf("Expected 2 mitigations, got %d", len(cwe.Mitigations))
	}

	if len(cwe.Examples) != 2 {
		t.Errorf("Expected 2 examples, got %d", len(cwe.Examples))
	}

	// 测试不同字段格式
	differentWeakness := &CWEWeakness{
		ID:          "CWE-699",
		Name:        "Software Development",
		Description: "Categories in this view represent common ways that software development practices may introduce weaknesses.",
	}

	cwe, err = fetcher.convertToCWE(differentWeakness)
	if err != nil {
		t.Errorf("convertToCWE failed with different field names: %v", err)
		return
	}

	if cwe.ID != "CWE-699" {
		t.Errorf("Expected ID to be CWE-699, got %s", cwe.ID)
	}

	if cwe.Name != "Software Development" {
		t.Errorf("Expected name to be 'Software Development', got %s", cwe.Name)
	}

	// 测试nil数据的情况
	_, err = fetcher.convertToCWE(nil)
	if err == nil {
		t.Error("Expected error for nil weakness data, got none")
	}

	// 测试空ID的情况
	emptyIDWeakness := &CWEWeakness{
		Name: "XSS",
	}

	cwe, err = fetcher.convertToCWE(emptyIDWeakness)
	if err != nil {
		t.Errorf("convertToCWE failed with empty ID: %v", err)
		return
	}

	// 空ID应该被处理，但不会有CWE-前缀
	if cwe.Name != "XSS" {
		t.Errorf("Expected name to be 'XSS', got %s", cwe.Name)
	}
}

// TestIsParentRelation 测试关系类型判断功能
func TestIsParentRelation(t *testing.T) {
	// 测试父子关系
	if !isParentRelation("ChildOf") {
		t.Error("ChildOf should be a parent relation")
	}
	if !isParentRelation("MemberOf") {
		t.Error("MemberOf should be a parent relation")
	}
	if !isParentRelation("IsA") {
		t.Error("IsA should be a parent relation")
	}

	// 测试非父子关系
	if isParentRelation("ParentOf") {
		t.Error("ParentOf should not be a parent relation")
	}
	if isParentRelation("HasMember") {
		t.Error("HasMember should not be a parent relation")
	}
	if isParentRelation("PeerOf") {
		t.Error("PeerOf should not be a parent relation")
	}

	// 测试不存在的关系
	if isParentRelation("NonExistentRelation") {
		t.Error("NonExistentRelation should not be a parent relation")
	}
}
