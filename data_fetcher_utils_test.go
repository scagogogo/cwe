package cwe

import (
	"testing"
)

// TestConvertToCWEBasic 测试基本的CWE数据转换
func TestConvertToCWEBasic(t *testing.T) {
	client := NewAPIClient()
	fetcher := NewDataFetcherWithClient(client)

	// 测试完整数据
	data := map[string]interface{}{
		"id":          "CWE-89",
		"name":        "SQL Injection",
		"description": "SQL injection description",
		"url":         "https://example.com/cwe-89",
		"mitigations": []interface{}{"Use prepared statements", "Validate input"},
		"examples":    []interface{}{"Example 1", "Example 2"},
	}

	cwe, err := fetcher.convertToCWE(data)
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
	differentData := map[string]interface{}{
		"ID":          "699",
		"Name":        "Software Development",
		"Description": "Categories in this view represent common ways that software development practices may introduce weaknesses.",
	}

	cwe, err = fetcher.convertToCWE(differentData)
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

	// 测试缺少ID的情况
	badData := map[string]interface{}{
		"name": "Bad Data",
	}

	_, err = fetcher.convertToCWE(badData)
	if err == nil {
		t.Error("Expected error for data without ID, got none")
	}

	// 测试数字ID的情况
	numericIDData := map[string]interface{}{
		"ID":   float64(79),
		"name": "XSS",
	}

	cwe, err = fetcher.convertToCWE(numericIDData)
	if err != nil {
		t.Errorf("convertToCWE failed with numeric ID: %v", err)
		return
	}

	if cwe.ID != "CWE-79" {
		t.Errorf("Expected ID to be CWE-79, got %s", cwe.ID)
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
