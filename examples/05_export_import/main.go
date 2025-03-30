// 本示例演示如何导出和导入CWE数据
// 包括将CWE数据保存为JSON/XML格式以及从这些格式导入
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/scagogogo/cwe" // 导入CWE库
)

func main() {
	fmt.Println("==== CWE导出和导入示例 ====")

	// 创建一个测试数据集用于导出演示
	registry := buildTestRegistry()
	fmt.Printf("已创建包含 %d 个CWE条目的测试数据集\n", len(registry.Entries))

	// 临时目录用于保存导出文件
	tmpDir := os.TempDir()
	fmt.Printf("将使用临时目录保存导出文件: %s\n", tmpDir)

	// 示例1: 导出为JSON格式
	fmt.Println("\n1. 导出CWE数据为JSON格式")
	jsonPath := filepath.Join(tmpDir, "cwe_export.json")
	err := exportToJSON(registry, jsonPath)
	if err != nil {
		fmt.Printf("导出JSON失败: %v\n", err)
	} else {
		fmt.Printf("成功导出CWE数据至: %s\n", jsonPath)
		fileInfo, _ := os.Stat(jsonPath)
		fmt.Printf("导出文件大小: %d 字节\n", fileInfo.Size())
	}

	// 示例2: 导出为XML格式
	fmt.Println("\n2. 导出CWE数据为XML格式")
	xmlPath := filepath.Join(tmpDir, "cwe_export.xml")
	err = exportToXML(registry, xmlPath)
	if err != nil {
		fmt.Printf("导出XML失败: %v\n", err)
	} else {
		fmt.Printf("成功导出CWE数据至: %s\n", xmlPath)
		fileInfo, _ := os.Stat(xmlPath)
		fmt.Printf("导出文件大小: %d 字节\n", fileInfo.Size())
	}

	// 示例3: 从JSON导入
	fmt.Println("\n3. 从JSON导入CWE数据")
	importedFromJSON, err := importFromJSON(jsonPath)
	if err != nil {
		fmt.Printf("从JSON导入失败: %v\n", err)
	} else {
		fmt.Printf("成功从JSON导入CWE数据，包含 %d 个条目\n", len(importedFromJSON.Entries))
		fmt.Printf("导入的根节点: %s - %s\n", importedFromJSON.Root.ID, importedFromJSON.Root.Name)

		// 验证导入的数据是否包含所有原始数据
		for id, original := range registry.Entries {
			if imported, exists := importedFromJSON.Entries[id]; exists {
				if imported.Name != original.Name {
					fmt.Printf("警告: 导入的数据与原始数据不匹配 - %s\n", id)
				}
			} else {
				fmt.Printf("警告: 导入的数据中缺少 %s\n", id)
			}
		}
		fmt.Println("数据导入验证完成")
	}

	// 示例4: 从XML导入
	fmt.Println("\n4. 从XML导入CWE数据")
	importedFromXML, err := importFromXML(xmlPath)
	if err != nil {
		fmt.Printf("从XML导入失败: %v\n", err)
	} else {
		fmt.Printf("成功从XML导入CWE数据，包含 %d 个条目\n", len(importedFromXML.Entries))
		fmt.Printf("导入的根节点: %s - %s\n", importedFromXML.Root.ID, importedFromXML.Root.Name)
	}

	// 示例5: 导出单个CWE
	fmt.Println("\n5. 导出单个CWE条目")
	sqlInjection, err := registry.GetByID("CWE-89")
	if err != nil {
		fmt.Printf("获取SQL注入条目失败: %v\n", err)
	} else {
		singleCWEPath := filepath.Join(tmpDir, "cwe_89.json")
		err = exportSingleCWE(sqlInjection, singleCWEPath)
		if err != nil {
			fmt.Printf("导出单个CWE失败: %v\n", err)
		} else {
			fmt.Printf("成功导出SQL注入CWE至: %s\n", singleCWEPath)

			// 读取并显示部分内容
			content, _ := ioutil.ReadFile(singleCWEPath)
			if len(content) > 200 {
				fmt.Printf("文件内容摘要: %s...\n", content[:200])
			} else {
				fmt.Printf("文件内容: %s\n", content)
			}
		}
	}

	// 示例6: 导出特定视图的子树
	fmt.Println("\n6. 导出特定视图的子树")
	inputValidation, err := registry.GetByID("CWE-20")
	if err != nil {
		fmt.Printf("获取输入验证条目失败: %v\n", err)
	} else {
		// 创建一个新的注册表只包含这个子树
		subRegistry := cwe.NewRegistry()
		subRegistry.Root = inputValidation

		// 添加所有子节点到注册表
		addCWEAndChildrenToRegistry(inputValidation, subRegistry)

		// 导出这个子树
		subTreePath := filepath.Join(tmpDir, "input_validation_subtree.json")
		err = exportToJSON(subRegistry, subTreePath)
		if err != nil {
			fmt.Printf("导出子树失败: %v\n", err)
		} else {
			fmt.Printf("成功导出输入验证子树至: %s\n", subTreePath)
			fmt.Printf("子树包含 %d 个CWE条目\n", len(subRegistry.Entries))

			// 列出子树中的所有条目
			fmt.Println("子树包含的CWE条目:")
			for id, entry := range subRegistry.Entries {
				fmt.Printf("  - %s: %s\n", id, entry.Name)
			}
		}
	}

	// 清理导出的文件
	fmt.Println("\n清理导出的测试文件...")
	os.Remove(jsonPath)
	os.Remove(xmlPath)
	os.Remove(filepath.Join(tmpDir, "cwe_89.json"))
	os.Remove(filepath.Join(tmpDir, "input_validation_subtree.json"))

	fmt.Println("\n==== 示例完成 ====")
}

// 导出注册表到JSON文件
func exportToJSON(registry *cwe.Registry, filePath string) error {
	// 创建一个导出结构
	exportData := struct {
		Version   string              `json:"version"`
		Timestamp string              `json:"timestamp"`
		RootID    string              `json:"rootId"`
		Entries   map[string]*cwe.CWE `json:"entries"`
	}{
		Version:   "1.0",
		Timestamp: time.Now().Format(time.RFC3339),
		RootID:    registry.Root.ID,
		Entries:   registry.Entries,
	}

	// 编码为JSON
	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	return ioutil.WriteFile(filePath, data, 0644)
}

// 导出注册表到XML文件
func exportToXML(registry *cwe.Registry, filePath string) error {
	// 创建一个适合XML导出的结构
	type CWEXML struct {
		ID          string   `xml:"id,attr"`
		Name        string   `xml:"name,attr"`
		Description string   `xml:"description,omitempty"`
		URL         string   `xml:"url,omitempty"`
		Severity    string   `xml:"severity,omitempty"`
		Mitigations []string `xml:"mitigations>mitigation,omitempty"`
		Children    []string `xml:"children>child,omitempty"`
	}

	exportData := struct {
		XMLName   xml.Name `xml:"cwe-registry"`
		Version   string   `xml:"version,attr"`
		Timestamp string   `xml:"timestamp,attr"`
		RootID    string   `xml:"rootId,attr"`
		Entries   []CWEXML `xml:"entries>cwe"`
	}{
		Version:   "1.0",
		Timestamp: time.Now().Format(time.RFC3339),
		RootID:    registry.Root.ID,
		Entries:   make([]CWEXML, 0, len(registry.Entries)),
	}

	// 转换所有条目为XML格式
	for _, entry := range registry.Entries {
		childIDs := make([]string, 0, len(entry.Children))
		for _, child := range entry.Children {
			childIDs = append(childIDs, child.ID)
		}

		xmlEntry := CWEXML{
			ID:          entry.ID,
			Name:        entry.Name,
			Description: entry.Description,
			URL:         entry.URL,
			Severity:    entry.Severity,
			Mitigations: entry.Mitigations,
			Children:    childIDs,
		}
		exportData.Entries = append(exportData.Entries, xmlEntry)
	}

	// 编码为XML
	data, err := xml.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}

	// 添加XML头
	xmlHeader := []byte(xml.Header)
	data = append(xmlHeader, data...)

	// 写入文件
	return ioutil.WriteFile(filePath, data, 0644)
}

// 从JSON文件导入注册表
func importFromJSON(filePath string) (*cwe.Registry, error) {
	// 读取文件
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 解码JSON
	importData := struct {
		Version   string              `json:"version"`
		Timestamp string              `json:"timestamp"`
		RootID    string              `json:"rootId"`
		Entries   map[string]*cwe.CWE `json:"entries"`
	}{}

	err = json.Unmarshal(data, &importData)
	if err != nil {
		return nil, err
	}

	// 创建注册表
	registry := cwe.NewRegistry()
	registry.Entries = importData.Entries

	// 设置根节点
	registry.Root = registry.Entries[importData.RootID]
	if registry.Root == nil {
		return nil, fmt.Errorf("根节点ID %s 不存在于导入的数据中", importData.RootID)
	}

	// 重建父子关系
	for _, entry := range registry.Entries {
		for _, child := range entry.Children {
			child.Parent = entry
		}
	}

	return registry, nil
}

// 从XML文件导入注册表
func importFromXML(filePath string) (*cwe.Registry, error) {
	// 读取文件
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 定义与导出时相同的XML结构
	type CWEXML struct {
		ID          string   `xml:"id,attr"`
		Name        string   `xml:"name,attr"`
		Description string   `xml:"description,omitempty"`
		URL         string   `xml:"url,omitempty"`
		Severity    string   `xml:"severity,omitempty"`
		Mitigations []string `xml:"mitigations>mitigation,omitempty"`
		Children    []string `xml:"children>child,omitempty"`
	}

	importData := struct {
		XMLName   xml.Name `xml:"cwe-registry"`
		Version   string   `xml:"version,attr"`
		Timestamp string   `xml:"timestamp,attr"`
		RootID    string   `xml:"rootId,attr"`
		Entries   []CWEXML `xml:"entries>cwe"`
	}{}

	// 解码XML
	err = xml.Unmarshal(data, &importData)
	if err != nil {
		return nil, err
	}

	// 创建注册表
	registry := cwe.NewRegistry()

	// 首先创建所有CWE对象
	for _, xmlEntry := range importData.Entries {
		entry := cwe.NewCWE(xmlEntry.ID, xmlEntry.Name)
		entry.Description = xmlEntry.Description
		entry.URL = xmlEntry.URL
		entry.Severity = xmlEntry.Severity
		entry.Mitigations = xmlEntry.Mitigations

		registry.Register(entry)
	}

	// 设置根节点
	registry.Root = registry.Entries[importData.RootID]
	if registry.Root == nil {
		return nil, fmt.Errorf("根节点ID %s 不存在于导入的数据中", importData.RootID)
	}

	// 然后建立父子关系
	for _, xmlEntry := range importData.Entries {
		parent := registry.Entries[xmlEntry.ID]
		if parent == nil {
			continue
		}

		for _, childID := range xmlEntry.Children {
			child := registry.Entries[childID]
			if child != nil {
				parent.AddChild(child)
			}
		}
	}

	return registry, nil
}

// 导出单个CWE条目到JSON文件
func exportSingleCWE(cweEntry *cwe.CWE, filePath string) error {
	// 编码为JSON，使用美化格式便于阅读
	data, err := json.MarshalIndent(cweEntry, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	return ioutil.WriteFile(filePath, data, 0644)
}

// 将CWE及其所有子节点添加到注册表
func addCWEAndChildrenToRegistry(cweEntry *cwe.CWE, registry *cwe.Registry) {
	registry.Register(cweEntry)

	for _, child := range cweEntry.Children {
		addCWEAndChildrenToRegistry(child, registry)
	}
}

// 构建测试用的CWE注册表
func buildTestRegistry() *cwe.Registry {
	// 创建注册表
	registry := cwe.NewRegistry()

	// 创建根节点 (研究视图)
	root := cwe.NewCWE("CWE-1000", "Research View")
	root.Description = "CWE研究视图"
	registry.Register(root)
	registry.Root = root

	// 创建几个顶级类别
	input := cwe.NewCWE("CWE-20", "Improper Input Validation")
	input.Description = "输入验证不当会导致用户控制的输入能够以意外方式影响程序的控制流或数据流"
	root.AddChild(input)
	registry.Register(input)

	auth := cwe.NewCWE("CWE-287", "Improper Authentication")
	auth.Description = "身份验证不当可能允许攻击者在没有正确凭证的情况下获取系统访问权限"
	auth.Severity = "高"
	root.AddChild(auth)
	registry.Register(auth)

	// 添加一些输入验证类别下的子CWE
	sqlInjection := cwe.NewCWE("CWE-89", "SQL Injection")
	sqlInjection.Description = "SQL注入漏洞允许攻击者通过操纵SQL查询来访问数据库中的数据"
	sqlInjection.Severity = "高"
	sqlInjection.Mitigations = append(sqlInjection.Mitigations,
		"使用参数化查询",
		"输入验证",
		"最小权限原则")
	input.AddChild(sqlInjection)
	registry.Register(sqlInjection)

	xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
	xss.Description = "跨站脚本攻击允许攻击者向其他用户的网页会话中注入恶意代码"
	xss.Severity = "中"
	input.AddChild(xss)
	registry.Register(xss)

	// 添加身份验证相关子项
	hardcodedCreds := cwe.NewCWE("CWE-798", "Use of Hard-coded Credentials")
	hardcodedCreds.Description = "使用硬编码的凭证会导致无法撤销或更改凭证"
	hardcodedCreds.Severity = "高"
	auth.AddChild(hardcodedCreds)
	registry.Register(hardcodedCreds)

	return registry
}
