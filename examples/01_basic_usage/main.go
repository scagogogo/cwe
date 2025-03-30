// 本示例演示CWE库的基本使用方式
// 包括创建CWE对象、建立层次关系、访问对象属性等基础功能
package main

import (
	"fmt"

	"github.com/scagogogo/cwe" // 导入CWE库
)

func main() {
	fmt.Println("==== CWE库基本使用示例 ====")

	// 示例1: 创建CWE对象
	fmt.Println("\n1. 创建CWE对象")
	// 创建一个表示"输入验证"类型的CWE实例
	// 参数为ID和名称
	inputValidation := cwe.NewCWE("CWE-20", "Improper Input Validation")
	fmt.Printf("已创建CWE实例 - ID: %s, 名称: %s\n", inputValidation.ID, inputValidation.Name)

	// 设置其他属性
	inputValidation.Description = "输入验证不当会导致用户控制的输入能够以意外方式影响程序的控制流或数据流"
	inputValidation.URL = "https://cwe.mitre.org/data/definitions/20.html"
	inputValidation.Severity = "高"

	// 添加缓解措施
	inputValidation.Mitigations = append(inputValidation.Mitigations,
		"实施严格的输入验证",
		"使用白名单而非黑名单")

	// 示例2: 构建CWE层次结构
	fmt.Println("\n2. 构建CWE层次结构")
	// 创建几个子类型的CWE
	sqlInjection := cwe.NewCWE("CWE-89", "SQL Injection")
	sqlInjection.Description = "SQL注入允许攻击者通过修改SQL查询来获取未经授权的数据库访问"

	xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
	xss.Description = "XSS允许攻击者通过向其他用户显示的Web页面中注入客户端脚本来绕过同源策略"

	// 建立父子关系
	// AddChild方法会自动设置Parent属性
	inputValidation.AddChild(sqlInjection)
	inputValidation.AddChild(xss)

	// 验证关系是否建立成功
	fmt.Printf("'%s'有%d个子节点\n", inputValidation.Name, len(inputValidation.Children))
	for i, child := range inputValidation.Children {
		fmt.Printf("  子节点%d: %s (%s)\n", i+1, child.ID, child.Name)
		fmt.Printf("  该子节点的父节点: %s (%s)\n", child.Parent.ID, child.Parent.Name)
	}

	// 示例3: 使用辅助方法
	fmt.Println("\n3. 使用辅助方法")

	// 获取数字ID
	numericID, err := sqlInjection.GetNumericID()
	if err == nil {
		fmt.Printf("%s的数字ID是: %d\n", sqlInjection.ID, numericID)
	}

	// 检查节点类型
	fmt.Printf("%s是根节点吗? %t\n", inputValidation.ID, inputValidation.IsRoot())
	fmt.Printf("%s是叶子节点吗? %t\n", sqlInjection.ID, sqlInjection.IsLeaf())

	// 获取从根到当前节点的路径
	path := sqlInjection.GetPath()
	fmt.Printf("%s到根节点的路径: ", sqlInjection.ID)
	for i, node := range path {
		if i > 0 {
			fmt.Print(" -> ")
		}
		fmt.Printf("%s", node.ID)
	}
	fmt.Println()

	// 示例4: 使用Registry管理多个CWE
	fmt.Println("\n4. 使用Registry管理多个CWE")

	// 创建一个新的注册表
	registry := cwe.NewRegistry()

	// 注册CWE实例
	registry.Register(inputValidation)
	registry.Register(sqlInjection)
	registry.Register(xss)

	// 从注册表中获取CWE
	retrievedCWE, err := registry.GetByID("CWE-89")
	if err == nil {
		fmt.Printf("从注册表中检索到CWE: %s (%s)\n", retrievedCWE.ID, retrievedCWE.Name)
	} else {
		fmt.Printf("检索CWE失败: %v\n", err)
	}

	fmt.Printf("注册表中的CWE数量: %d\n", len(registry.Entries))

	// 设置根节点
	registry.Root = inputValidation
	fmt.Printf("注册表根节点: %s (%s)\n", registry.Root.ID, registry.Root.Name)

	fmt.Println("\n==== 示例完成 ====")
}
