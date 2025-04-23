// 本示例演示如何使用CWE库构建完整的CWE树结构
// 展示了通过视图构建树、遍历树结构、查找节点等功能
package main

import (
	"fmt"

	"github.com/scagogogo/cwe" // 导入CWE库
)

func main() {
	fmt.Println("==== CWE树结构构建示例 ====")

	// 创建数据获取器
	fetcher := cwe.NewDataFetcher()

	// 示例1: 使用视图构建CWE树
	fmt.Println("\n1. 使用视图构建CWE树")
	// 这里使用CWE-1000(研究视图)构建树
	// 注意：此操作可能需要一些时间，因为它会递归获取很多CWE
	fmt.Println("正在构建CWE树，这可能需要一些时间...")
	registry, err := fetcher.BuildCWETreeWithView("1000")
	if err != nil {
		fmt.Printf("构建CWE树失败: %v\n", err)
		return
	}

	// 输出树的基本信息
	fmt.Printf("成功构建CWE树!\n")
	fmt.Printf("树包含CWE条目数量: %d\n", len(registry.Entries))
	fmt.Printf("根节点: %s (%s)\n", registry.Root.ID, registry.Root.Name)
	fmt.Printf("根节点有 %d 个直接子节点\n", len(registry.Root.Children))

	// 示例2: 使用BuildCWETree构建树结构
	fmt.Println("\n2. 使用BuildCWETree构建树结构")
	fmt.Println("正在构建树结构...")
	cweIDs := []string{"CWE-1000", "CWE-20", "CWE-89", "CWE-79", "CWE-77", "CWE-287", "CWE-798"}
	cweMap, rootNodes, err := fetcher.BuildCWETree(cweIDs)
	if err != nil {
		fmt.Printf("构建树结构失败: %v\n", err)
	} else {
		fmt.Printf("成功构建树结构!\n")
		fmt.Printf("CWE映射中的条目数量: %d\n", len(cweMap))
		fmt.Printf("根节点数量: %d\n", len(rootNodes))

		// 打印树结构
		fmt.Println("树结构:")
		for _, root := range rootNodes {
			printTreeNode(root, 0)
		}
	}

	// 示例3: 手动构建一个简单的CWE树
	fmt.Println("\n3. 手动构建一个简单的CWE树")
	manualRegistry := buildSampleTree()
	printTreeStructure(manualRegistry.Root, 0)

	// 示例4: 在树中查找特定CWE
	fmt.Println("\n4. 在树中查找特定CWE")
	// 查找SQL注入(CWE-89)
	cwe89 := cwe.FindByID(manualRegistry.Root, "CWE-89")
	if cwe89 != nil {
		fmt.Printf("找到 %s: %s\n", cwe89.ID, cwe89.Name)
		fmt.Printf("父节点: %s\n", cwe89.Parent.ID)

		// 获取路径
		path := cwe89.GetPath()
		fmt.Print("从根到此节点的路径: ")
		for i, node := range path {
			if i > 0 {
				fmt.Print(" -> ")
			}
			fmt.Print(node.ID)
		}
		fmt.Println()
	} else {
		fmt.Println("未找到CWE-89")
	}

	// 示例5: 关键字搜索
	fmt.Println("\n5. 在树中进行关键字搜索")
	results := cwe.FindByKeyword(manualRegistry.Root, "injection")
	fmt.Printf("找到包含'injection'的CWE: %d个\n", len(results))
	for i, result := range results {
		fmt.Printf("  %d. %s: %s\n", i+1, result.ID, result.Name)
	}

	// 示例6: 遍历树的一个子树
	fmt.Println("\n6. 遍历树的子树 (以'输入验证'为根)")
	// 查找输入验证(CWE-20)节点
	cwe20 := cwe.FindByID(manualRegistry.Root, "CWE-20")
	if cwe20 != nil {
		fmt.Printf("'%s'子树:\n", cwe20.Name)
		printTreeStructure(cwe20, 0)
	}

	fmt.Println("\n==== 示例完成 ====")
}

// buildSampleTree 手动构建一个小型的示例CWE树
func buildSampleTree() *cwe.Registry {
	// 创建注册表
	registry := cwe.NewRegistry()

	// 创建根节点 (研究视图)
	root := cwe.NewCWE("CWE-1000", "Research View")
	root.Description = "CWE研究视图"
	registry.Register(root)
	registry.Root = root

	// 创建几个顶级类别
	input := cwe.NewCWE("CWE-20", "Improper Input Validation")
	input.Description = "输入验证不当"
	root.AddChild(input)
	registry.Register(input)

	auth := cwe.NewCWE("CWE-287", "Improper Authentication")
	auth.Description = "身份验证不当"
	root.AddChild(auth)
	registry.Register(auth)

	// 添加一些子CWE
	sqlInjection := cwe.NewCWE("CWE-89", "SQL Injection")
	sqlInjection.Description = "SQL注入漏洞"
	input.AddChild(sqlInjection)
	registry.Register(sqlInjection)

	xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
	xss.Description = "跨站脚本攻击"
	input.AddChild(xss)
	registry.Register(xss)

	cmdInjection := cwe.NewCWE("CWE-77", "Command Injection")
	cmdInjection.Description = "命令注入漏洞"
	input.AddChild(cmdInjection)
	registry.Register(cmdInjection)

	// 添加身份验证相关子项
	hardcodedCreds := cwe.NewCWE("CWE-798", "Use of Hard-coded Credentials")
	hardcodedCreds.Description = "使用硬编码的凭证"
	auth.AddChild(hardcodedCreds)
	registry.Register(hardcodedCreds)

	return registry
}

// printTreeStructure 递归打印树结构，带缩进
func printTreeStructure(node *cwe.CWE, depth int) {
	// 生成缩进
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	// 打印当前节点
	fmt.Printf("%s- %s: %s\n", indent, node.ID, node.Name)

	// 递归打印子节点
	for _, child := range node.Children {
		printTreeStructure(child, depth+1)
	}
}

// printTreeNode 递归打印TreeNode结构，带缩进
func printTreeNode(node *cwe.TreeNode, depth int) {
	// 生成缩进
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	// 打印当前节点
	fmt.Printf("%s- %s: %s\n", indent, node.CWE.ID, node.CWE.Name)

	// 递归打印子节点
	for _, child := range node.Children {
		printTreeNode(child, depth+1)
	}
}
