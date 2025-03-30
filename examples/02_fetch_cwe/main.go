// 本示例演示如何使用CWE库从API获取CWE数据
// 包括获取当前版本、获取特定CWE、CWE类别和视图等
package main

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cwe" // 导入CWE库
)

func main() {
	fmt.Println("==== CWE数据获取示例 ====")

	// 创建一个数据获取器
	// 默认使用MITRE官方API: https://cwe.mitre.org/data/api/
	fetcher := cwe.NewDataFetcher()

	// 示例1: 获取CWE当前版本
	fmt.Println("\n1. 获取CWE当前版本")
	version, err := fetcher.GetCurrentVersion()
	if err != nil {
		fmt.Printf("获取版本失败: %v\n", err)
	} else {
		fmt.Printf("当前CWE版本: %s\n", version)
	}

	// 示例2: 获取特定CWE弱点
	fmt.Println("\n2. 获取特定CWE弱点 (SQL注入, CWE-89)")
	// 可以使用数字ID或带前缀的ID
	sqlInjection, err := fetcher.FetchWeakness("89")
	if err != nil {
		fmt.Printf("获取CWE-89失败: %v\n", err)
	} else {
		// 输出获取到的数据
		fmt.Printf("CWE ID: %s\n", sqlInjection.ID)
		fmt.Printf("名称: %s\n", sqlInjection.Name)
		fmt.Printf("描述: %s\n", truncateString(sqlInjection.Description, 100))
		fmt.Printf("URL: %s\n", sqlInjection.URL)

		// 输出其他可用信息(如果有)
		if sqlInjection.Severity != "" {
			fmt.Printf("严重性: %s\n", sqlInjection.Severity)
		}
		if len(sqlInjection.Mitigations) > 0 {
			fmt.Println("缓解措施:")
			for _, mitigation := range sqlInjection.Mitigations {
				fmt.Printf("  - %s\n", mitigation)
			}
		}
	}

	// 示例3: 获取CWE类别
	fmt.Println("\n3. 获取CWE类别 (CWE-699: 软件开发错误)")
	category, err := fetcher.FetchCategory("699")
	if err != nil {
		fmt.Printf("获取CWE-699失败: %v\n", err)
	} else {
		fmt.Printf("类别ID: %s\n", category.ID)
		fmt.Printf("名称: %s\n", category.Name)
		fmt.Printf("描述: %s\n", truncateString(category.Description, 100))
	}

	// 示例4: 获取CWE视图
	fmt.Println("\n4. 获取CWE视图 (CWE-1000: 研究概念视图)")
	view, err := fetcher.FetchView("1000")
	if err != nil {
		fmt.Printf("获取CWE-1000失败: %v\n", err)
	} else {
		fmt.Printf("视图ID: %s\n", view.ID)
		fmt.Printf("名称: %s\n", view.Name)
		fmt.Printf("描述: %s\n", truncateString(view.Description, 100))
	}

	// 示例5: 同时获取多个CWE
	fmt.Println("\n5. 同时获取多个CWE")
	// 这里使用了一个ID列表，您可以根据需要修改
	ids := []string{"79", "89", "287"}
	multiRegistry, err := fetcher.FetchMultiple(ids)
	if err != nil {
		fmt.Printf("获取多个CWE失败: %v\n", err)
	} else {
		fmt.Printf("获取到的CWE数量: %d\n", len(multiRegistry.Entries))
		for id, cweItem := range multiRegistry.Entries {
			fmt.Printf("  - %s: %s\n", id, cweItem.Name)
		}
	}

	// 示例6: 获取CWE间的关系
	fmt.Println("\n6. 获取CWE之间的关系 (示例: CWE-89的父节点)")
	client := cwe.NewAPIClient() // 这里直接使用API客户端

	// 获取父节点 - 第二个参数是视图ID(可选)
	parents, err := client.GetParents("89", "")
	if err != nil {
		fmt.Printf("获取父节点失败: %v\n", err)
	} else if len(parents) == 0 {
		fmt.Println("该CWE没有父节点")
	} else {
		fmt.Printf("CWE-89的父节点: %s\n", strings.Join(parents, ", "))
	}

	// 获取子节点
	children, err := client.GetChildren("20", "")
	if err != nil {
		fmt.Printf("获取子节点失败: %v\n", err)
	} else if len(children) == 0 {
		fmt.Println("该CWE没有子节点")
	} else {
		fmt.Printf("CWE-20的子节点(最多显示5个): ")
		for i, child := range children {
			if i >= 5 {
				fmt.Printf("... 等共%d个", len(children))
				break
			}
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(child)
		}
		fmt.Println()
	}

	// 示例7: 获取CWE及其所有子关系
	fmt.Println("\n7. 获取CWE及其所有子关系 (CWE-74: 输入验证)")
	// 第二个参数是视图ID，这里使用研究视图(1000)
	cweWithRelations, err := fetcher.FetchCWEByIDWithRelations("74", "1000")
	if err != nil {
		fmt.Printf("获取CWE-74及其关系失败: %v\n", err)
	} else {
		fmt.Printf("CWE ID: %s\n", cweWithRelations.ID)
		fmt.Printf("名称: %s\n", cweWithRelations.Name)
		fmt.Printf("子节点数量: %d\n", len(cweWithRelations.Children))

		// 打印子节点
		if len(cweWithRelations.Children) > 0 {
			fmt.Println("子节点(最多显示5个):")
			for i, child := range cweWithRelations.Children {
				if i >= 5 {
					fmt.Printf("  ... 及其他 %d 个子节点\n", len(cweWithRelations.Children)-5)
					break
				}
				fmt.Printf("  - %s: %s\n", child.ID, child.Name)
			}
		}
	}

	fmt.Println("\n==== 示例完成 ====")
}

// truncateString 辅助函数：截断过长的字符串，显示开头部分
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
