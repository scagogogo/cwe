// 本示例演示如何使用CWE库搜索和筛选CWE条目
// 包括按关键字搜索、按ID查找、自定义筛选等
package main

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cwe" // 导入CWE库
)

func main() {
	fmt.Println("==== CWE搜索和筛选示例 ====")

	// 首先构建一个包含足够数据的CWE树
	registry := buildTestRegistry()
	fmt.Printf("已构建测试注册表，包含 %d 个CWE条目\n", len(registry.Entries))

	// 示例1: 按ID查找
	fmt.Println("\n1. 按ID查找CWE")
	// 找到CWE-79 (跨站脚本)
	xss, err := registry.GetByID("CWE-79")
	if err != nil {
		fmt.Printf("查找CWE-79失败: %v\n", err)
	} else {
		fmt.Printf("找到 %s: %s\n", xss.ID, xss.Name)
		fmt.Printf("描述: %s\n", xss.Description)
	}

	// 尝试查找一个不存在的ID
	nonExistent, err := registry.GetByID("CWE-9999")
	if err != nil {
		fmt.Printf("查找CWE-9999失败: %v\n", err) // 预期会失败
	} else {
		fmt.Printf("找到 %s: %s\n", nonExistent.ID, nonExistent.Name)
	}

	// 示例2: 在树中使用FindByID查找
	fmt.Println("\n2. 在树中使用FindByID查找")
	// FindByID从根节点开始递归搜索，不需要准确的ID格式
	sqli := cwe.FindByID(registry.Root, "89") // 不需要CWE-前缀
	if sqli != nil {
		fmt.Printf("找到 %s: %s\n", sqli.ID, sqli.Name)
		// 显示其在树中的位置
		if sqli.Parent != nil {
			fmt.Printf("父节点: %s (%s)\n", sqli.Parent.ID, sqli.Parent.Name)
		}
	} else {
		fmt.Println("未找到CWE-89")
	}

	// 示例3: 关键字搜索
	fmt.Println("\n3. 关键字搜索")
	// 搜索包含"injection"的CWE
	injectionResults := cwe.FindByKeyword(registry.Root, "injection")
	fmt.Printf("找到包含'injection'的CWE: %d个\n", len(injectionResults))
	for i, result := range injectionResults {
		fmt.Printf("  %d. %s: %s\n", i+1, result.ID, result.Name)
	}

	// 搜索包含"authentication"的CWE
	authResults := cwe.FindByKeyword(registry.Root, "authentication")
	fmt.Printf("找到包含'authentication'的CWE: %d个\n", len(authResults))
	for i, result := range authResults {
		fmt.Printf("  %d. %s: %s\n", i+1, result.ID, result.Name)
	}

	// 示例4: 自定义筛选函数
	fmt.Println("\n4. 使用自定义函数筛选")
	// 找出所有叶子节点
	leaves := filterCWEs(registry.Entries, func(c *cwe.CWE) bool {
		return c.IsLeaf()
	})
	fmt.Printf("找到叶子节点: %d个\n", len(leaves))
	for i, leaf := range leaves {
		fmt.Printf("  %d. %s: %s\n", i+1, leaf.ID, leaf.Name)
	}

	// 找出所有严重性为"高"的CWE
	highSeverity := filterCWEs(registry.Entries, func(c *cwe.CWE) bool {
		return strings.Contains(strings.ToLower(c.Severity), "高") ||
			strings.Contains(strings.ToLower(c.Severity), "high")
	})
	fmt.Printf("找到高严重性CWE: %d个\n", len(highSeverity))
	for i, cwe := range highSeverity {
		fmt.Printf("  %d. %s: %s (严重性: %s)\n", i+1, cwe.ID, cwe.Name, cwe.Severity)
	}

	// 示例5: 复合条件筛选
	fmt.Println("\n5. 复合条件筛选")
	// 找出所有输入验证类别下的且有缓解措施的叶子节点
	inputValidationWithMitigations := filterCWEs(registry.Entries, func(c *cwe.CWE) bool {
		// 检查是否是叶子节点
		isLeaf := c.IsLeaf()
		// 检查是否有缓解措施
		hasMitigations := len(c.Mitigations) > 0
		// 检查是否在输入验证类别下
		inInputValidation := false
		current := c
		for current != nil && current.Parent != nil {
			if current.Parent.ID == "CWE-20" {
				inInputValidation = true
				break
			}
			current = current.Parent
		}
		return isLeaf && hasMitigations && inInputValidation
	})
	fmt.Printf("找到输入验证类别下有缓解措施的叶子节点: %d个\n", len(inputValidationWithMitigations))
	for i, cwe := range inputValidationWithMitigations {
		fmt.Printf("  %d. %s: %s\n", i+1, cwe.ID, cwe.Name)
		fmt.Printf("     缓解措施: %d个\n", len(cwe.Mitigations))
		for j, mitigation := range cwe.Mitigations {
			if j < 2 { // 只显示前两个缓解措施
				fmt.Printf("       - %s\n", mitigation)
			} else {
				fmt.Printf("       - ... 等\n")
				break
			}
		}
	}

	fmt.Println("\n==== 示例完成 ====")
}

// filterCWEs 根据提供的过滤函数筛选CWE
func filterCWEs(entries map[string]*cwe.CWE, filter func(*cwe.CWE) bool) []*cwe.CWE {
	results := make([]*cwe.CWE, 0)
	for _, entry := range entries {
		if filter(entry) {
			results = append(results, entry)
		}
	}
	return results
}

// buildTestRegistry 构建一个测试用的CWE注册表
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

	crypto := cwe.NewCWE("CWE-310", "Cryptographic Issues")
	crypto.Description = "加密问题可能导致敏感数据泄露或系统完整性问题"
	root.AddChild(crypto)
	registry.Register(crypto)

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
	xss.Mitigations = append(xss.Mitigations,
		"输出编码",
		"内容安全策略(CSP)")
	input.AddChild(xss)
	registry.Register(xss)

	cmdInjection := cwe.NewCWE("CWE-77", "Command Injection")
	cmdInjection.Description = "命令注入漏洞允许攻击者通过注入操作系统命令来执行任意命令"
	cmdInjection.Severity = "高"
	input.AddChild(cmdInjection)
	registry.Register(cmdInjection)

	// 添加身份验证相关子项
	hardcodedCreds := cwe.NewCWE("CWE-798", "Use of Hard-coded Credentials")
	hardcodedCreds.Description = "使用硬编码的凭证会导致无法撤销或更改凭证"
	hardcodedCreds.Severity = "高"
	auth.AddChild(hardcodedCreds)
	registry.Register(hardcodedCreds)

	weakAuth := cwe.NewCWE("CWE-308", "Use of Single-factor Authentication")
	weakAuth.Description = "仅使用单因素身份验证可能会导致凭证被轻易破解"
	weakAuth.Severity = "中"
	auth.AddChild(weakAuth)
	registry.Register(weakAuth)

	// 添加加密相关子项
	weakCrypto := cwe.NewCWE("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm")
	weakCrypto.Description = "使用已知存在缺陷的加密算法可能导致机密性或完整性被破坏"
	weakCrypto.Severity = "高"
	crypto.AddChild(weakCrypto)
	registry.Register(weakCrypto)

	insecureRandom := cwe.NewCWE("CWE-338", "Use of Cryptographically Weak Pseudo-Random Number Generator")
	insecureRandom.Description = "使用加密弱的伪随机数生成器可能导致可预测的值"
	insecureRandom.Severity = "中"
	insecureRandom.Mitigations = append(insecureRandom.Mitigations,
		"使用密码学安全的随机数生成器",
		"避免使用Math.random()")
	crypto.AddChild(insecureRandom)
	registry.Register(insecureRandom)

	return registry
}
