# 构建树

本示例展示如何构建和操作CWE层次结构树，包括创建、遍历和分析树结构。

## 基本树构建

### 手动构建简单树

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建根节点（视图）
    root := &cwe.TreeNode{
        CWE: &cwe.CWEView{
            ID:          "1000",
            Name:        "研究概念",
            Description: "用于研究的CWE视图",
        },
        Depth: 0,
    }
    
    // 创建类别节点
    category := &cwe.TreeNode{
        CWE: &cwe.CWECategory{
            ID:          "20",
            Name:        "输入验证不当",
            Description: "产品未正确验证输入",
        },
        Depth: 1,
    }
    
    // 创建弱点节点
    weakness1 := &cwe.TreeNode{
        CWE: &cwe.CWEWeakness{
            ID:          "79",
            Name:        "跨站脚本",
            Description: "应用程序在生成网页时未正确验证输入",
            Severity:    "Medium",
        },
        Depth: 2,
    }
    
    weakness2 := &cwe.TreeNode{
        CWE: &cwe.CWEWeakness{
            ID:          "89",
            Name:        "SQL注入",
            Description: "应用程序在构造SQL命令时未正确验证输入",
            Severity:    "High",
        },
        Depth: 2,
    }
    
    // 建立父子关系
    root.AddChild(category)
    category.AddChild(weakness1)
    category.AddChild(weakness2)
    
    // 打印树结构
    fmt.Println("CWE层次结构:")
    root.PrintTree()
}
```

### 从API构建树

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func buildTreeFromAPI(client *cwe.APIClient, viewID string) (*cwe.TreeNode, error) {
    // 获取视图信息
    view, err := client.GetView(viewID)
    if err != nil {
        return nil, fmt.Errorf("获取视图失败: %v", err)
    }
    
    // 创建根节点
    root := &cwe.TreeNode{
        CWE:   view,
        Depth: 0,
    }
    
    // 模拟添加一些子节点（实际应用中会从API获取关系数据）
    categoryIDs := []string{"20", "22", "74"}
    
    for _, categoryID := range categoryIDs {
        category, err := client.GetCategory(categoryID)
        if err != nil {
            log.Printf("获取类别CWE-%s失败: %v", categoryID, err)
            continue
        }
        
        categoryNode := &cwe.TreeNode{
            CWE:    category,
            Parent: root,
            Depth:  1,
        }
        
        root.AddChild(categoryNode)
        
        // 为每个类别添加一些弱点
        weaknessIDs := getWeaknessesForCategory(categoryID)
        for _, weaknessID := range weaknessIDs {
            weakness, err := client.GetWeakness(weaknessID)
            if err != nil {
                log.Printf("获取弱点CWE-%s失败: %v", weaknessID, err)
                continue
            }
            
            weaknessNode := &cwe.TreeNode{
                CWE:    weakness,
                Parent: categoryNode,
                Depth:  2,
            }
            
            categoryNode.AddChild(weaknessNode)
        }
    }
    
    return root, nil
}

func getWeaknessesForCategory(categoryID string) []string {
    // 模拟数据 - 实际应用中应该从API获取
    switch categoryID {
    case "20":
        return []string{"79", "89", "78"}
    case "22":
        return []string{"77", "352"}
    case "74":
        return []string{"434", "502"}
    default:
        return []string{}
    }
}

func main() {
    client := cwe.NewAPIClient()
    
    fmt.Println("正在从API构建CWE树...")
    
    tree, err := buildTreeFromAPI(client, "1000")
    if err != nil {
        log.Fatalf("构建树失败: %v", err)
    }
    
    fmt.Println("构建完成！")
    fmt.Println("\nCWE层次结构:")
    tree.PrintTree()
    
    // 显示统计信息
    stats := tree.GetStats()
    fmt.Printf("\n统计信息:\n")
    fmt.Printf("  总节点数: %d\n", stats["total"])
    fmt.Printf("  弱点数: %d\n", stats["weaknesses"])
    fmt.Printf("  类别数: %d\n", stats["categories"])
    fmt.Printf("  视图数: %d\n", stats["views"])
    fmt.Printf("  叶子节点数: %d\n", stats["leaves"])
}
```

## 树的遍历

### 深度优先遍历

```go
package main

import (
    "fmt"
    "strings"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建示例树
    tree := createSampleTree()
    
    fmt.Println("深度优先遍历:")
    tree.Walk(func(node *cwe.TreeNode) {
        indent := strings.Repeat("  ", node.Depth)
        
        switch cweData := node.CWE.(type) {
        case *cwe.CWEView:
            fmt.Printf("%s📁 视图: CWE-%s - %s\n", indent, cweData.ID, cweData.Name)
        case *cwe.CWECategory:
            fmt.Printf("%s📂 类别: CWE-%s - %s\n", indent, cweData.ID, cweData.Name)
        case *cwe.CWEWeakness:
            fmt.Printf("%s🐛 弱点: CWE-%s - %s", indent, cweData.ID, cweData.Name)
            if cweData.Severity != "" {
                fmt.Printf(" [%s]", cweData.Severity)
            }
            fmt.Println()
        }
    })
}

func createSampleTree() *cwe.TreeNode {
    // 创建示例树结构
    root := &cwe.TreeNode{
        CWE: &cwe.CWEView{
            ID:   "1000",
            Name: "研究概念",
        },
        Depth: 0,
    }
    
    category := &cwe.TreeNode{
        CWE: &cwe.CWECategory{
            ID:   "20",
            Name: "输入验证不当",
        },
        Depth: 1,
    }
    
    weakness1 := &cwe.TreeNode{
        CWE: &cwe.CWEWeakness{
            ID:       "79",
            Name:     "跨站脚本",
            Severity: "Medium",
        },
        Depth: 2,
    }
    
    weakness2 := &cwe.TreeNode{
        CWE: &cwe.CWEWeakness{
            ID:       "89",
            Name:     "SQL注入",
            Severity: "High",
        },
        Depth: 2,
    }
    
    root.AddChild(category)
    category.AddChild(weakness1)
    category.AddChild(weakness2)
    
    return root
}
```

### 广度优先遍历

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func main() {
    tree := createSampleTree()
    
    fmt.Println("广度优先遍历:")
    tree.BreadthFirstWalk(func(node *cwe.TreeNode) {
        switch cweData := node.CWE.(type) {
        case *cwe.CWEView:
            fmt.Printf("深度%d - 视图: CWE-%s\n", node.Depth, cweData.ID)
        case *cwe.CWECategory:
            fmt.Printf("深度%d - 类别: CWE-%s\n", node.Depth, cweData.ID)
        case *cwe.CWEWeakness:
            fmt.Printf("深度%d - 弱点: CWE-%s [%s]\n", node.Depth, cweData.ID, cweData.Severity)
        }
    })
}
```

### 条件遍历

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func main() {
    tree := createSampleTree()
    
    fmt.Println("只遍历高严重程度的弱点:")
    tree.WalkIf(
        func(node *cwe.TreeNode) {
            if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
                fmt.Printf("🚨 高危弱点: CWE-%s - %s\n", weakness.ID, weakness.Name)
            }
        },
        func(node *cwe.TreeNode) bool {
            if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
                return weakness.Severity == "High"
            }
            return false
        },
    )
}
```

## 树的搜索

### 按ID查找

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func main() {
    tree := createSampleTree()
    
    // 查找特定ID的节点
    targetID := "89"
    node := tree.FindByID(targetID)
    
    if node != nil {
        fmt.Printf("找到CWE-%s:\n", targetID)
        
        if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
            fmt.Printf("  名称: %s\n", weakness.Name)
            fmt.Printf("  严重程度: %s\n", weakness.Severity)
            fmt.Printf("  深度: %d\n", node.Depth)
            fmt.Printf("  路径: %s\n", node.GetPathString())
        }
    } else {
        fmt.Printf("未找到CWE-%s\n", targetID)
    }
}
```

### 按条件查找

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func main() {
    tree := createSampleTree()
    
    // 查找所有高严重程度的弱点
    highSeverityNodes := tree.FindAll(func(node *cwe.TreeNode) bool {
        if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
            return weakness.Severity == "High"
        }
        return false
    })
    
    fmt.Printf("找到 %d 个高严重程度弱点:\n", len(highSeverityNodes))
    for _, node := range highSeverityNodes {
        if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
            fmt.Printf("  CWE-%s: %s\n", weakness.ID, weakness.Name)
        }
    }
    
    // 查找所有叶子节点
    leaves := tree.GetLeaves()
    fmt.Printf("\n找到 %d 个叶子节点:\n", len(leaves))
    for _, leaf := range leaves {
        switch cweData := leaf.CWE.(type) {
        case *cwe.CWEWeakness:
            fmt.Printf("  弱点: CWE-%s\n", cweData.ID)
        case *cwe.CWECategory:
            fmt.Printf("  类别: CWE-%s\n", cweData.ID)
        case *cwe.CWEView:
            fmt.Printf("  视图: CWE-%s\n", cweData.ID)
        }
    }
}
```

## 树的分析

### 统计分析

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func analyzeTree(tree *cwe.TreeNode) {
    fmt.Println("=== 树结构分析 ===")
    
    // 基本统计
    stats := tree.GetStats()
    fmt.Printf("基本统计:\n")
    fmt.Printf("  总节点数: %d\n", stats["total"])
    fmt.Printf("  弱点数: %d\n", stats["weaknesses"])
    fmt.Printf("  类别数: %d\n", stats["categories"])
    fmt.Printf("  视图数: %d\n", stats["views"])
    fmt.Printf("  叶子节点数: %d\n", stats["leaves"])
    
    // 深度分析
    maxDepth := 0
    depthCount := make(map[int]int)
    
    tree.Walk(func(node *cwe.TreeNode) {
        if node.Depth > maxDepth {
            maxDepth = node.Depth
        }
        depthCount[node.Depth]++
    })
    
    fmt.Printf("\n深度分析:\n")
    fmt.Printf("  最大深度: %d\n", maxDepth)
    for depth := 0; depth <= maxDepth; depth++ {
        fmt.Printf("  深度%d: %d个节点\n", depth, depthCount[depth])
    }
    
    // 严重程度分析
    severityCount := make(map[string]int)
    tree.Walk(func(node *cwe.TreeNode) {
        if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
            if weakness.Severity != "" {
                severityCount[weakness.Severity]++
            } else {
                severityCount["Unknown"]++
            }
        }
    })
    
    if len(severityCount) > 0 {
        fmt.Printf("\n严重程度分布:\n")
        for severity, count := range severityCount {
            fmt.Printf("  %s: %d个\n", severity, count)
        }
    }
}

func main() {
    tree := createLargerSampleTree()
    analyzeTree(tree)
}

func createLargerSampleTree() *cwe.TreeNode {
    // 创建更大的示例树
    root := &cwe.TreeNode{
        CWE: &cwe.CWEView{
            ID:   "1000",
            Name: "研究概念",
        },
        Depth: 0,
    }
    
    // 添加多个类别
    categories := []struct {
        ID   string
        Name string
    }{
        {"20", "输入验证不当"},
        {"22", "路径遍历"},
        {"74", "中和不当"},
    }
    
    for _, cat := range categories {
        categoryNode := &cwe.TreeNode{
            CWE: &cwe.CWECategory{
                ID:   cat.ID,
                Name: cat.Name,
            },
            Depth: 1,
        }
        root.AddChild(categoryNode)
        
        // 为每个类别添加弱点
        weaknesses := getWeaknessesForCategory(cat.ID)
        for _, w := range weaknesses {
            weaknessNode := &cwe.TreeNode{
                CWE: &cwe.CWEWeakness{
                    ID:       w.ID,
                    Name:     w.Name,
                    Severity: w.Severity,
                },
                Depth: 2,
            }
            categoryNode.AddChild(weaknessNode)
        }
    }
    
    return root
}

type WeaknessInfo struct {
    ID       string
    Name     string
    Severity string
}

func getWeaknessesForCategory(categoryID string) []WeaknessInfo {
    switch categoryID {
    case "20":
        return []WeaknessInfo{
            {"79", "跨站脚本", "Medium"},
            {"89", "SQL注入", "High"},
            {"78", "OS命令注入", "High"},
        }
    case "22":
        return []WeaknessInfo{
            {"77", "路径遍历", "Medium"},
            {"352", "跨站请求伪造", "Medium"},
        }
    case "74":
        return []WeaknessInfo{
            {"434", "不受限制的文件上传", "High"},
            {"502", "反序列化不可信数据", "Critical"},
        }
    default:
        return []WeaknessInfo{}
    }
}
```

## 树的序列化

### 保存和加载树

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建树
    tree := createSampleTree()
    
    // 保存到文件
    filename := "cwe_tree.json"
    err := tree.SaveToFile(filename)
    if err != nil {
        log.Fatalf("保存树失败: %v", err)
    }
    fmt.Printf("树已保存到 %s\n", filename)
    
    // 从文件加载
    loadedTree, err := cwe.LoadTreeFromFile(filename)
    if err != nil {
        log.Fatalf("加载树失败: %v", err)
    }
    fmt.Println("树已从文件加载")
    
    // 验证加载的树
    fmt.Println("\n加载的树结构:")
    loadedTree.PrintTree()
    
    // 比较统计信息
    originalStats := tree.GetStats()
    loadedStats := loadedTree.GetStats()
    
    fmt.Printf("\n统计信息比较:\n")
    fmt.Printf("原始树 - 总节点: %d, 弱点: %d\n", 
        originalStats["total"], originalStats["weaknesses"])
    fmt.Printf("加载树 - 总节点: %d, 弱点: %d\n", 
        loadedStats["total"], loadedStats["weaknesses"])
}
```

## 运行示例

保存任意示例代码为 `main.go`，然后运行：

```bash
go mod init cwe-tree-example
go get github.com/scagogogo/cwe
go run main.go
```

## 最佳实践

1. **内存管理** - 对于大型树，注意内存使用
2. **深度控制** - 避免过深的递归导致栈溢出
3. **数据一致性** - 确保父子关系的正确性
4. **性能优化** - 对于频繁查找，考虑建立索引
5. **错误处理** - 处理树操作中的各种错误情况

## 下一步

- 学习[搜索和过滤](./search-filter)功能
- 了解[导出和导入](./export-import)数据的方法
- 探索[速率限制客户端](./rate-limited)的高级用法
