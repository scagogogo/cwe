# 搜索和过滤

本示例展示如何使用CWE Go库的搜索和过滤功能来查找特定的CWE数据。

## 基本搜索

### 关键字搜索

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建注册表
    registry := cwe.NewCWERegistry()
    
    // 添加一些测试数据
    testData := []*cwe.CWEWeakness{
        {
            ID:          "79",
            Name:        "跨站脚本",
            Description: "应用程序在生成网页时未正确验证输入，导致恶意脚本执行",
            Severity:    "Medium",
        },
        {
            ID:          "89",
            Name:        "SQL注入",
            Description: "应用程序在构造SQL命令时未正确验证输入",
            Severity:    "High",
        },
        {
            ID:          "78",
            Name:        "OS命令注入",
            Description: "应用程序在构造操作系统命令时未正确验证输入",
            Severity:    "High",
        },
        {
            ID:          "352",
            Name:        "跨站请求伪造",
            Description: "应用程序未验证请求是否来自可信源",
            Severity:    "Medium",
        },
    }
    
    // 添加到注册表
    for _, weakness := range testData {
        registry.AddCWE(weakness)
    }
    
    // 搜索包含"注入"的CWE
    fmt.Println("搜索关键字 '注入':")
    results := registry.SearchByKeyword("注入")
    
    fmt.Printf("找到 %d 个结果:\n", len(results))
    for _, result := range results {
        fmt.Printf("- CWE-%s: %s\n", result.GetID(), result.GetName())
    }
    
    // 搜索包含"脚本"的CWE
    fmt.Println("\n搜索关键字 '脚本':")
    scriptResults := registry.SearchByKeyword("脚本")
    
    fmt.Printf("找到 %d 个结果:\n", len(scriptResults))
    for _, result := range scriptResults {
        fmt.Printf("- CWE-%s: %s\n", result.GetID(), result.GetName())
    }
}
```

### 多关键字搜索

```go
package main

import (
    "fmt"
    "strings"
    
    "github.com/scagogogo/cwe"
)

func searchMultipleKeywords(registry *cwe.CWERegistry, keywords []string) []interface{} {
    var results []interface{}
    
    allData := registry.GetAll()
    
    for _, item := range allData {
        text := getSearchableText(item)
        matchesAll := true
        
        // 检查是否包含所有关键字
        for _, keyword := range keywords {
            if !strings.Contains(strings.ToLower(text), strings.ToLower(keyword)) {
                matchesAll = false
                break
            }
        }
        
        if matchesAll {
            results = append(results, item)
        }
    }
    
    return results
}

func getSearchableText(item interface{}) string {
    switch data := item.(type) {
    case *cwe.CWEWeakness:
        return data.Name + " " + data.Description
    case *cwe.CWECategory:
        return data.Name + " " + data.Description
    case *cwe.CWEView:
        return data.Name + " " + data.Description
    default:
        return ""
    }
}

func main() {
    registry := createSampleRegistry()
    
    // 搜索同时包含"应用程序"和"验证"的CWE
    keywords := []string{"应用程序", "验证"}
    results := searchMultipleKeywords(registry, keywords)
    
    fmt.Printf("搜索关键字 %v:\n", keywords)
    fmt.Printf("找到 %d 个结果:\n", len(results))
    
    for _, result := range results {
        switch data := result.(type) {
        case *cwe.CWEWeakness:
            fmt.Printf("- CWE-%s: %s\n", data.ID, data.Name)
        }
    }
}

func createSampleRegistry() *cwe.CWERegistry {
    registry := cwe.NewCWERegistry()
    
    testData := []*cwe.CWEWeakness{
        {
            ID:          "79",
            Name:        "跨站脚本",
            Description: "应用程序在生成网页时未正确验证输入",
            Severity:    "Medium",
        },
        {
            ID:          "89",
            Name:        "SQL注入",
            Description: "应用程序在构造SQL命令时未正确验证输入",
            Severity:    "High",
        },
        {
            ID:          "20",
            Name:        "输入验证不当",
            Description: "产品未正确验证输入",
            Severity:    "Low",
        },
    }
    
    for _, weakness := range testData {
        registry.AddCWE(weakness)
    }
    
    return registry
}
```

## 高级过滤

### 按严重程度过滤

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

func filterBySeverity(registry *cwe.CWERegistry, severity string) []*cwe.CWEWeakness {
    var results []*cwe.CWEWeakness
    
    weaknesses := registry.GetWeaknesses()
    for _, weakness := range weaknesses {
        if weakness.Severity == severity {
            results = append(results, weakness)
        }
    }
    
    return results
}

func main() {
    registry := createSampleRegistry()
    
    // 按不同严重程度过滤
    severities := []string{"High", "Medium", "Low"}
    
    for _, severity := range severities {
        results := filterBySeverity(registry, severity)
        fmt.Printf("%s严重程度的弱点 (%d个):\n", severity, len(results))
        
        for _, weakness := range results {
            fmt.Printf("  - CWE-%s: %s\n", weakness.ID, weakness.Name)
        }
        fmt.Println()
    }
}
```

### 按ID范围过滤

```go
package main

import (
    "fmt"
    "strconv"
    
    "github.com/scagogogo/cwe"
)

func filterByIDRange(registry *cwe.CWERegistry, minID, maxID int) []interface{} {
    var results []interface{}
    
    allData := registry.GetAll()
    for _, item := range allData {
        id := getNumericID(item)
        if id >= minID && id <= maxID {
            results = append(results, item)
        }
    }
    
    return results
}

func getNumericID(item interface{}) int {
    var idStr string
    
    switch data := item.(type) {
    case *cwe.CWEWeakness:
        idStr = data.ID
    case *cwe.CWECategory:
        idStr = data.ID
    case *cwe.CWEView:
        idStr = data.ID
    default:
        return 0
    }
    
    id, err := strconv.Atoi(idStr)
    if err != nil {
        return 0
    }
    
    return id
}

func main() {
    registry := createExtendedRegistry()
    
    // 过滤ID在70-90范围内的CWE
    results := filterByIDRange(registry, 70, 90)
    
    fmt.Printf("ID在70-90范围内的CWE (%d个):\n", len(results))
    for _, result := range results {
        switch data := result.(type) {
        case *cwe.CWEWeakness:
            fmt.Printf("  - CWE-%s: %s [%s]\n", data.ID, data.Name, data.Severity)
        case *cwe.CWECategory:
            fmt.Printf("  - CWE-%s: %s [类别]\n", data.ID, data.Name)
        }
    }
}

func createExtendedRegistry() *cwe.CWERegistry {
    registry := cwe.NewCWERegistry()
    
    testData := []*cwe.CWEWeakness{
        {ID: "79", Name: "跨站脚本", Severity: "Medium"},
        {ID: "89", Name: "SQL注入", Severity: "High"},
        {ID: "78", Name: "OS命令注入", Severity: "High"},
        {ID: "77", Name: "路径遍历", Severity: "Medium"},
        {ID: "95", Name: "代码注入", Severity: "High"},
        {ID: "352", Name: "跨站请求伪造", Severity: "Medium"},
    }
    
    for _, weakness := range testData {
        registry.AddCWE(weakness)
    }
    
    return registry
}
```

## 复合过滤条件

### 自定义过滤器

```go
package main

import (
    "fmt"
    "strings"
    
    "github.com/scagogogo/cwe"
)

type FilterCriteria struct {
    Keywords       []string
    Severity       string
    IDRange        *IDRange
    NameMinLength  int
    NameMaxLength  int
    ExcludeKeywords []string
}

type IDRange struct {
    Min, Max int
}

func advancedFilter(registry *cwe.CWERegistry, criteria FilterCriteria) []*cwe.CWEWeakness {
    var results []*cwe.CWEWeakness
    
    weaknesses := registry.GetWeaknesses()
    
    for _, weakness := range weaknesses {
        if matchesCriteria(weakness, criteria) {
            results = append(results, weakness)
        }
    }
    
    return results
}

func matchesCriteria(weakness *cwe.CWEWeakness, criteria FilterCriteria) bool {
    // 检查关键字
    if len(criteria.Keywords) > 0 {
        text := strings.ToLower(weakness.Name + " " + weakness.Description)
        for _, keyword := range criteria.Keywords {
            if !strings.Contains(text, strings.ToLower(keyword)) {
                return false
            }
        }
    }
    
    // 检查排除关键字
    if len(criteria.ExcludeKeywords) > 0 {
        text := strings.ToLower(weakness.Name + " " + weakness.Description)
        for _, keyword := range criteria.ExcludeKeywords {
            if strings.Contains(text, strings.ToLower(keyword)) {
                return false
            }
        }
    }
    
    // 检查严重程度
    if criteria.Severity != "" && weakness.Severity != criteria.Severity {
        return false
    }
    
    // 检查ID范围
    if criteria.IDRange != nil {
        id := getNumericID(weakness)
        if id < criteria.IDRange.Min || id > criteria.IDRange.Max {
            return false
        }
    }
    
    // 检查名称长度
    nameLength := len(weakness.Name)
    if criteria.NameMinLength > 0 && nameLength < criteria.NameMinLength {
        return false
    }
    if criteria.NameMaxLength > 0 && nameLength > criteria.NameMaxLength {
        return false
    }
    
    return true
}

func main() {
    registry := createExtendedRegistry()
    
    // 复合过滤条件示例
    criteria := FilterCriteria{
        Keywords:      []string{"注入"},
        Severity:      "High",
        IDRange:       &IDRange{Min: 70, Max: 100},
        NameMinLength: 3,
        NameMaxLength: 20,
    }
    
    results := advancedFilter(registry, criteria)
    
    fmt.Printf("复合过滤结果 (%d个):\n", len(results))
    fmt.Printf("条件: 包含'注入', 高严重程度, ID在70-100, 名称长度3-20字符\n\n")
    
    for _, weakness := range results {
        fmt.Printf("- CWE-%s: %s [%s]\n", weakness.ID, weakness.Name, weakness.Severity)
        fmt.Printf("  名称长度: %d字符\n", len(weakness.Name))
        fmt.Println()
    }
}
```

## 搜索结果排序

### 按相关性排序

```go
package main

import (
    "fmt"
    "sort"
    "strings"
    
    "github.com/scagogogo/cwe"
)

type SearchResult struct {
    Weakness  *cwe.CWEWeakness
    Relevance int
}

func searchWithRelevance(registry *cwe.CWERegistry, keyword string) []SearchResult {
    var results []SearchResult
    
    weaknesses := registry.GetWeaknesses()
    
    for _, weakness := range weaknesses {
        relevance := calculateRelevance(weakness, keyword)
        if relevance > 0 {
            results = append(results, SearchResult{
                Weakness:  weakness,
                Relevance: relevance,
            })
        }
    }
    
    // 按相关性排序（降序）
    sort.Slice(results, func(i, j int) bool {
        return results[i].Relevance > results[j].Relevance
    })
    
    return results
}

func calculateRelevance(weakness *cwe.CWEWeakness, keyword string) int {
    keyword = strings.ToLower(keyword)
    name := strings.ToLower(weakness.Name)
    description := strings.ToLower(weakness.Description)
    
    relevance := 0
    
    // 名称中的匹配权重更高
    if strings.Contains(name, keyword) {
        relevance += 10
        
        // 完全匹配权重最高
        if name == keyword {
            relevance += 20
        }
        
        // 开头匹配权重较高
        if strings.HasPrefix(name, keyword) {
            relevance += 15
        }
    }
    
    // 描述中的匹配
    if strings.Contains(description, keyword) {
        relevance += 5
        
        // 计算出现次数
        count := strings.Count(description, keyword)
        relevance += count * 2
    }
    
    return relevance
}

func main() {
    registry := createExtendedRegistry()
    
    keyword := "注入"
    results := searchWithRelevance(registry, keyword)
    
    fmt.Printf("搜索 '%s' 的结果（按相关性排序）:\n\n", keyword)
    
    for i, result := range results {
        fmt.Printf("%d. CWE-%s: %s [相关性: %d]\n", 
            i+1, result.Weakness.ID, result.Weakness.Name, result.Relevance)
        fmt.Printf("   严重程度: %s\n", result.Weakness.Severity)
        fmt.Printf("   描述: %s\n", result.Weakness.Description)
        fmt.Println()
    }
}
```

## 搜索统计

### 搜索结果分析

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cwe"
)

type SearchStats struct {
    TotalResults     int
    SeverityCount    map[string]int
    AverageNameLength float64
    IDRanges         map[string]int
}

func analyzeSearchResults(results []*cwe.CWEWeakness) SearchStats {
    stats := SearchStats{
        TotalResults:  len(results),
        SeverityCount: make(map[string]int),
        IDRanges:      make(map[string]int),
    }
    
    if len(results) == 0 {
        return stats
    }
    
    totalNameLength := 0
    
    for _, weakness := range results {
        // 统计严重程度
        if weakness.Severity != "" {
            stats.SeverityCount[weakness.Severity]++
        } else {
            stats.SeverityCount["Unknown"]++
        }
        
        // 计算名称长度
        totalNameLength += len(weakness.Name)
        
        // 统计ID范围
        id := getNumericID(weakness)
        switch {
        case id < 100:
            stats.IDRanges["1-99"]++
        case id < 200:
            stats.IDRanges["100-199"]++
        case id < 300:
            stats.IDRanges["200-299"]++
        case id < 400:
            stats.IDRanges["300-399"]++
        default:
            stats.IDRanges["400+"]++
        }
    }
    
    stats.AverageNameLength = float64(totalNameLength) / float64(len(results))
    
    return stats
}

func printSearchStats(keyword string, stats SearchStats) {
    fmt.Printf("搜索 '%s' 的统计信息:\n", keyword)
    fmt.Printf("总结果数: %d\n\n", stats.TotalResults)
    
    if stats.TotalResults == 0 {
        return
    }
    
    fmt.Println("严重程度分布:")
    for severity, count := range stats.SeverityCount {
        percentage := float64(count) / float64(stats.TotalResults) * 100
        fmt.Printf("  %s: %d个 (%.1f%%)\n", severity, count, percentage)
    }
    
    fmt.Printf("\n平均名称长度: %.1f字符\n", stats.AverageNameLength)
    
    fmt.Println("\nID范围分布:")
    for idRange, count := range stats.IDRanges {
        percentage := float64(count) / float64(stats.TotalResults) * 100
        fmt.Printf("  %s: %d个 (%.1f%%)\n", idRange, count, percentage)
    }
}

func main() {
    registry := createLargeRegistry()
    
    // 搜索并分析结果
    keywords := []string{"注入", "脚本", "验证"}
    
    for _, keyword := range keywords {
        results := registry.SearchByKeyword(keyword)
        
        // 转换为弱点列表
        var weaknesses []*cwe.CWEWeakness
        for _, result := range results {
            if weakness, ok := result.(*cwe.CWEWeakness); ok {
                weaknesses = append(weaknesses, weakness)
            }
        }
        
        stats := analyzeSearchResults(weaknesses)
        printSearchStats(keyword, stats)
        fmt.Println(strings.Repeat("-", 50))
    }
}

func createLargeRegistry() *cwe.CWERegistry {
    registry := cwe.NewCWERegistry()
    
    testData := []*cwe.CWEWeakness{
        {ID: "79", Name: "跨站脚本", Description: "应用程序在生成网页时未正确验证输入", Severity: "Medium"},
        {ID: "89", Name: "SQL注入", Description: "应用程序在构造SQL命令时未正确验证输入", Severity: "High"},
        {ID: "78", Name: "OS命令注入", Description: "应用程序在构造操作系统命令时未正确验证输入", Severity: "High"},
        {ID: "77", Name: "路径遍历", Description: "应用程序未正确验证文件路径", Severity: "Medium"},
        {ID: "352", Name: "跨站请求伪造", Description: "应用程序未验证请求来源", Severity: "Medium"},
        {ID: "434", Name: "文件上传", Description: "应用程序未验证上传文件", Severity: "High"},
        {ID: "20", Name: "输入验证不当", Description: "产品未正确验证输入", Severity: "Low"},
        {ID: "95", Name: "代码注入", Description: "应用程序执行未验证的代码", Severity: "Critical"},
    }
    
    for _, weakness := range testData {
        registry.AddCWE(weakness)
    }
    
    return registry
}
```

## 运行示例

保存任意示例代码为 `main.go`，然后运行：

```bash
go mod init cwe-search-example
go get github.com/scagogogo/cwe
go run main.go
```

## 最佳实践

1. **搜索优化** - 对于大量数据，考虑建立索引
2. **模糊匹配** - 实现容错的搜索算法
3. **结果排序** - 按相关性对搜索结果排序
4. **缓存结果** - 缓存常用搜索结果
5. **用户体验** - 提供搜索建议和自动完成

## 下一步

- 学习[导出和导入](./export-import)数据的方法
- 了解[速率限制客户端](./rate-limited)的高级用法
- 探索[基本用法](./basic-usage)的更多功能
