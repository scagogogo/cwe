# 搜索和工具

搜索和工具模块提供了强大的CWE数据搜索、过滤和实用功能。

## 概述

搜索和工具功能包括：

- 关键字搜索
- 高级过滤
- 数据验证
- 格式转换
- 实用工具函数

## 搜索功能

### 基本关键字搜索

```go
// 在注册表中搜索
registry := cwe.NewCWERegistry()

// 添加一些测试数据
registry.AddCWE(&cwe.CWEWeakness{
    ID:   "79",
    Name: "跨站脚本",
    Description: "应用程序在生成网页时未正确验证输入",
})

registry.AddCWE(&cwe.CWEWeakness{
    ID:   "89",
    Name: "SQL注入",
    Description: "应用程序在构造SQL命令时未正确验证输入",
})

// 搜索包含"注入"的CWE
results := registry.SearchByKeyword("注入")
fmt.Printf("找到 %d 个结果\n", len(results))
```

### 高级搜索

```go
// 自定义搜索函数
func advancedSearch(registry *cwe.CWERegistry, criteria SearchCriteria) []interface{} {
    var results []interface{}
    
    allData := registry.GetAll()
    
    for _, item := range allData {
        if matchesCriteria(item, criteria) {
            results = append(results, item)
        }
    }
    
    return results
}

type SearchCriteria struct {
    Keywords    []string
    Severity    string
    Type        string // "weakness", "category", "view"
    IDRange     *IDRange
    NameLength  *LengthRange
}

type IDRange struct {
    Min, Max int
}

type LengthRange struct {
    Min, Max int
}

func matchesCriteria(item interface{}, criteria SearchCriteria) bool {
    // 类型过滤
    if criteria.Type != "" {
        switch criteria.Type {
        case "weakness":
            if _, ok := item.(*cwe.CWEWeakness); !ok {
                return false
            }
        case "category":
            if _, ok := item.(*cwe.CWECategory); !ok {
                return false
            }
        case "view":
            if _, ok := item.(*cwe.CWEView); !ok {
                return false
            }
        }
    }
    
    // 关键字匹配
    if len(criteria.Keywords) > 0 {
        text := getSearchableText(item)
        for _, keyword := range criteria.Keywords {
            if !strings.Contains(strings.ToLower(text), strings.ToLower(keyword)) {
                return false
            }
        }
    }
    
    // 严重程度过滤（仅适用于弱点）
    if criteria.Severity != "" {
        if weakness, ok := item.(*cwe.CWEWeakness); ok {
            if weakness.Severity != criteria.Severity {
                return false
            }
        }
    }
    
    return true
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
```

## 过滤功能

### 按类型过滤

```go
func filterByType(registry *cwe.CWERegistry, cweType string) []interface{} {
    switch cweType {
    case "weakness":
        weaknesses := registry.GetWeaknesses()
        result := make([]interface{}, len(weaknesses))
        for i, w := range weaknesses {
            result[i] = w
        }
        return result
        
    case "category":
        categories := registry.GetCategories()
        result := make([]interface{}, len(categories))
        for i, c := range categories {
            result[i] = c
        }
        return result
        
    case "view":
        views := registry.GetViews()
        result := make([]interface{}, len(views))
        for i, v := range views {
            result[i] = v
        }
        return result
        
    default:
        return registry.GetAll()
    }
}
```

### 按严重程度过滤

```go
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

// 使用示例
highSeverityWeaknesses := filterBySeverity(registry, "High")
mediumSeverityWeaknesses := filterBySeverity(registry, "Medium")
lowSeverityWeaknesses := filterBySeverity(registry, "Low")
```

### 按ID范围过滤

```go
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
```

## 数据验证

### CWE数据验证

```go
func validateCWEWeakness(weakness *cwe.CWEWeakness) []string {
    var errors []string
    
    if weakness.ID == "" {
        errors = append(errors, "ID不能为空")
    }
    
    if weakness.Name == "" {
        errors = append(errors, "名称不能为空")
    }
    
    if len(weakness.Name) > 200 {
        errors = append(errors, "名称过长（超过200字符）")
    }
    
    if weakness.Description == "" {
        errors = append(errors, "描述不能为空")
    }
    
    if weakness.Severity != "" {
        validSeverities := []string{"Low", "Medium", "High", "Critical"}
        if !contains(validSeverities, weakness.Severity) {
            errors = append(errors, "无效的严重程度")
        }
    }
    
    return errors
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
```

### 批量验证

```go
func validateRegistry(registry *cwe.CWERegistry) map[string][]string {
    validationErrors := make(map[string][]string)
    
    // 验证弱点
    weaknesses := registry.GetWeaknesses()
    for _, weakness := range weaknesses {
        errors := validateCWEWeakness(weakness)
        if len(errors) > 0 {
            validationErrors["CWE-"+weakness.ID] = errors
        }
    }
    
    // 验证类别
    categories := registry.GetCategories()
    for _, category := range categories {
        errors := validateCWECategory(category)
        if len(errors) > 0 {
            validationErrors["Category-"+category.ID] = errors
        }
    }
    
    return validationErrors
}

func validateCWECategory(category *cwe.CWECategory) []string {
    var errors []string
    
    if category.ID == "" {
        errors = append(errors, "ID不能为空")
    }
    
    if category.Name == "" {
        errors = append(errors, "名称不能为空")
    }
    
    return errors
}
```

## 格式转换

### ID格式化

```go
func normalizeID(id string) string {
    // 移除CWE-前缀
    id = strings.TrimPrefix(strings.ToUpper(id), "CWE-")
    
    // 移除前导零
    id = strings.TrimLeft(id, "0")
    
    // 如果为空，返回"0"
    if id == "" {
        return "0"
    }
    
    return id
}

func formatID(id string) string {
    normalized := normalizeID(id)
    return "CWE-" + normalized
}

// 使用示例
fmt.Println(formatID("79"))      // CWE-79
fmt.Println(formatID("CWE-89"))  // CWE-89
fmt.Println(formatID("0020"))    // CWE-20
```

### 文本格式化

```go
func formatDescription(description string, maxLength int) string {
    if len(description) <= maxLength {
        return description
    }
    
    // 截断并添加省略号
    return description[:maxLength-3] + "..."
}

func formatName(name string) string {
    // 首字母大写
    if len(name) == 0 {
        return name
    }
    
    return strings.ToUpper(string(name[0])) + strings.ToLower(name[1:])
}
```

## 统计工具

### 数据统计

```go
func generateStatistics(registry *cwe.CWERegistry) map[string]interface{} {
    stats := make(map[string]interface{})
    
    // 基本计数
    stats["total_count"] = registry.Count()
    stats["weakness_count"] = len(registry.GetWeaknesses())
    stats["category_count"] = len(registry.GetCategories())
    stats["view_count"] = len(registry.GetViews())
    
    // 严重程度分布
    severityDist := make(map[string]int)
    weaknesses := registry.GetWeaknesses()
    for _, weakness := range weaknesses {
        if weakness.Severity != "" {
            severityDist[weakness.Severity]++
        } else {
            severityDist["Unknown"]++
        }
    }
    stats["severity_distribution"] = severityDist
    
    // 名称长度统计
    nameLengths := make([]int, 0, len(weaknesses))
    for _, weakness := range weaknesses {
        nameLengths = append(nameLengths, len(weakness.Name))
    }
    
    if len(nameLengths) > 0 {
        sort.Ints(nameLengths)
        stats["name_length_min"] = nameLengths[0]
        stats["name_length_max"] = nameLengths[len(nameLengths)-1]
        stats["name_length_avg"] = average(nameLengths)
        stats["name_length_median"] = median(nameLengths)
    }
    
    return stats
}

func average(numbers []int) float64 {
    if len(numbers) == 0 {
        return 0
    }
    
    sum := 0
    for _, num := range numbers {
        sum += num
    }
    
    return float64(sum) / float64(len(numbers))
}

func median(numbers []int) float64 {
    if len(numbers) == 0 {
        return 0
    }
    
    mid := len(numbers) / 2
    if len(numbers)%2 == 0 {
        return float64(numbers[mid-1]+numbers[mid]) / 2
    }
    
    return float64(numbers[mid])
}
```

## 导出工具

### 导出为不同格式

```go
func exportToCSV(registry *cwe.CWERegistry, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    writer := csv.NewWriter(file)
    defer writer.Flush()
    
    // 写入标题行
    headers := []string{"ID", "Type", "Name", "Description", "Severity"}
    if err := writer.Write(headers); err != nil {
        return err
    }
    
    // 写入数据
    allData := registry.GetAll()
    for _, item := range allData {
        record := formatForCSV(item)
        if err := writer.Write(record); err != nil {
            return err
        }
    }
    
    return nil
}

func formatForCSV(item interface{}) []string {
    switch data := item.(type) {
    case *cwe.CWEWeakness:
        return []string{
            data.ID,
            "Weakness",
            data.Name,
            data.Description,
            data.Severity,
        }
    case *cwe.CWECategory:
        return []string{
            data.ID,
            "Category",
            data.Name,
            data.Description,
            "",
        }
    case *cwe.CWEView:
        return []string{
            data.ID,
            "View",
            data.Name,
            data.Description,
            "",
        }
    default:
        return []string{"", "", "", "", ""}
    }
}
```

## 最佳实践

1. **搜索优化** - 对于大量数据，考虑使用索引
2. **数据验证** - 在处理数据前进行验证
3. **错误处理** - 处理搜索和过滤中的错误
4. **性能考虑** - 对于复杂搜索，考虑并发处理
5. **用户体验** - 提供搜索进度和结果统计

## 下一步

- 了解[树操作](./tree)的层次结构处理
- 学习[注册表](./registry)的数据管理
- 查看[示例](/zh/examples/)中的实际应用
