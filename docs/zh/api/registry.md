# 注册表

CWE注册表提供了一个集中的数据管理系统，用于存储、搜索和操作CWE数据集合。

## 概述

`CWERegistry` 是一个线程安全的数据容器，提供以下功能：

- CWE数据的存储和检索
- 按关键字搜索
- 数据导出和导入
- 统计和分析功能

## 创建注册表

```go
// 创建新的注册表
registry := cwe.NewCWERegistry()
```

## 基本操作

### 添加CWE数据

```go
// 添加弱点
weakness := &cwe.CWEWeakness{
    ID:          "79",
    Name:        "跨站脚本",
    Description: "应用程序在生成网页时未正确验证输入",
    Severity:    "Medium",
}
registry.AddCWE(weakness)

// 添加类别
category := &cwe.CWECategory{
    ID:          "20",
    Name:        "输入验证不当",
    Description: "产品未正确验证输入",
}
registry.AddCWE(category)

// 添加视图
view := &cwe.CWEView{
    ID:          "1000",
    Name:        "研究概念",
    Description: "用于研究的CWE视图",
}
registry.AddCWE(view)
```

### 获取CWE数据

```go
// 按ID获取
cweData := registry.GetByID("79")
if cweData != nil {
    switch data := cweData.(type) {
    case *cwe.CWEWeakness:
        fmt.Printf("弱点: %s\n", data.Name)
    case *cwe.CWECategory:
        fmt.Printf("类别: %s\n", data.Name)
    case *cwe.CWEView:
        fmt.Printf("视图: %s\n", data.Name)
    }
}
```

### 删除CWE数据

```go
// 删除指定ID的CWE
registry.RemoveByID("79")
```

## 搜索功能

### 按关键字搜索

```go
// 搜索包含"注入"的CWE
results := registry.SearchByKeyword("注入")

fmt.Printf("找到 %d 个结果:\n", len(results))
for _, result := range results {
    fmt.Printf("- CWE-%s: %s\n", result.GetID(), result.GetName())
}
```

### 按类型过滤

```go
// 获取所有弱点
weaknesses := registry.GetWeaknesses()
fmt.Printf("弱点数量: %d\n", len(weaknesses))

// 获取所有类别
categories := registry.GetCategories()
fmt.Printf("类别数量: %d\n", len(categories))

// 获取所有视图
views := registry.GetViews()
fmt.Printf("视图数量: %d\n", len(views))
```

### 高级搜索

```go
// 自定义搜索函数
func searchBySeverity(registry *cwe.CWERegistry, severity string) []*cwe.CWEWeakness {
    var results []*cwe.CWEWeakness
    
    weaknesses := registry.GetWeaknesses()
    for _, weakness := range weaknesses {
        if weakness.Severity == severity {
            results = append(results, weakness)
        }
    }
    
    return results
}

// 搜索高严重程度的弱点
highSeverityWeaknesses := searchBySeverity(registry, "High")
```

## 批量操作

### 批量添加

```go
// 从API批量添加
func populateFromAPI(registry *cwe.CWERegistry, client *cwe.APIClient, ids []string) error {
    for _, id := range ids {
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("获取CWE-%s失败: %v", id, err)
            continue
        }
        
        registry.AddCWE(weakness)
    }
    
    return nil
}

// 使用示例
ids := []string{"79", "89", "20", "22"}
err := populateFromAPI(registry, client, ids)
if err != nil {
    log.Fatal(err)
}
```

### 批量导出

```go
// 导出所有数据
allData := registry.GetAll()

// 转换为JSON
jsonData, err := json.MarshalIndent(allData, "", "  ")
if err != nil {
    log.Fatal(err)
}

// 保存到文件
err = ioutil.WriteFile("cwe_data.json", jsonData, 0644)
if err != nil {
    log.Fatal(err)
}
```

## 数据统计

### 基本统计

```go
func getRegistryStats(registry *cwe.CWERegistry) map[string]int {
    stats := make(map[string]int)
    
    stats["total"] = registry.Count()
    stats["weaknesses"] = len(registry.GetWeaknesses())
    stats["categories"] = len(registry.GetCategories())
    stats["views"] = len(registry.GetViews())
    
    return stats
}

// 使用示例
stats := getRegistryStats(registry)
fmt.Printf("统计信息: %+v\n", stats)
```

### 详细分析

```go
func analyzeWeaknesses(registry *cwe.CWERegistry) {
    weaknesses := registry.GetWeaknesses()
    
    severityCount := make(map[string]int)
    nameLength := make(map[string]int)
    
    for _, weakness := range weaknesses {
        // 按严重程度统计
        if weakness.Severity != "" {
            severityCount[weakness.Severity]++
        }
        
        // 按名称长度统计
        length := len(weakness.Name)
        switch {
        case length < 20:
            nameLength["短"]++
        case length < 50:
            nameLength["中"]++
        default:
            nameLength["长"]++
        }
    }
    
    fmt.Println("严重程度分布:")
    for severity, count := range severityCount {
        fmt.Printf("  %s: %d\n", severity, count)
    }
    
    fmt.Println("名称长度分布:")
    for category, count := range nameLength {
        fmt.Printf("  %s: %d\n", category, count)
    }
}
```

## 数据持久化

### 保存到文件

```go
func saveRegistry(registry *cwe.CWERegistry, filename string) error {
    data := registry.GetAll()
    
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return err
    }
    
    return ioutil.WriteFile(filename, jsonData, 0644)
}
```

### 从文件加载

```go
func loadRegistry(filename string) (*cwe.CWERegistry, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    
    var items []interface{}
    err = json.Unmarshal(data, &items)
    if err != nil {
        return nil, err
    }
    
    registry := cwe.NewCWERegistry()
    
    for _, item := range items {
        // 根据数据类型添加到注册表
        // 这里需要根据实际的数据结构进行类型判断和转换
        registry.AddCWE(item)
    }
    
    return registry, nil
}
```

## 并发安全

注册表是线程安全的，可以在多个goroutine中安全使用：

```go
var wg sync.WaitGroup

// 并发添加数据
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        
        weakness := &cwe.CWEWeakness{
            ID:   fmt.Sprintf("%d", id),
            Name: fmt.Sprintf("测试弱点 %d", id),
        }
        
        registry.AddCWE(weakness)
    }(i)
}

wg.Wait()

fmt.Printf("注册表中共有 %d 个条目\n", registry.Count())
```

## 事件监听

### 添加监听器

```go
// 定义事件监听器
type RegistryListener struct{}

func (l *RegistryListener) OnAdd(cweData interface{}) {
    switch data := cweData.(type) {
    case *cwe.CWEWeakness:
        fmt.Printf("添加了弱点: CWE-%s\n", data.ID)
    case *cwe.CWECategory:
        fmt.Printf("添加了类别: CWE-%s\n", data.ID)
    case *cwe.CWEView:
        fmt.Printf("添加了视图: CWE-%s\n", data.ID)
    }
}

func (l *RegistryListener) OnRemove(id string) {
    fmt.Printf("删除了CWE-%s\n", id)
}

// 注册监听器
listener := &RegistryListener{}
registry.AddListener(listener)
```

## 最佳实践

1. **数据验证** - 添加数据前进行验证
2. **定期备份** - 定期保存注册表数据
3. **内存管理** - 监控注册表大小，避免内存泄漏
4. **搜索优化** - 对于大量数据，考虑使用索引
5. **并发控制** - 在高并发场景下注意性能

## 下一步

- 了解[搜索和工具](./search-utils)的高级功能
- 学习[树操作](./tree)的层次结构处理
- 查看[示例](/zh/examples/)中的实际应用
