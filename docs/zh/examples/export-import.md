# 导出和导入

本示例展示如何导出和导入CWE数据，支持多种格式包括JSON、XML和CSV。

## JSON格式导出导入

### 导出为JSON

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    
    "github.com/scagogogo/cwe"
)

func exportToJSON(registry *cwe.CWERegistry, filename string) error {
    // 获取所有数据
    allData := registry.GetAll()
    
    // 转换为JSON
    jsonData, err := json.MarshalIndent(allData, "", "  ")
    if err != nil {
        return fmt.Errorf("JSON序列化失败: %v", err)
    }
    
    // 写入文件
    err = ioutil.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("写入文件失败: %v", err)
    }
    
    return nil
}

func main() {
    // 创建示例数据
    registry := createSampleRegistry()
    
    // 导出为JSON
    filename := "cwe_data.json"
    err := exportToJSON(registry, filename)
    if err != nil {
        log.Fatalf("导出失败: %v", err)
    }
    
    fmt.Printf("数据已导出到 %s\n", filename)
    
    // 显示文件大小
    fileInfo, err := ioutil.ReadFile(filename)
    if err == nil {
        fmt.Printf("文件大小: %d 字节\n", len(fileInfo))
    }
}

func createSampleRegistry() *cwe.CWERegistry {
    registry := cwe.NewCWERegistry()
    
    // 添加弱点
    weaknesses := []*cwe.CWEWeakness{
        {
            ID:          "79",
            Name:        "跨站脚本",
            Description: "应用程序在生成网页时未正确验证输入",
            Severity:    "Medium",
            URL:         "https://cwe.mitre.org/data/definitions/79.html",
        },
        {
            ID:          "89",
            Name:        "SQL注入",
            Description: "应用程序在构造SQL命令时未正确验证输入",
            Severity:    "High",
            URL:         "https://cwe.mitre.org/data/definitions/89.html",
        },
    }
    
    for _, weakness := range weaknesses {
        registry.AddCWE(weakness)
    }
    
    // 添加类别
    categories := []*cwe.CWECategory{
        {
            ID:          "20",
            Name:        "输入验证不当",
            Description: "产品未正确验证输入",
            URL:         "https://cwe.mitre.org/data/definitions/20.html",
        },
    }
    
    for _, category := range categories {
        registry.AddCWE(category)
    }
    
    return registry
}
```

### 从JSON导入

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    
    "github.com/scagogogo/cwe"
)

func importFromJSON(filename string) (*cwe.CWERegistry, error) {
    // 读取文件
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("读取文件失败: %v", err)
    }
    
    // 解析JSON
    var items []map[string]interface{}
    err = json.Unmarshal(data, &items)
    if err != nil {
        return nil, fmt.Errorf("JSON解析失败: %v", err)
    }
    
    // 创建注册表
    registry := cwe.NewCWERegistry()
    
    // 处理每个项目
    for _, item := range items {
        cweData, err := convertMapToCWE(item)
        if err != nil {
            log.Printf("转换数据失败: %v", err)
            continue
        }
        
        registry.AddCWE(cweData)
    }
    
    return registry, nil
}

func convertMapToCWE(item map[string]interface{}) (interface{}, error) {
    // 根据数据结构判断类型
    if severity, exists := item["severity"]; exists && severity != nil {
        // 这是一个弱点
        weakness := &cwe.CWEWeakness{}
        
        if id, ok := item["id"].(string); ok {
            weakness.ID = id
        }
        if name, ok := item["name"].(string); ok {
            weakness.Name = name
        }
        if desc, ok := item["description"].(string); ok {
            weakness.Description = desc
        }
        if sev, ok := item["severity"].(string); ok {
            weakness.Severity = sev
        }
        if url, ok := item["url"].(string); ok {
            weakness.URL = url
        }
        
        return weakness, nil
    } else {
        // 这可能是类别或视图
        category := &cwe.CWECategory{}
        
        if id, ok := item["id"].(string); ok {
            category.ID = id
        }
        if name, ok := item["name"].(string); ok {
            category.Name = name
        }
        if desc, ok := item["description"].(string); ok {
            category.Description = desc
        }
        if url, ok := item["url"].(string); ok {
            category.URL = url
        }
        
        return category, nil
    }
}

func main() {
    filename := "cwe_data.json"
    
    // 从JSON导入
    registry, err := importFromJSON(filename)
    if err != nil {
        log.Fatalf("导入失败: %v", err)
    }
    
    fmt.Printf("成功导入数据\n")
    
    // 显示统计信息
    fmt.Printf("总条目数: %d\n", registry.Count())
    fmt.Printf("弱点数: %d\n", len(registry.GetWeaknesses()))
    fmt.Printf("类别数: %d\n", len(registry.GetCategories()))
    
    // 显示导入的数据
    fmt.Println("\n导入的弱点:")
    for _, weakness := range registry.GetWeaknesses() {
        fmt.Printf("- CWE-%s: %s [%s]\n", weakness.ID, weakness.Name, weakness.Severity)
    }
    
    fmt.Println("\n导入的类别:")
    for _, category := range registry.GetCategories() {
        fmt.Printf("- CWE-%s: %s\n", category.ID, category.Name)
    }
}
```

## CSV格式导出导入

### 导出为CSV

```go
package main

import (
    "encoding/csv"
    "fmt"
    "os"
    
    "github.com/scagogogo/cwe"
)

func exportToCSV(registry *cwe.CWERegistry, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    writer := csv.NewWriter(file)
    defer writer.Flush()
    
    // 写入标题行
    headers := []string{"ID", "Type", "Name", "Description", "Severity", "URL"}
    if err := writer.Write(headers); err != nil {
        return err
    }
    
    // 写入弱点数据
    for _, weakness := range registry.GetWeaknesses() {
        record := []string{
            weakness.ID,
            "Weakness",
            weakness.Name,
            weakness.Description,
            weakness.Severity,
            weakness.URL,
        }
        if err := writer.Write(record); err != nil {
            return err
        }
    }
    
    // 写入类别数据
    for _, category := range registry.GetCategories() {
        record := []string{
            category.ID,
            "Category",
            category.Name,
            category.Description,
            "",
            category.URL,
        }
        if err := writer.Write(record); err != nil {
            return err
        }
    }
    
    return nil
}

func main() {
    registry := createSampleRegistry()
    
    filename := "cwe_data.csv"
    err := exportToCSV(registry, filename)
    if err != nil {
        log.Fatalf("导出CSV失败: %v", err)
    }
    
    fmt.Printf("数据已导出到 %s\n", filename)
}
```

### 从CSV导入

```go
package main

import (
    "encoding/csv"
    "fmt"
    "io"
    "log"
    "os"
    
    "github.com/scagogogo/cwe"
)

func importFromCSV(filename string) (*cwe.CWERegistry, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    reader := csv.NewReader(file)
    registry := cwe.NewCWERegistry()
    
    // 跳过标题行
    _, err = reader.Read()
    if err != nil {
        return nil, err
    }
    
    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }
        
        if len(record) < 6 {
            continue
        }
        
        id := record[0]
        cweType := record[1]
        name := record[2]
        description := record[3]
        severity := record[4]
        url := record[5]
        
        switch cweType {
        case "Weakness":
            weakness := &cwe.CWEWeakness{
                ID:          id,
                Name:        name,
                Description: description,
                Severity:    severity,
                URL:         url,
            }
            registry.AddCWE(weakness)
            
        case "Category":
            category := &cwe.CWECategory{
                ID:          id,
                Name:        name,
                Description: description,
                URL:         url,
            }
            registry.AddCWE(category)
        }
    }
    
    return registry, nil
}

func main() {
    filename := "cwe_data.csv"
    
    registry, err := importFromCSV(filename)
    if err != nil {
        log.Fatalf("导入CSV失败: %v", err)
    }
    
    fmt.Printf("从CSV成功导入 %d 个条目\n", registry.Count())
    
    // 显示导入的数据
    fmt.Println("\n弱点:")
    for _, weakness := range registry.GetWeaknesses() {
        fmt.Printf("- CWE-%s: %s\n", weakness.ID, weakness.Name)
    }
    
    fmt.Println("\n类别:")
    for _, category := range registry.GetCategories() {
        fmt.Printf("- CWE-%s: %s\n", category.ID, category.Name)
    }
}
```

## XML格式导出导入

### 导出为XML

```go
package main

import (
    "encoding/xml"
    "fmt"
    "io/ioutil"
    "log"
    
    "github.com/scagogogo/cwe"
)

type CWEData struct {
    XMLName    xml.Name             `xml:"cwe_data"`
    Weaknesses []*cwe.CWEWeakness   `xml:"weaknesses>weakness"`
    Categories []*cwe.CWECategory   `xml:"categories>category"`
    Views      []*cwe.CWEView       `xml:"views>view"`
}

func exportToXML(registry *cwe.CWERegistry, filename string) error {
    data := CWEData{
        Weaknesses: registry.GetWeaknesses(),
        Categories: registry.GetCategories(),
        Views:      registry.GetViews(),
    }
    
    xmlData, err := xml.MarshalIndent(data, "", "  ")
    if err != nil {
        return fmt.Errorf("XML序列化失败: %v", err)
    }
    
    // 添加XML声明
    xmlContent := []byte(xml.Header + string(xmlData))
    
    err = ioutil.WriteFile(filename, xmlContent, 0644)
    if err != nil {
        return fmt.Errorf("写入文件失败: %v", err)
    }
    
    return nil
}

func main() {
    registry := createSampleRegistry()
    
    filename := "cwe_data.xml"
    err := exportToXML(registry, filename)
    if err != nil {
        log.Fatalf("导出XML失败: %v", err)
    }
    
    fmt.Printf("数据已导出到 %s\n", filename)
}
```

### 从XML导入

```go
package main

import (
    "encoding/xml"
    "fmt"
    "io/ioutil"
    "log"
    
    "github.com/scagogogo/cwe"
)

func importFromXML(filename string) (*cwe.CWERegistry, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("读取文件失败: %v", err)
    }
    
    var cweData CWEData
    err = xml.Unmarshal(data, &cweData)
    if err != nil {
        return nil, fmt.Errorf("XML解析失败: %v", err)
    }
    
    registry := cwe.NewCWERegistry()
    
    // 添加弱点
    for _, weakness := range cweData.Weaknesses {
        registry.AddCWE(weakness)
    }
    
    // 添加类别
    for _, category := range cweData.Categories {
        registry.AddCWE(category)
    }
    
    // 添加视图
    for _, view := range cweData.Views {
        registry.AddCWE(view)
    }
    
    return registry, nil
}

func main() {
    filename := "cwe_data.xml"
    
    registry, err := importFromXML(filename)
    if err != nil {
        log.Fatalf("导入XML失败: %v", err)
    }
    
    fmt.Printf("从XML成功导入数据\n")
    fmt.Printf("弱点: %d个\n", len(registry.GetWeaknesses()))
    fmt.Printf("类别: %d个\n", len(registry.GetCategories()))
    fmt.Printf("视图: %d个\n", len(registry.GetViews()))
}
```

## 批量导出导入

### 从API批量导出

```go
package main

import (
    "fmt"
    "log"
    "sync"
    
    "github.com/scagogogo/cwe"
)

func batchExportFromAPI(client *cwe.APIClient, ids []string, filename string) error {
    registry := cwe.NewCWERegistry()
    
    var wg sync.WaitGroup
    var mu sync.Mutex
    
    fmt.Printf("正在从API获取 %d 个CWE...\n", len(ids))
    
    // 并发获取数据
    for _, id := range ids {
        wg.Add(1)
        
        go func(cweID string) {
            defer wg.Done()
            
            weakness, err := client.GetWeakness(cweID)
            if err != nil {
                log.Printf("获取CWE-%s失败: %v", cweID, err)
                return
            }
            
            mu.Lock()
            registry.AddCWE(weakness)
            mu.Unlock()
            
            fmt.Printf("✓ 获取CWE-%s完成\n", cweID)
        }(id)
    }
    
    wg.Wait()
    
    // 导出为JSON
    err := exportToJSON(registry, filename)
    if err != nil {
        return fmt.Errorf("导出失败: %v", err)
    }
    
    fmt.Printf("成功导出 %d 个CWE到 %s\n", registry.Count(), filename)
    return nil
}

func main() {
    client := cwe.NewAPIClient()
    
    // 要导出的CWE ID列表
    ids := []string{"79", "89", "78", "77", "352", "434", "502", "20", "22"}
    
    err := batchExportFromAPI(client, ids, "batch_export.json")
    if err != nil {
        log.Fatalf("批量导出失败: %v", err)
    }
}
```

## 数据验证和清理

### 导入时验证数据

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

type ValidationResult struct {
    Valid   bool
    Errors  []string
    Warnings []string
}

func validateCWEData(data interface{}) ValidationResult {
    result := ValidationResult{Valid: true}
    
    switch cweData := data.(type) {
    case *cwe.CWEWeakness:
        if cweData.ID == "" {
            result.Errors = append(result.Errors, "ID不能为空")
            result.Valid = false
        }
        
        if cweData.Name == "" {
            result.Errors = append(result.Errors, "名称不能为空")
            result.Valid = false
        }
        
        if len(cweData.Name) > 200 {
            result.Warnings = append(result.Warnings, "名称过长")
        }
        
        if cweData.Description == "" {
            result.Warnings = append(result.Warnings, "描述为空")
        }
        
        validSeverities := []string{"Low", "Medium", "High", "Critical"}
        if cweData.Severity != "" && !contains(validSeverities, cweData.Severity) {
            result.Warnings = append(result.Warnings, "无效的严重程度")
        }
        
    case *cwe.CWECategory:
        if cweData.ID == "" {
            result.Errors = append(result.Errors, "ID不能为空")
            result.Valid = false
        }
        
        if cweData.Name == "" {
            result.Errors = append(result.Errors, "名称不能为空")
            result.Valid = false
        }
    }
    
    return result
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func importWithValidation(filename string) (*cwe.CWERegistry, error) {
    registry, err := importFromJSON(filename)
    if err != nil {
        return nil, err
    }
    
    validCount := 0
    errorCount := 0
    warningCount := 0
    
    // 验证所有数据
    allData := registry.GetAll()
    for _, item := range allData {
        result := validateCWEData(item)
        
        if result.Valid {
            validCount++
        } else {
            errorCount++
            fmt.Printf("❌ 验证失败: %v\n", result.Errors)
        }
        
        if len(result.Warnings) > 0 {
            warningCount++
            fmt.Printf("⚠️  警告: %v\n", result.Warnings)
        }
    }
    
    fmt.Printf("\n验证结果:\n")
    fmt.Printf("  有效: %d个\n", validCount)
    fmt.Printf("  错误: %d个\n", errorCount)
    fmt.Printf("  警告: %d个\n", warningCount)
    
    return registry, nil
}

func main() {
    filename := "cwe_data.json"
    
    registry, err := importWithValidation(filename)
    if err != nil {
        log.Fatalf("导入失败: %v", err)
    }
    
    fmt.Printf("导入完成，共 %d 个条目\n", registry.Count())
}
```

## 运行示例

保存任意示例代码为 `main.go`，然后运行：

```bash
go mod init cwe-export-example
go get github.com/scagogogo/cwe
go run main.go
```

## 最佳实践

1. **数据验证** - 导入时验证数据完整性
2. **错误处理** - 处理文件读写错误
3. **格式选择** - 根据需求选择合适的格式
4. **备份数据** - 导出前备份原始数据
5. **版本控制** - 为导出的数据添加版本信息

## 下一步

- 学习[速率限制客户端](./rate-limited)的高级用法
- 了解[基本用法](./basic-usage)的更多功能
- 探索[构建树](./build-tree)的层次结构处理
