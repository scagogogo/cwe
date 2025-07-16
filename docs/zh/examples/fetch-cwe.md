# 获取CWE数据

本示例展示如何从CWE API获取各种类型的数据，包括弱点、类别和视图。

## 基本数据获取

### 获取单个弱点

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建API客户端
    client := cwe.NewAPIClient()
    
    // 获取CWE-79（跨站脚本）
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("获取弱点失败: %v", err)
    }
    
    fmt.Printf("弱点信息:\n")
    fmt.Printf("  ID: CWE-%s\n", weakness.ID)
    fmt.Printf("  名称: %s\n", weakness.Name)
    fmt.Printf("  描述: %s\n", weakness.Description)
    
    if weakness.Severity != "" {
        fmt.Printf("  严重程度: %s\n", weakness.Severity)
    }
    
    if weakness.URL != "" {
        fmt.Printf("  详细信息: %s\n", weakness.URL)
    }
}
```

### 获取类别信息

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 获取CWE-20（输入验证不当）类别
    category, err := client.GetCategory("20")
    if err != nil {
        log.Fatalf("获取类别失败: %v", err)
    }
    
    fmt.Printf("类别信息:\n")
    fmt.Printf("  ID: CWE-%s\n", category.ID)
    fmt.Printf("  名称: %s\n", category.Name)
    fmt.Printf("  描述: %s\n", category.Description)
    
    if category.URL != "" {
        fmt.Printf("  详细信息: %s\n", category.URL)
    }
}
```

### 获取视图信息

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 获取CWE-1000（研究概念）视图
    view, err := client.GetView("1000")
    if err != nil {
        log.Fatalf("获取视图失败: %v", err)
    }
    
    fmt.Printf("视图信息:\n")
    fmt.Printf("  ID: CWE-%s\n", view.ID)
    fmt.Printf("  名称: %s\n", view.Name)
    fmt.Printf("  描述: %s\n", view.Description)
    
    if view.URL != "" {
        fmt.Printf("  详细信息: %s\n", view.URL)
    }
}
```

## 批量数据获取

### 获取多个弱点

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 定义要获取的CWE ID列表
    ids := []string{"79", "89", "20", "22", "78"}
    
    fmt.Printf("正在获取 %d 个CWE...\n", len(ids))
    
    // 批量获取
    cwes, err := client.GetCWEs(ids)
    if err != nil {
        log.Fatalf("批量获取失败: %v", err)
    }
    
    fmt.Printf("成功获取 %d 个CWE:\n\n", len(cwes))
    
    for id, weakness := range cwes {
        fmt.Printf("CWE-%s: %s\n", id, weakness.Name)
        if weakness.Severity != "" {
            fmt.Printf("  严重程度: %s\n", weakness.Severity)
        }
        fmt.Printf("  描述: %s\n", weakness.Description[:100] + "...")
        fmt.Println()
    }
}
```

### 并发获取

```go
package main

import (
    "fmt"
    "log"
    "sync"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 要获取的CWE ID列表
    ids := []string{"79", "89", "20", "22", "78", "77", "352", "434", "502"}
    
    // 结果存储
    results := make(map[string]*cwe.CWEWeakness)
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    fmt.Printf("并发获取 %d 个CWE...\n", len(ids))
    
    // 并发获取每个CWE
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
            results[cweID] = weakness
            mu.Unlock()
            
            fmt.Printf("✓ 获取CWE-%s完成\n", cweID)
        }(id)
    }
    
    // 等待所有goroutine完成
    wg.Wait()
    
    fmt.Printf("\n成功获取 %d 个CWE:\n", len(results))
    for id, weakness := range results {
        fmt.Printf("- CWE-%s: %s\n", id, weakness.Name)
    }
}
```

## 高级获取技术

### 带重试的获取

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/scagogogo/cwe"
)

func fetchWithRetry(client *cwe.APIClient, id string, maxRetries int) (*cwe.CWEWeakness, error) {
    var lastErr error
    
    for i := 0; i <= maxRetries; i++ {
        weakness, err := client.GetWeakness(id)
        if err == nil {
            return weakness, nil
        }
        
        lastErr = err
        
        if i < maxRetries {
            waitTime := time.Duration(i+1) * time.Second
            fmt.Printf("获取CWE-%s失败，%v后重试... (第%d次)\n", id, waitTime, i+1)
            time.Sleep(waitTime)
        }
    }
    
    return nil, fmt.Errorf("重试%d次后仍然失败: %v", maxRetries, lastErr)
}

func main() {
    client := cwe.NewAPIClient()
    
    // 使用重试机制获取CWE
    weakness, err := fetchWithRetry(client, "79", 3)
    if err != nil {
        log.Fatalf("获取失败: %v", err)
    }
    
    fmt.Printf("成功获取: CWE-%s - %s\n", weakness.ID, weakness.Name)
}
```

### 缓存获取结果

```go
package main

import (
    "fmt"
    "log"
    "sync"
    "time"
    
    "github.com/scagogogo/cwe"
)

type CachedClient struct {
    client *cwe.APIClient
    cache  map[string]*cacheItem
    mu     sync.RWMutex
}

type cacheItem struct {
    weakness  *cwe.CWEWeakness
    timestamp time.Time
}

func NewCachedClient(client *cwe.APIClient) *CachedClient {
    return &CachedClient{
        client: client,
        cache:  make(map[string]*cacheItem),
    }
}

func (c *CachedClient) GetWeakness(id string) (*cwe.CWEWeakness, error) {
    // 检查缓存
    c.mu.RLock()
    if item, exists := c.cache[id]; exists {
        // 检查是否过期（5分钟）
        if time.Since(item.timestamp) < 5*time.Minute {
            c.mu.RUnlock()
            fmt.Printf("从缓存获取CWE-%s\n", id)
            return item.weakness, nil
        }
    }
    c.mu.RUnlock()
    
    // 从API获取
    fmt.Printf("从API获取CWE-%s\n", id)
    weakness, err := c.client.GetWeakness(id)
    if err != nil {
        return nil, err
    }
    
    // 存入缓存
    c.mu.Lock()
    c.cache[id] = &cacheItem{
        weakness:  weakness,
        timestamp: time.Now(),
    }
    c.mu.Unlock()
    
    return weakness, nil
}

func main() {
    client := cwe.NewAPIClient()
    cachedClient := NewCachedClient(client)
    
    // 第一次获取（从API）
    weakness1, err := cachedClient.GetWeakness("79")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("第一次: CWE-%s - %s\n", weakness1.ID, weakness1.Name)
    
    // 第二次获取（从缓存）
    weakness2, err := cachedClient.GetWeakness("79")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("第二次: CWE-%s - %s\n", weakness2.ID, weakness2.Name)
}
```

## 数据验证和处理

### 验证获取的数据

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func validateWeakness(weakness *cwe.CWEWeakness) []string {
    var issues []string
    
    if weakness.ID == "" {
        issues = append(issues, "ID为空")
    }
    
    if weakness.Name == "" {
        issues = append(issues, "名称为空")
    }
    
    if weakness.Description == "" {
        issues = append(issues, "描述为空")
    }
    
    if len(weakness.Name) > 200 {
        issues = append(issues, "名称过长")
    }
    
    return issues
}

func main() {
    client := cwe.NewAPIClient()
    
    ids := []string{"79", "89", "20"}
    
    for _, id := range ids {
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("获取CWE-%s失败: %v", id, err)
            continue
        }
        
        // 验证数据
        issues := validateWeakness(weakness)
        if len(issues) > 0 {
            fmt.Printf("CWE-%s 数据问题:\n", id)
            for _, issue := range issues {
                fmt.Printf("  - %s\n", issue)
            }
        } else {
            fmt.Printf("✓ CWE-%s 数据完整\n", id)
        }
    }
}
```

### 数据转换和格式化

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "strings"
    
    "github.com/scagogogo/cwe"
)

type FormattedCWE struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description"`
    Severity    string `json:"severity,omitempty"`
    Summary     string `json:"summary"`
}

func formatCWE(weakness *cwe.CWEWeakness) *FormattedCWE {
    // 生成摘要（描述的前100个字符）
    summary := weakness.Description
    if len(summary) > 100 {
        summary = summary[:100] + "..."
    }
    
    return &FormattedCWE{
        ID:          "CWE-" + weakness.ID,
        Name:        strings.Title(weakness.Name),
        Description: weakness.Description,
        Severity:    weakness.Severity,
        Summary:     summary,
    }
}

func main() {
    client := cwe.NewAPIClient()
    
    // 获取并格式化多个CWE
    ids := []string{"79", "89", "20"}
    var formattedCWEs []*FormattedCWE
    
    for _, id := range ids {
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("获取CWE-%s失败: %v", id, err)
            continue
        }
        
        formatted := formatCWE(weakness)
        formattedCWEs = append(formattedCWEs, formatted)
    }
    
    // 输出为JSON
    jsonData, err := json.MarshalIndent(formattedCWEs, "", "  ")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("格式化的CWE数据:")
    fmt.Println(string(jsonData))
}
```

## 运行示例

保存任意示例代码为 `main.go`，然后运行：

```bash
go mod init cwe-fetch-example
go get github.com/scagogogo/cwe
go run main.go
```

## 注意事项

1. **速率限制** - 注意API的速率限制，避免请求过于频繁
2. **错误处理** - 始终检查和处理错误
3. **网络连接** - 确保有稳定的网络连接
4. **数据验证** - 验证从API获取的数据完整性
5. **缓存策略** - 对于频繁访问的数据，考虑使用缓存

## 下一步

- 学习[构建树](./build-tree)来处理CWE层次结构
- 了解[搜索和过滤](./search-filter)功能
- 探索[导出和导入](./export-import)数据的方法
