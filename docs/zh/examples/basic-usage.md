# 基本用法

本示例展示了CWE Go库的基本用法，包括安装、初始化和执行常见操作。

## 安装

首先安装CWE Go库：

```bash
go get github.com/scagogogo/cwe
```

## 基本示例

### 1. 获取CWE版本信息

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建新的API客户端
    client := cwe.NewAPIClient()
    
    // 获取CWE数据库版本信息
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("获取CWE版本失败: %v", err)
    }
    
    fmt.Printf("当前CWE版本: %s\n", version.Version)
    fmt.Printf("发布日期: %s\n", version.ReleaseDate)
    // 输出:
    // 当前CWE版本: 4.12
    // 发布日期: 2023-01-15
}
```

### 2. 获取特定弱点

``go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 获取CWE-79（跨站脚本）
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("获取弱点失败: %v", err)
    }
    
    fmt.Printf("弱点ID: CWE-%s\n", weakness.ID)
    fmt.Printf("弱点名称: %s\n", weakness.Name)
    fmt.Printf("描述: %s\n", weakness.Description)
```

```text
Output:
弱点ID: CWE-79
弱点名称: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
描述: The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page...
```

```go
    if weakness.URL != "" {
        fmt.Printf("更多信息: %s\n", weakness.URL)
        // 输出: 更多信息: https://cwe.mitre.org/data/definitions/79.html
    }
}
```

### 3. 获取类别信息

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
    
    fmt.Printf("类别ID: CWE-%s\n", category.ID)
    fmt.Printf("类别名称: %s\n", category.Name)
    fmt.Printf("描述: %s\n", category.Description)
```

```text
输出:
类别ID: CWE-20
类别名称: Improper Input Validation
描述: The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.
```

```go
}
```

### 4. 获取视图信息

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
    
    fmt.Printf("视图ID: CWE-%s\n", view.ID)
    fmt.Printf("视图名称: %s\n", view.Name)
    fmt.Printf("描述: %s\n", view.Description)
```

```text
输出:
视图ID: CWE-1000
视图名称: Research Concepts
描述: This view (slice) covers the most abstract and fundamental concepts related to software security.
```

```go
}
```

## 批量操作

### 获取多个CWE

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 获取多个CWE弱点
    ids := []string{"79", "89", "20"}
    cwes, err := client.GetCWEs(ids)
    if err != nil {
        log.Fatalf("获取CWE列表失败: %v", err)
    }
    
    fmt.Printf("成功获取 %d 个CWE:\n", len(cwes))
    for id, weakness := range cwes {
        fmt.Printf("- CWE-%s: %s\n", id, weakness.Name)
    }
```

```text
输出:
成功获取 3 个CWE:
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-20: Improper Input Validation
```

```go
}
```

## 错误处理

### 处理常见错误

```go
package main

import (
    "fmt"
    "log"
    "strings"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 尝试获取不存在的CWE
    weakness, err := client.GetWeakness("99999")
    if err != nil {
        switch {
        case strings.Contains(err.Error(), "404"):
            fmt.Println("CWE不存在")
            // 输出: CWE不存在
        case strings.Contains(err.Error(), "timeout"):
            fmt.Println("请求超时，请稍后重试")
            // 输出: 请求超时，请稍后重试
        case strings.Contains(err.Error(), "rate limit"):
            fmt.Println("请求过于频繁，请稍后重试")
            // 输出: 请求过于频繁，请稍后重试
        default:
            log.Printf("未知错误: %v", err)
            // 输出: 未知错误: [具体错误信息]
        }
        return
    }
    
    fmt.Printf("获取到弱点: %s\n", weakness.Name)
}
```

## 自定义配置

### 自定义API客户端

```go
package main

import (
    "time"
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建自定义速率限制器
    limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
    
    // 创建自定义配置的客户端
    client := cwe.NewAPIClientWithOptions(
        "",                    // 使用默认API端点
        30*time.Second,        // HTTP超时
        limiter,              // 速率限制器
    )
    // 输出: 创建具有自定义配置的API客户端
    
    // 获取并显示当前速率限制
    currentLimiter := client.GetRateLimiter()
    fmt.Printf("当前速率限制: %v\n", currentLimiter.GetInterval())
    // 输出: 当前速率限制: 5s
    
    // 调整速率限制
    currentLimiter.SetInterval(2 * time.Second)
    fmt.Printf("更新后的速率限制: %v\n", currentLimiter.GetInterval())
    // 输出: 更新后的速率限制: 2s
}
```

## 并发使用

### 多goroutine安全使用

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
    
    var wg sync.WaitGroup
    ids := []string{"79", "89", "20", "287", "78"}
    
    // 并发获取多个CWE
    for i, id := range ids {
        wg.Add(1)
        go func(index int, cweID string) {
            defer wg.Done()
            
            weakness, err := client.GetWeakness(cweID)
            if err != nil {
                log.Printf("获取CWE-%s失败: %v", cweID, err)
                return
            }
            
            fmt.Printf("Goroutine %d: CWE-%s = %s\n", index, cweID, weakness.Name)
        }(i, id)
    }
    
    wg.Wait()
    // 输出: 多个goroutine并发获取CWE信息
}
```

## 最佳实践

1. **重用客户端实例** - 避免频繁创建新的客户端
2. **适当的速率限制** - 根据API使用情况调整速率限制
3. **错误处理** - 始终检查和处理错误
4. **超时设置** - 设置合理的HTTP超时时间

## 下一步

- 查看[构建树结构](./build-tree)示例
- 学习[搜索和过滤](./search-filter)功能
- 了解[导出和导入](./export-import)数据