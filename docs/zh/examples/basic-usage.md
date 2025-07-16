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
}
```

### 2. 获取特定弱点

```go
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
    
    if weakness.URL != "" {
        fmt.Printf("更多信息: %s\n", weakness.URL)
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
        case strings.Contains(err.Error(), "timeout"):
            fmt.Println("请求超时，请稍后重试")
        case strings.Contains(err.Error(), "rate limit"):
            fmt.Println("请求过于频繁，请稍后重试")
        default:
            log.Printf("未知错误: %v", err)
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
    "fmt"
    "log"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建自定义速率限制器（每5秒1个请求）
    limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
    
    // 创建自定义配置的客户端
    client := cwe.NewAPIClientWithOptions(
        "",                    // 使用默认API端点
        30*time.Second,        // 30秒超时
        limiter,              // 自定义速率限制器
    )
    
    // 使用客户端
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("获取版本失败: %v", err)
    }
    
    fmt.Printf("CWE版本: %s\n", version.Version)
}
```

### 动态调整速率限制

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 获取当前速率限制器
    limiter := client.GetRateLimiter()
    
    // 调整为每2秒1个请求
    limiter.SetInterval(2 * time.Second)
    
    fmt.Println("速率限制已调整为每2秒1个请求")
    
    // 现在所有请求都会使用新的速率限制
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("获取到: CWE-%s\n", weakness.ID)
}
```

## 完整示例

### 综合使用示例

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建客户端
    client := cwe.NewAPIClient()
    
    fmt.Println("=== CWE Go库基本用法示例 ===\n")
    
    // 1. 获取版本信息
    fmt.Println("1. 获取CWE版本信息:")
    version, err := client.GetVersion()
    if err != nil {
        log.Printf("获取版本失败: %v", err)
    } else {
        fmt.Printf("   版本: %s\n", version.Version)
        fmt.Printf("   发布日期: %s\n", version.ReleaseDate)
    }
    
    // 2. 获取弱点
    fmt.Println("\n2. 获取CWE-79弱点:")
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Printf("获取弱点失败: %v", err)
    } else {
        fmt.Printf("   ID: CWE-%s\n", weakness.ID)
        fmt.Printf("   名称: %s\n", weakness.Name)
        fmt.Printf("   描述: %s\n", weakness.Description[:100] + "...")
    }
    
    // 3. 获取类别
    fmt.Println("\n3. 获取CWE-20类别:")
    category, err := client.GetCategory("20")
    if err != nil {
        log.Printf("获取类别失败: %v", err)
    } else {
        fmt.Printf("   ID: CWE-%s\n", category.ID)
        fmt.Printf("   名称: %s\n", category.Name)
    }
    
    // 4. 批量获取
    fmt.Println("\n4. 批量获取CWE:")
    ids := []string{"79", "89"}
    cwes, err := client.GetCWEs(ids)
    if err != nil {
        log.Printf("批量获取失败: %v", err)
    } else {
        for id, cwe := range cwes {
            fmt.Printf("   CWE-%s: %s\n", id, cwe.Name)
        }
    }
    
    fmt.Println("\n=== 示例完成 ===")
}
```

## 运行示例

保存上述代码为 `main.go`，然后运行：

```bash
go mod init cwe-example
go get github.com/scagogogo/cwe
go run main.go
```

## 注意事项

1. **速率限制**: 默认情况下，客户端每10秒只能发送1个请求
2. **错误处理**: 始终检查和处理错误
3. **网络连接**: 确保有可用的网络连接访问CWE API
4. **API可用性**: CWE API可能偶尔不可用，请实现适当的重试逻辑

## 下一步

- 查看[获取CWE数据](./fetch-cwe)了解更高级的数据获取技术
- 学习[搜索和过滤](./search-filter)功能
- 探索[树操作](./build-tree)来处理CWE层次结构
