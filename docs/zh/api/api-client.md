# API客户端

API客户端是CWE Go库的核心组件，提供了访问CWE REST API的完整功能。

## 概述

`APIClient` 提供了一个简单而强大的接口来访问CWE数据：

- 获取CWE版本信息
- 检索弱点、类别和视图数据
- 批量获取多个CWE条目
- 内置速率限制和重试机制

## 创建客户端

### 默认客户端

```go
// 创建默认配置的客户端
client := cwe.NewAPIClient()
```

默认配置包括：
- 每10秒1个请求的速率限制
- 30秒HTTP超时
- 3次重试机制

### 自定义客户端

```go
import (
    "time"
    "github.com/scagogogo/cwe"
)

// 创建自定义速率限制器
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// 创建自定义配置的客户端
client := cwe.NewAPIClientWithOptions(
    "",                    // 使用默认API端点
    30*time.Second,        // HTTP超时
    limiter,              // 速率限制器
)
```

## 主要方法

### 获取版本信息

```go
version, err := client.GetVersion()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("CWE版本: %s\n", version.Version)
fmt.Printf("发布日期: %s\n", version.ReleaseDate)
```

### 获取弱点

```go
// 获取单个弱点
weakness, err := client.GetWeakness("79")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("CWE-79: %s\n", weakness.Name)
```

### 获取类别

```go
// 获取类别信息
category, err := client.GetCategory("20")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("类别: %s\n", category.Name)
```

### 获取视图

```go
// 获取视图信息
view, err := client.GetView("1000")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("视图: %s\n", view.Name)
```

### 批量获取

```go
// 获取多个CWE
ids := []string{"79", "89", "20"}
cwes, err := client.GetCWEs(ids)
if err != nil {
    log.Fatal(err)
}

for id, cwe := range cwes {
    fmt.Printf("CWE-%s: %s\n", id, cwe.Name)
}
```

## 配置管理

### 获取和设置速率限制器

```go
// 获取当前速率限制器
limiter := client.GetRateLimiter()

// 调整速率限制
limiter.SetInterval(2 * time.Second)

// 或设置新的速率限制器
newLimiter := cwe.NewHTTPRateLimiter(1 * time.Second)
client.SetRateLimiter(newLimiter)
```

### 获取和设置HTTP客户端

```go
// 获取当前HTTP客户端
httpClient := client.GetHTTPClient()

// 设置新的HTTP客户端
newHTTPClient := cwe.NewHttpClient(
    cwe.WithRateLimit(5),
    cwe.WithMaxRetries(3),
    cwe.WithRetryInterval(time.Second),
)
client.SetHTTPClient(newHTTPClient)
```

## 错误处理

API客户端会返回详细的错误信息：

```go
weakness, err := client.GetWeakness("invalid")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "404"):
        fmt.Println("CWE不存在")
    case strings.Contains(err.Error(), "timeout"):
        fmt.Println("请求超时")
    case strings.Contains(err.Error(), "rate limit"):
        fmt.Println("请求过于频繁")
    default:
        fmt.Printf("其他错误: %v\n", err)
    }
}
```

## 最佳实践

1. **重用客户端实例** - 避免频繁创建新的客户端
2. **适当的速率限制** - 根据API使用情况调整速率限制
3. **错误处理** - 始终检查和处理错误
4. **超时设置** - 设置合理的HTTP超时时间

## 线程安全

API客户端是线程安全的，可以在多个goroutine中安全使用：

```go
var wg sync.WaitGroup

for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        weakness, err := client.GetWeakness(fmt.Sprintf("%d", id))
        if err != nil {
            log.Printf("获取CWE-%d失败: %v", id, err)
            return
        }
        fmt.Printf("CWE-%d: %s\n", id, weakness.Name)
    }(i + 70) // 从CWE-70开始
}

wg.Wait()
```

## 下一步

- 了解[HTTP客户端](./http-client)的详细配置
- 学习[速率限制器](./rate-limiter)的使用
- 查看[示例](/zh/examples/)中的实际用法
