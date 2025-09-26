# 限速客户端

本示例演示了限速HTTP客户端的高级用法，包括自定义配置、自适应速率限制和性能优化策略。

## 完整示例

```go
package main

import (
    "context"
    "fmt"
    "log"
    "strings"
    "sync"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    fmt.Println("==== 限速客户端示例 ====")
    
    // 1. 基本速率限制
    fmt.Println("\n1. 基本速率限制")
    basicRateLimitingExample()
    
    // 2. 自定义速率限制配置
    fmt.Println("\n2. 自定义速率限制配置")
    customConfigurationExample()
    
    // 3. 自适应速率限制
    fmt.Println("\n3. 自适应速率限制")
    adaptiveRateLimitingExample()
    
    // 4. 并发使用与速率限制
    fmt.Println("\n4. 并发使用")
    concurrentUsageExample()
    
    // 5. 带错误处理的速率限制
    fmt.Println("\n5. 错误处理和恢复")
    errorHandlingExample()
    
    // 6. 性能监控
    fmt.Println("\n6. 性能监控")
    performanceMonitoringExample()
    
    fmt.Println("\n==== 限速客户端示例完成 ====")
}

func basicRateLimitingExample() {
    // 创建具有默认速率限制（10秒）的客户端
    client := cwe.NewAPIClient()
    
    fmt.Printf("默认速率限制: %v\n", client.GetRateLimiter().GetInterval())
    // 输出: 默认速率限制: 10s
    
    // 发出几个请求以演示速率限制
    start := time.Now()
    
    for i := 0; i < 3; i++ {
        fmt.Printf("发出请求 %d 于 %v\n", i+1, time.Since(start))
        
        version, err := client.GetVersion()
        if err != nil {
            log.Printf("请求 %d 失败: %v", i+1, err)
            continue
        }
        
        fmt.Printf("  响应: CWE版本 %s\n", version.Version)
        // 输出: 响应: CWE版本 4.12
    }
    
    fmt.Printf("总时间: %v\n", time.Since(start))
    // 输出: 总时间: 20.045s（大约，由于请求之间有10秒速率限制）
}

func customConfigurationExample() {
    // 创建具有自定义速率限制的客户端
    customLimiter := cwe.NewHTTPRateLimiter(2 * time.Second)
    client := cwe.NewAPIClientWithOptions(
        "",                    // 默认基础URL
        30 * time.Second,      // 30秒超时
        customLimiter,         // 自定义速率限制器
    )
    
    fmt.Printf("自定义速率限制: %v\n", client.GetRateLimiter().GetInterval())
    // 输出: 自定义速率限制: 2s
    
    // 演示更快的请求
    start := time.Now()
    
    ids := []string{"79", "89", "287"}
    for i, id := range ids {
        fmt.Printf("获取CWE-%s 于 %v\n", id, time.Since(start))
        
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("获取CWE-%s失败: %v", id, err)
            continue
        }
        
        fmt.Printf("  CWE-%s: %s\n", id, weakness.Name)
        // 输出: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    }
    
    fmt.Printf("总时间: %v\n", time.Since(start))
    // 输出: 总时间: 4.023s（大约，由于请求之间有2秒速率限制）
}

func adaptiveRateLimitingExample() {
    client := cwe.NewAPIClient()
    limiter := client.GetRateLimiter()
    
    // 从激进的速率限制开始
    limiter.SetInterval(1 * time.Second)
    
    fmt.Printf("开始时的间隔: %v\n", limiter.GetInterval())
    // 输出: 开始时的间隔: 1s
    
    // 根据响应模拟自适应行为
    testIDs := []string{"79", "89", "287", "22", "78"}
    
    for i, id := range testIDs {
        start := time.Now()
        weakness, err := client.GetWeakness(id)
        requestTime := time.Since(start)
        
        if err != nil {
            // 发生错误 - 放慢速度
            currentInterval := limiter.GetInterval()
            newInterval := currentInterval * 2
            limiter.SetInterval(newInterval)
            
            fmt.Printf("请求 %d 失败，放慢到 %v\n", i+1, newInterval)
            // 输出: 请求 1 失败，放慢到 2s
            continue
        }
        
        fmt.Printf("请求 %d 在 %v 内成功\n", i+1, requestTime)
        // 输出: 请求 1 在 1.234s 内成功
        
        // 成功 - 可以加速
        if requestTime < 500*time.Millisecond {
            currentInterval := limiter.GetInterval()
            if currentInterval > 500*time.Millisecond {
                newInterval := currentInterval - 200*time.Millisecond
                limiter.SetInterval(newInterval)
                fmt.Printf("  加速到 %v\n", newInterval)
                // 输出: 加速到 800ms
            }
        }
        
        fmt.Printf("  CWE-%s: %s\n", id, weakness.Name)
        // 输出: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    }
}

func concurrentUsageExample() {
    client := cwe.NewAPIClient()
    
    // 为并发使用设置适度的速率限制
    client.GetRateLimiter().SetInterval(3 * time.Second)
    
    var wg sync.WaitGroup
    results := make(chan string, 5)
    
    ids := []string{"79", "89", "287", "22", "78"}
    
    fmt.Printf("开始 %d 个并发请求，速率限制为 %v\n", 
        len(ids), client.GetRateLimiter().GetInterval())
    // 输出: 开始 5 个并发请求，速率限制为 3s
    
    start := time.Now()
    
    for i, id := range ids {
        wg.Add(1)
        go func(goroutineID int, cweID string) {
            defer wg.Done()
            
            requestStart := time.Now()
            weakness, err := client.GetWeakness(cweID)
            requestTime := time.Since(requestStart)
            
            if err != nil {
                results <- fmt.Sprintf("Goroutine %d: CWE-%s 在 %v 后失败: %v", 
                    goroutineID, cweID, requestTime, err)
                // 输出: Goroutine 1: CWE-79 在 1.234s 后失败: [错误详情]
                return
            }
            
            results <- fmt.Sprintf("Goroutine %d: CWE-%s 在 %v 内完成: %s", 
                goroutineID, cweID, requestTime, weakness.Name)
            // 输出: Goroutine 1: CWE-79 在 1.234s 内完成: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
        }(i+1, id)
    }
    
    // 所有goroutine完成后关闭结果通道
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // 打印结果
    for result := range results {
        fmt.Printf("  %s\n", result)
    }
    
    fmt.Printf("所有并发请求在 %v 内完成\n", time.Since(start))
    // 输出: 所有并发请求在 15.678s 内完成（大约）
}

func errorHandlingExample() {
    client := cwe.NewAPIClient()
    
    // 使用无效的CWE ID测试错误处理
    _, err := client.GetWeakness("invalid-id")
    if err != nil {
        fmt.Printf("无效ID的预期错误: %v\n", err)
        // 输出: 无效ID的预期错误: [错误详情]
        
        // 检查是否为速率限制错误
        if strings.Contains(err.Error(), "rate limit") {
            fmt.Println("检测到速率限制错误")
            // 输出: 检测到速率限制错误
        }
    }
    
    // 演示错误后的成功请求
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("错误后获取弱点失败: %v", err)
    }
    
    fmt.Printf("成功获取CWE-79: %s\n", weakness.Name)
    // 输出: 成功获取CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
}

func performanceMonitoringExample() {
    client := cwe.NewAPIClient()
    
    // 跟踪请求性能
    var totalRequests int
    var totalTime time.Duration
    var errors int
    
    ids := []string{"79", "89", "287", "22", "78"}
    
    for _, id := range ids {
        start := time.Now()
        _, err := client.GetWeakness(id)
        duration := time.Since(start)
        
        totalRequests++
        totalTime += duration
        
        if err != nil {
            errors++
            fmt.Printf("CWE-%s 的请求在 %v 后失败: %v\n", id, duration, err)
            // 输出: CWE-79 的请求在 1.234s 后失败: [错误详情]
            continue
        }
        
        fmt.Printf("CWE-%s 的请求在 %v 内完成\n", id, duration)
        // 输出: CWE-79 的请求在 1.234s 内完成
    }
    
    avgTime := totalTime / time.Duration(totalRequests)
    successRate := float64(totalRequests-errors) / float64(totalRequests) * 100
    
    fmt.Printf("\n性能摘要:\n")
    fmt.Printf("  总请求数: %d\n", totalRequests)
    // 输出: 总请求数: 5
    fmt.Printf("  平均响应时间: %v\n", avgTime)
    // 输出: 平均响应时间: 1.234s
    fmt.Printf("  成功率: %.1f%%\n", successRate)
    // 输出: 成功率: 100.0%
    fmt.Printf("  错误数: %d\n", errors)
    // 输出: 错误数: 0
}
```

## 关键概念

### 速率限制策略

1. **固定速率限制** - 请求之间保持一致的延迟
2. **自适应速率限制** - 根据响应时间和错误调整
3. **并发控制** - 管理多个同时请求

### 最佳实践

1. **保守开始** - 从较慢的速率开始，根据需要增加
2. **监控性能** - 跟踪请求时间和成功率
3. **优雅处理错误** - 实现重试逻辑和错误恢复
4. **尊重API限制** - 避免压垮目标服务器

### 常见模式

```go
// 模式1: 简单速率限制
client := cwe.NewAPIClient()
// 使用默认的10秒速率限制

// 模式2: 自定义速率限制
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)
client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)

// 模式3: 自适应速率限制
func adaptiveClient() *cwe.APIClient {
    client := cwe.NewAPIClient()
    
    // 监控响应并调整速率限制
    go func() {
        for {
            // 检查响应时间和错误率
            // 相应调整速率限制
            time.Sleep(1 * time.Minute)
        }
    }()
    
    return client
}
```

## 下一步

- 查看[HTTP客户端](/zh/api/http-client)的详细配置
- 学习[速率限制器](/zh/api/rate-limiter)的使用
- 了解[API客户端](/zh/api/api-client)的更多功能
