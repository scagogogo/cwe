# 速率限制客户端

本示例展示如何使用速率限制HTTP客户端来控制请求频率，避免API过载。

## 基本速率限制

### 使用默认速率限制

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建默认API客户端（内置速率限制）
    client := cwe.NewAPIClient()
    
    fmt.Println("使用默认速率限制（每10秒1个请求）")
    
    // 连续发送多个请求
    ids := []string{"79", "89", "78"}
    
    for i, id := range ids {
        start := time.Now()
        
        fmt.Printf("发送第%d个请求: CWE-%s...", i+1, id)
        
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("请求失败: %v", err)
            continue
        }
        
        duration := time.Since(start)
        fmt.Printf(" 完成 (耗时: %v)\n", duration)
        fmt.Printf("  结果: %s\n", weakness.Name)
    }
}
```

### 自定义速率限制

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建自定义速率限制器（每2秒1个请求）
    limiter := cwe.NewHTTPRateLimiter(2 * time.Second)
    
    // 创建带自定义速率限制的客户端
    client := cwe.NewAPIClientWithOptions(
        "",                    // 使用默认API端点
        30*time.Second,        // 30秒超时
        limiter,              // 自定义速率限制器
    )
    
    fmt.Println("使用自定义速率限制（每2秒1个请求）")
    
    ids := []string{"79", "89", "78", "77"}
    
    for i, id := range ids {
        start := time.Now()
        
        fmt.Printf("发送第%d个请求: CWE-%s...", i+1, id)
        
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("请求失败: %v", err)
            continue
        }
        
        duration := time.Since(start)
        fmt.Printf(" 完成 (耗时: %v)\n", duration)
        fmt.Printf("  结果: %s [%s]\n", weakness.Name, weakness.Severity)
    }
}
```

## 动态速率限制调整

### 根据响应调整速率限制

```go
package main

import (
    "fmt"
    "log"
    "strings"
    "time"
    
    "github.com/scagogogo/cwe"
)

func adaptiveRateLimit(client *cwe.APIClient, id string) (*cwe.CWEWeakness, error) {
    limiter := client.GetRateLimiter()
    currentInterval := limiter.GetInterval()
    
    weakness, err := client.GetWeakness(id)
    
    if err != nil {
        // 如果是速率限制错误，增加间隔时间
        if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "429") {
            newInterval := currentInterval * 2
            limiter.SetInterval(newInterval)
            fmt.Printf("检测到速率限制，调整间隔为: %v\n", newInterval)
        }
        return nil, err
    }
    
    // 请求成功，可以适当减少间隔时间
    if currentInterval > time.Second {
        newInterval := time.Duration(float64(currentInterval) * 0.9)
        if newInterval < time.Second {
            newInterval = time.Second
        }
        limiter.SetInterval(newInterval)
        fmt.Printf("请求成功，优化间隔为: %v\n", newInterval)
    }
    
    return weakness, nil
}

func main() {
    // 创建初始速率限制较快的客户端
    limiter := cwe.NewHTTPRateLimiter(500 * time.Millisecond)
    client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)
    
    fmt.Println("使用自适应速率限制")
    
    ids := []string{"79", "89", "78", "77", "352", "434"}
    
    for i, id := range ids {
        fmt.Printf("\n第%d个请求: CWE-%s\n", i+1, id)
        
        weakness, err := adaptiveRateLimit(client, id)
        if err != nil {
            log.Printf("请求失败: %v", err)
            continue
        }
        
        fmt.Printf("成功获取: %s\n", weakness.Name)
        
        // 显示当前速率限制
        currentInterval := client.GetRateLimiter().GetInterval()
        fmt.Printf("当前间隔: %v\n", currentInterval)
    }
}
```

## 并发请求与速率限制

### 工作池模式

```go
package main

import (
    "fmt"
    "log"
    "sync"
    "time"
    
    "github.com/scagogogo/cwe"
)

type WorkerPool struct {
    client     *cwe.APIClient
    workers    int
    taskChan   chan string
    resultChan chan Result
    wg         sync.WaitGroup
}

type Result struct {
    ID       string
    Weakness *cwe.CWEWeakness
    Error    error
    Duration time.Duration
}

func NewWorkerPool(client *cwe.APIClient, workers int) *WorkerPool {
    return &WorkerPool{
        client:     client,
        workers:    workers,
        taskChan:   make(chan string, workers*2),
        resultChan: make(chan Result, workers*2),
    }
}

func (p *WorkerPool) Start() {
    for i := 0; i < p.workers; i++ {
        p.wg.Add(1)
        go p.worker(i)
    }
}

func (p *WorkerPool) worker(id int) {
    defer p.wg.Done()
    
    for cweID := range p.taskChan {
        start := time.Now()
        
        fmt.Printf("Worker %d: 处理 CWE-%s\n", id, cweID)
        
        weakness, err := p.client.GetWeakness(cweID)
        duration := time.Since(start)
        
        result := Result{
            ID:       cweID,
            Weakness: weakness,
            Error:    err,
            Duration: duration,
        }
        
        p.resultChan <- result
    }
}

func (p *WorkerPool) Submit(id string) {
    p.taskChan <- id
}

func (p *WorkerPool) Close() {
    close(p.taskChan)
    p.wg.Wait()
    close(p.resultChan)
}

func (p *WorkerPool) GetResults() []Result {
    var results []Result
    for result := range p.resultChan {
        results = append(results, result)
    }
    return results
}

func main() {
    // 创建速率限制客户端
    limiter := cwe.NewHTTPRateLimiter(1 * time.Second)
    client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)
    
    // 创建工作池（3个worker）
    pool := NewWorkerPool(client, 3)
    pool.Start()
    
    // 提交任务
    ids := []string{"79", "89", "78", "77", "352", "434", "502", "20", "22"}
    
    fmt.Printf("提交 %d 个任务到工作池\n", len(ids))
    
    for _, id := range ids {
        pool.Submit(id)
    }
    
    // 关闭工作池并等待完成
    pool.Close()
    
    // 收集结果
    results := pool.GetResults()
    
    fmt.Printf("\n处理完成，共 %d 个结果:\n", len(results))
    
    successCount := 0
    totalDuration := time.Duration(0)
    
    for _, result := range results {
        if result.Error != nil {
            fmt.Printf("❌ CWE-%s: %v (耗时: %v)\n", result.ID, result.Error, result.Duration)
        } else {
            fmt.Printf("✅ CWE-%s: %s (耗时: %v)\n", 
                result.ID, result.Weakness.Name, result.Duration)
            successCount++
        }
        totalDuration += result.Duration
    }
    
    fmt.Printf("\n统计信息:\n")
    fmt.Printf("成功: %d/%d\n", successCount, len(results))
    fmt.Printf("平均耗时: %v\n", totalDuration/time.Duration(len(results)))
}
```

## 速率限制监控

### 请求统计和监控

```go
package main

import (
    "fmt"
    "log"
    "sync"
    "time"
    
    "github.com/scagogogo/cwe"
)

type RateLimitMonitor struct {
    client        *cwe.APIClient
    requestCount  int64
    successCount  int64
    errorCount    int64
    totalWaitTime time.Duration
    mu            sync.RWMutex
}

func NewRateLimitMonitor(client *cwe.APIClient) *RateLimitMonitor {
    return &RateLimitMonitor{
        client: client,
    }
}

func (m *RateLimitMonitor) GetWeakness(id string) (*cwe.CWEWeakness, error) {
    start := time.Now()
    
    // 记录请求开始
    m.mu.Lock()
    m.requestCount++
    m.mu.Unlock()
    
    // 发送请求
    weakness, err := m.client.GetWeakness(id)
    
    // 记录结果
    duration := time.Since(start)
    
    m.mu.Lock()
    m.totalWaitTime += duration
    if err != nil {
        m.errorCount++
    } else {
        m.successCount++
    }
    m.mu.Unlock()
    
    return weakness, err
}

func (m *RateLimitMonitor) GetStats() (int64, int64, int64, time.Duration, time.Duration) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    var avgWaitTime time.Duration
    if m.requestCount > 0 {
        avgWaitTime = m.totalWaitTime / time.Duration(m.requestCount)
    }
    
    return m.requestCount, m.successCount, m.errorCount, m.totalWaitTime, avgWaitTime
}

func (m *RateLimitMonitor) PrintStats() {
    total, success, errors, totalWait, avgWait := m.GetStats()
    
    fmt.Printf("\n=== 速率限制监控统计 ===\n")
    fmt.Printf("总请求数: %d\n", total)
    fmt.Printf("成功请求: %d\n", success)
    fmt.Printf("失败请求: %d\n", errors)
    
    if total > 0 {
        successRate := float64(success) / float64(total) * 100
        fmt.Printf("成功率: %.1f%%\n", successRate)
    }
    
    fmt.Printf("总等待时间: %v\n", totalWait)
    fmt.Printf("平均等待时间: %v\n", avgWait)
    
    // 显示当前速率限制设置
    limiter := m.client.GetRateLimiter()
    fmt.Printf("当前速率限制: %v\n", limiter.GetInterval())
}

func main() {
    // 创建速率限制客户端
    limiter := cwe.NewHTTPRateLimiter(2 * time.Second)
    client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)
    
    // 创建监控器
    monitor := NewRateLimitMonitor(client)
    
    fmt.Println("开始监控速率限制性能")
    
    ids := []string{"79", "89", "78", "77", "352"}
    
    for i, id := range ids {
        fmt.Printf("请求 %d/%d: CWE-%s...", i+1, len(ids), id)
        
        weakness, err := monitor.GetWeakness(id)
        if err != nil {
            fmt.Printf(" 失败: %v\n", err)
        } else {
            fmt.Printf(" 成功: %s\n", weakness.Name)
        }
        
        // 每隔几个请求显示统计信息
        if (i+1)%2 == 0 {
            monitor.PrintStats()
        }
    }
    
    // 最终统计
    monitor.PrintStats()
}
```

## 高级速率限制策略

### 指数退避策略

```go
package main

import (
    "fmt"
    "log"
    "math"
    "strings"
    "time"
    
    "github.com/scagogogo/cwe"
)

type ExponentialBackoffClient struct {
    client      *cwe.APIClient
    baseDelay   time.Duration
    maxDelay    time.Duration
    maxRetries  int
}

func NewExponentialBackoffClient(client *cwe.APIClient) *ExponentialBackoffClient {
    return &ExponentialBackoffClient{
        client:     client,
        baseDelay:  1 * time.Second,
        maxDelay:   30 * time.Second,
        maxRetries: 5,
    }
}

func (c *ExponentialBackoffClient) GetWeakness(id string) (*cwe.CWEWeakness, error) {
    var lastErr error
    
    for attempt := 0; attempt <= c.maxRetries; attempt++ {
        weakness, err := c.client.GetWeakness(id)
        
        if err == nil {
            if attempt > 0 {
                fmt.Printf("重试成功 (第%d次尝试)\n", attempt+1)
            }
            return weakness, nil
        }
        
        lastErr = err
        
        // 检查是否是速率限制错误
        if !c.isRateLimitError(err) {
            return nil, err
        }
        
        if attempt < c.maxRetries {
            // 计算退避延迟
            delay := c.calculateDelay(attempt)
            fmt.Printf("速率限制错误，%v后重试 (第%d次尝试)\n", delay, attempt+1)
            time.Sleep(delay)
        }
    }
    
    return nil, fmt.Errorf("重试%d次后仍然失败: %v", c.maxRetries, lastErr)
}

func (c *ExponentialBackoffClient) isRateLimitError(err error) bool {
    errStr := strings.ToLower(err.Error())
    return strings.Contains(errStr, "rate limit") || 
           strings.Contains(errStr, "429") ||
           strings.Contains(errStr, "too many requests")
}

func (c *ExponentialBackoffClient) calculateDelay(attempt int) time.Duration {
    // 指数退避: baseDelay * 2^attempt
    delay := time.Duration(float64(c.baseDelay) * math.Pow(2, float64(attempt)))
    
    // 限制最大延迟
    if delay > c.maxDelay {
        delay = c.maxDelay
    }
    
    return delay
}

func main() {
    // 创建一个较快的速率限制（容易触发限制）
    limiter := cwe.NewHTTPRateLimiter(100 * time.Millisecond)
    client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)
    
    // 创建指数退避客户端
    backoffClient := NewExponentialBackoffClient(client)
    
    fmt.Println("使用指数退避策略")
    
    ids := []string{"79", "89", "78"}
    
    for i, id := range ids {
        fmt.Printf("\n请求 %d: CWE-%s\n", i+1, id)
        
        start := time.Now()
        weakness, err := backoffClient.GetWeakness(id)
        duration := time.Since(start)
        
        if err != nil {
            log.Printf("最终失败: %v (总耗时: %v)", err, duration)
        } else {
            fmt.Printf("成功获取: %s (总耗时: %v)\n", weakness.Name, duration)
        }
    }
}
```

## 速率限制最佳实践

### 智能速率限制管理

```go
package main

import (
    "fmt"
    "sync"
    "time"
    
    "github.com/scagogogo/cwe"
)

type SmartRateLimiter struct {
    client          *cwe.APIClient
    successRate     float64
    recentRequests  []RequestResult
    maxHistory      int
    adjustmentMutex sync.RWMutex
}

type RequestResult struct {
    Success   bool
    Timestamp time.Time
    Duration  time.Duration
}

func NewSmartRateLimiter(client *cwe.APIClient) *SmartRateLimiter {
    return &SmartRateLimiter{
        client:         client,
        successRate:    1.0,
        recentRequests: make([]RequestResult, 0),
        maxHistory:     20,
    }
}

func (s *SmartRateLimiter) GetWeakness(id string) (*cwe.CWEWeakness, error) {
    start := time.Now()
    
    weakness, err := s.client.GetWeakness(id)
    duration := time.Since(start)
    
    // 记录请求结果
    result := RequestResult{
        Success:   err == nil,
        Timestamp: time.Now(),
        Duration:  duration,
    }
    
    s.recordResult(result)
    s.adjustRateLimit()
    
    return weakness, err
}

func (s *SmartRateLimiter) recordResult(result RequestResult) {
    s.adjustmentMutex.Lock()
    defer s.adjustmentMutex.Unlock()
    
    s.recentRequests = append(s.recentRequests, result)
    
    // 保持历史记录在限制范围内
    if len(s.recentRequests) > s.maxHistory {
        s.recentRequests = s.recentRequests[1:]
    }
    
    // 计算成功率
    if len(s.recentRequests) > 0 {
        successCount := 0
        for _, req := range s.recentRequests {
            if req.Success {
                successCount++
            }
        }
        s.successRate = float64(successCount) / float64(len(s.recentRequests))
    }
}

func (s *SmartRateLimiter) adjustRateLimit() {
    s.adjustmentMutex.Lock()
    defer s.adjustmentMutex.Unlock()
    
    limiter := s.client.GetRateLimiter()
    currentInterval := limiter.GetInterval()
    
    var newInterval time.Duration
    
    switch {
    case s.successRate >= 0.95:
        // 成功率很高，可以加快请求
        newInterval = time.Duration(float64(currentInterval) * 0.8)
        if newInterval < 500*time.Millisecond {
            newInterval = 500 * time.Millisecond
        }
        
    case s.successRate >= 0.8:
        // 成功率良好，保持当前速率
        newInterval = currentInterval
        
    case s.successRate >= 0.6:
        // 成功率一般，稍微减慢
        newInterval = time.Duration(float64(currentInterval) * 1.2)
        
    default:
        // 成功率较低，显著减慢
        newInterval = time.Duration(float64(currentInterval) * 1.5)
        if newInterval > 30*time.Second {
            newInterval = 30 * time.Second
        }
    }
    
    if newInterval != currentInterval {
        limiter.SetInterval(newInterval)
        fmt.Printf("调整速率限制: %v -> %v (成功率: %.1f%%)\n", 
            currentInterval, newInterval, s.successRate*100)
    }
}

func (s *SmartRateLimiter) GetStats() (float64, time.Duration, int) {
    s.adjustmentMutex.RLock()
    defer s.adjustmentMutex.RUnlock()
    
    currentInterval := s.client.GetRateLimiter().GetInterval()
    return s.successRate, currentInterval, len(s.recentRequests)
}

func main() {
    // 创建初始客户端
    limiter := cwe.NewHTTPRateLimiter(1 * time.Second)
    client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)
    
    // 创建智能速率限制器
    smartLimiter := NewSmartRateLimiter(client)
    
    fmt.Println("使用智能速率限制管理")
    
    ids := []string{"79", "89", "78", "77", "352", "434", "502", "20", "22", "74"}
    
    for i, id := range ids {
        fmt.Printf("\n请求 %d/%d: CWE-%s\n", i+1, len(ids), id)
        
        weakness, err := smartLimiter.GetWeakness(id)
        if err != nil {
            fmt.Printf("❌ 失败: %v\n", err)
        } else {
            fmt.Printf("✅ 成功: %s\n", weakness.Name)
        }
        
        // 显示当前统计
        successRate, interval, historySize := smartLimiter.GetStats()
        fmt.Printf("当前状态: 成功率=%.1f%%, 间隔=%v, 历史=%d\n", 
            successRate*100, interval, historySize)
    }
}
```

## 运行示例

保存任意示例代码为 `main.go`，然后运行：

```bash
go mod init cwe-rate-limit-example
go get github.com/scagogogo/cwe
go run main.go
```

## 最佳实践

1. **合理设置初始速率** - 根据API文档设置合适的初始速率限制
2. **监控和调整** - 监控请求成功率并动态调整速率限制
3. **错误处理** - 正确处理速率限制错误和重试
4. **指数退避** - 使用指数退避策略处理临时性错误
5. **并发控制** - 在并发环境中合理控制请求频率

## 下一步

- 回顾[基本用法](./basic-usage)了解更多基础功能
- 学习[获取CWE数据](./fetch-cwe)的高级技术
- 探索[API参考](/zh/api/)了解详细的API文档
