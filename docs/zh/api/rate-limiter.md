# 速率限制器

速率限制器用于控制HTTP请求的频率，防止API过载并确保请求的可靠性。

## 概述

`HTTPRateLimiter` 提供了以下功能：

- 请求频率控制
- 动态间隔调整
- 线程安全操作
- 简单易用的API

## 创建速率限制器

### 基本创建

```go
import (
    "time"
    "github.com/scagogogo/cwe"
)

// 创建每2秒1个请求的限制器
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)
```

### 不同间隔示例

```go
// 每秒1个请求
fastLimiter := cwe.NewHTTPRateLimiter(1 * time.Second)

// 每5秒1个请求
slowLimiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// 每分钟1个请求
verySlowLimiter := cwe.NewHTTPRateLimiter(1 * time.Minute)
```

## 基本用法

### 等待许可

```go
// 等待直到可以发送请求
limiter.Wait()

// 现在可以安全地发送请求
resp, err := http.Get("https://api.example.com/data")
```

### 检查是否可以请求

```go
// 非阻塞检查
if limiter.Allow() {
    // 可以立即发送请求
    resp, err := http.Get("https://api.example.com/data")
} else {
    // 需要等待
    fmt.Println("请求过于频繁，请稍后重试")
}
```

## 动态配置

### 获取和设置间隔

```go
// 获取当前间隔
currentInterval := limiter.GetInterval()
fmt.Printf("当前间隔: %v\n", currentInterval)

// 设置新的间隔
limiter.SetInterval(3 * time.Second)
fmt.Println("间隔已更新为3秒")
```

### 根据响应调整

```go
func adjustRateLimit(limiter *cwe.HTTPRateLimiter, resp *http.Response) {
    switch resp.StatusCode {
    case 429: // Too Many Requests
        // 增加间隔时间
        current := limiter.GetInterval()
        newInterval := current * 2
        limiter.SetInterval(newInterval)
        log.Printf("速率限制增加到: %v", newInterval)
        
    case 200:
        // 成功请求，可以适当减少间隔
        current := limiter.GetInterval()
        if current > time.Second {
            newInterval := current / 2
            limiter.SetInterval(newInterval)
            log.Printf("速率限制减少到: %v", newInterval)
        }
    }
}
```

## 高级用法

### 带超时的等待

```go
func waitWithTimeout(limiter *cwe.HTTPRateLimiter, timeout time.Duration) error {
    done := make(chan struct{})
    
    go func() {
        limiter.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        return nil
    case <-time.After(timeout):
        return errors.New("等待超时")
    }
}

// 使用示例
err := waitWithTimeout(limiter, 10*time.Second)
if err != nil {
    log.Printf("等待许可超时: %v", err)
    return
}

// 发送请求
resp, err := http.Get("https://api.example.com/data")
```

### 批量请求控制

```go
func batchRequestsWithRateLimit(limiter *cwe.HTTPRateLimiter, urls []string) {
    for i, url := range urls {
        // 等待速率限制许可
        limiter.Wait()
        
        fmt.Printf("发送第%d个请求: %s\n", i+1, url)
        
        go func(u string) {
            resp, err := http.Get(u)
            if err != nil {
                log.Printf("请求失败: %v", err)
                return
            }
            defer resp.Body.Close()
            
            fmt.Printf("请求成功: %s (状态: %d)\n", u, resp.StatusCode)
        }(url)
    }
}
```

## 并发使用

### 多goroutine安全使用

```go
func concurrentRequests(limiter *cwe.HTTPRateLimiter, urls []string) {
    var wg sync.WaitGroup
    
    for _, url := range urls {
        wg.Add(1)
        
        go func(u string) {
            defer wg.Done()
            
            // 每个goroutine都需要等待许可
            limiter.Wait()
            
            resp, err := http.Get(u)
            if err != nil {
                log.Printf("请求失败: %v", err)
                return
            }
            defer resp.Body.Close()
            
            fmt.Printf("请求完成: %s\n", u)
        }(url)
    }
    
    wg.Wait()
}
```

### 工作池模式

```go
type RateLimitedWorkerPool struct {
    limiter   *cwe.HTTPRateLimiter
    workers   int
    taskChan  chan string
    resultChan chan result
}

type result struct {
    URL    string
    Status int
    Error  error
}

func NewRateLimitedWorkerPool(limiter *cwe.HTTPRateLimiter, workers int) *RateLimitedWorkerPool {
    return &RateLimitedWorkerPool{
        limiter:    limiter,
        workers:    workers,
        taskChan:   make(chan string, workers*2),
        resultChan: make(chan result, workers*2),
    }
}

func (p *RateLimitedWorkerPool) Start() {
    for i := 0; i < p.workers; i++ {
        go p.worker()
    }
}

func (p *RateLimitedWorkerPool) worker() {
    for url := range p.taskChan {
        // 等待速率限制许可
        p.limiter.Wait()
        
        resp, err := http.Get(url)
        
        result := result{URL: url}
        if err != nil {
            result.Error = err
        } else {
            result.Status = resp.StatusCode
            resp.Body.Close()
        }
        
        p.resultChan <- result
    }
}

func (p *RateLimitedWorkerPool) Submit(url string) {
    p.taskChan <- url
}

func (p *RateLimitedWorkerPool) GetResult() result {
    return <-p.resultChan
}
```

## 监控和统计

### 请求统计

```go
type RateLimiterStats struct {
    TotalRequests   int64
    WaitTime        time.Duration
    AverageWaitTime time.Duration
    mu              sync.RWMutex
}

func (s *RateLimiterStats) RecordWait(duration time.Duration) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.TotalRequests++
    s.WaitTime += duration
    s.AverageWaitTime = s.WaitTime / time.Duration(s.TotalRequests)
}

func (s *RateLimiterStats) GetStats() (int64, time.Duration, time.Duration) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    return s.TotalRequests, s.WaitTime, s.AverageWaitTime
}

// 带统计的等待
func waitWithStats(limiter *cwe.HTTPRateLimiter, stats *RateLimiterStats) {
    start := time.Now()
    limiter.Wait()
    duration := time.Since(start)
    
    stats.RecordWait(duration)
}
```

## 自适应速率限制

### 基于响应的自适应

```go
type AdaptiveRateLimiter struct {
    limiter     *cwe.HTTPRateLimiter
    successRate float64
    minInterval time.Duration
    maxInterval time.Duration
    mu          sync.RWMutex
}

func NewAdaptiveRateLimiter(initial, min, max time.Duration) *AdaptiveRateLimiter {
    return &AdaptiveRateLimiter{
        limiter:     cwe.NewHTTPRateLimiter(initial),
        successRate: 1.0,
        minInterval: min,
        maxInterval: max,
    }
}

func (a *AdaptiveRateLimiter) RecordResponse(success bool) {
    a.mu.Lock()
    defer a.mu.Unlock()
    
    // 简单的成功率计算（可以使用更复杂的算法）
    if success {
        a.successRate = a.successRate*0.9 + 0.1
    } else {
        a.successRate = a.successRate * 0.9
    }
    
    // 根据成功率调整间隔
    current := a.limiter.GetInterval()
    var newInterval time.Duration
    
    if a.successRate > 0.95 {
        // 成功率高，可以加快请求
        newInterval = time.Duration(float64(current) * 0.9)
    } else if a.successRate < 0.8 {
        // 成功率低，需要减慢请求
        newInterval = time.Duration(float64(current) * 1.2)
    } else {
        newInterval = current
    }
    
    // 确保在最小和最大间隔范围内
    if newInterval < a.minInterval {
        newInterval = a.minInterval
    }
    if newInterval > a.maxInterval {
        newInterval = a.maxInterval
    }
    
    a.limiter.SetInterval(newInterval)
}

func (a *AdaptiveRateLimiter) Wait() {
    a.limiter.Wait()
}
```

## 配置建议

### 不同场景的配置

```go
// 开发环境 - 较快的请求频率
devLimiter := cwe.NewHTTPRateLimiter(500 * time.Millisecond)

// 生产环境 - 保守的请求频率
prodLimiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// 公共API - 严格的速率限制
publicAPILimiter := cwe.NewHTTPRateLimiter(10 * time.Second)

// 内部API - 相对宽松的限制
internalAPILimiter := cwe.NewHTTPRateLimiter(1 * time.Second)
```

## 最佳实践

1. **合理设置间隔** - 根据API提供商的限制设置合适的间隔
2. **动态调整** - 根据响应状态动态调整速率限制
3. **监控统计** - 记录请求统计信息，便于优化
4. **错误处理** - 处理速率限制相关的错误
5. **并发安全** - 在多goroutine环境中安全使用

## 下一步

- 了解[HTTP客户端](./http-client)的集成使用
- 学习[API客户端](./api-client)的配置
- 查看[示例](/zh/examples/)中的实际应用
