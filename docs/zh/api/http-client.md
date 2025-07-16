# HTTP客户端

HTTP客户端提供了带有速率限制、重试机制和错误处理的HTTP请求功能。

## 概述

`HTTPClient` 是一个增强的HTTP客户端，具有以下特性：

- 速率限制控制
- 自动重试机制
- 请求超时管理
- 错误处理和日志记录
- 线程安全设计

## 创建HTTP客户端

### 默认客户端

```go
// 使用默认配置
client := cwe.NewHTTPClient()
```

默认配置：
- 每10秒1个请求
- 最多重试3次
- 重试间隔1秒
- 30秒超时

### 自定义配置

```go
import (
    "net/http"
    "time"
    "github.com/scagogogo/cwe"
)

// 创建自定义HTTP客户端
httpClient := &http.Client{
    Timeout: 30 * time.Second,
}

// 创建速率限制器
rateLimiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// 创建带配置的客户端
client := cwe.NewHTTPClientWithOptions(
    httpClient,     // 基础HTTP客户端
    rateLimiter,    // 速率限制器
    5,              // 最大重试次数
    2*time.Second,  // 重试间隔
)
```

## 基本用法

### GET请求

```go
resp, err := client.Get("https://api.example.com/data")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

body, err := ioutil.ReadAll(resp.Body)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("响应: %s\n", string(body))
```

### POST请求

```go
data := []byte(`{"key": "value"}`)
resp, err := client.Post(
    "https://api.example.com/data",
    "application/json",
    bytes.NewBuffer(data),
)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
```

### 自定义请求

```go
req, err := http.NewRequest("PUT", "https://api.example.com/data", nil)
if err != nil {
    log.Fatal(err)
}

req.Header.Set("Authorization", "Bearer token")
req.Header.Set("Content-Type", "application/json")

resp, err := client.Do(req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
```

## 速率限制

### 获取和设置速率限制器

```go
// 获取当前速率限制器
limiter := client.GetRateLimiter()

// 调整速率限制
limiter.SetInterval(3 * time.Second)

// 设置新的速率限制器
newLimiter := cwe.NewHTTPRateLimiter(1 * time.Second)
client.SetRateLimiter(newLimiter)
```

### 动态调整

```go
// 根据响应状态动态调整速率限制
func adaptiveRateLimit(client *cwe.HTTPClient, resp *http.Response) {
    limiter := client.GetRateLimiter()
    
    switch resp.StatusCode {
    case 429: // Too Many Requests
        // 增加间隔时间
        currentInterval := limiter.GetInterval()
        newInterval := currentInterval * 2
        limiter.SetInterval(newInterval)
        log.Printf("速率限制调整为: %v", newInterval)
        
    case 200:
        // 成功请求，可以适当减少间隔
        currentInterval := limiter.GetInterval()
        if currentInterval > time.Second {
            newInterval := currentInterval / 2
            limiter.SetInterval(newInterval)
        }
    }
}
```

## 重试机制

### 配置重试

```go
// 设置重试参数
client.SetMaxRetries(5)
client.SetRetryInterval(3 * time.Second)
```

### 自定义重试逻辑

```go
// 定义重试条件
func shouldRetry(resp *http.Response, err error) bool {
    if err != nil {
        // 网络错误，重试
        return true
    }
    
    // 服务器错误，重试
    if resp.StatusCode >= 500 {
        return true
    }
    
    // 速率限制，重试
    if resp.StatusCode == 429 {
        return true
    }
    
    return false
}

// 带重试的请求
func requestWithRetry(client *cwe.HTTPClient, url string) (*http.Response, error) {
    maxRetries := client.GetMaxRetries()
    retryInterval := client.GetRetryInterval()
    
    var lastErr error
    var resp *http.Response
    
    for i := 0; i <= maxRetries; i++ {
        resp, lastErr = client.Get(url)
        
        if lastErr == nil && !shouldRetry(resp, nil) {
            return resp, nil
        }
        
        if resp != nil {
            resp.Body.Close()
        }
        
        if i < maxRetries {
            time.Sleep(retryInterval * time.Duration(i+1))
        }
    }
    
    return nil, fmt.Errorf("重试%d次后仍然失败: %v", maxRetries, lastErr)
}
```

## 错误处理

### 错误类型

```go
func handleHTTPError(err error) {
    switch {
    case strings.Contains(err.Error(), "timeout"):
        fmt.Println("请求超时")
    case strings.Contains(err.Error(), "connection refused"):
        fmt.Println("连接被拒绝")
    case strings.Contains(err.Error(), "no such host"):
        fmt.Println("主机不存在")
    case strings.Contains(err.Error(), "rate limit"):
        fmt.Println("请求过于频繁")
    default:
        fmt.Printf("其他错误: %v\n", err)
    }
}
```

### 响应状态处理

```go
func handleResponse(resp *http.Response) error {
    switch resp.StatusCode {
    case 200:
        return nil
    case 400:
        return errors.New("请求参数错误")
    case 401:
        return errors.New("未授权")
    case 403:
        return errors.New("禁止访问")
    case 404:
        return errors.New("资源不存在")
    case 429:
        return errors.New("请求过于频繁")
    case 500:
        return errors.New("服务器内部错误")
    case 502:
        return errors.New("网关错误")
    case 503:
        return errors.New("服务不可用")
    default:
        return fmt.Errorf("未知状态码: %d", resp.StatusCode)
    }
}
```

## 监控和日志

### 请求日志

```go
type LoggingHTTPClient struct {
    *cwe.HTTPClient
    logger *log.Logger
}

func NewLoggingHTTPClient(client *cwe.HTTPClient) *LoggingHTTPClient {
    return &LoggingHTTPClient{
        HTTPClient: client,
        logger:     log.New(os.Stdout, "[HTTP] ", log.LstdFlags),
    }
}

func (c *LoggingHTTPClient) Do(req *http.Request) (*http.Response, error) {
    start := time.Now()
    
    c.logger.Printf("请求: %s %s", req.Method, req.URL.String())
    
    resp, err := c.HTTPClient.Do(req)
    
    duration := time.Since(start)
    
    if err != nil {
        c.logger.Printf("请求失败: %v (耗时: %v)", err, duration)
        return nil, err
    }
    
    c.logger.Printf("响应: %d (耗时: %v)", resp.StatusCode, duration)
    
    return resp, nil
}
```

### 性能监控

```go
type HTTPMetrics struct {
    RequestCount    int64
    SuccessCount    int64
    ErrorCount      int64
    TotalDuration   time.Duration
    AverageDuration time.Duration
    mu              sync.RWMutex
}

func (m *HTTPMetrics) RecordRequest(duration time.Duration, success bool) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.RequestCount++
    m.TotalDuration += duration
    m.AverageDuration = m.TotalDuration / time.Duration(m.RequestCount)
    
    if success {
        m.SuccessCount++
    } else {
        m.ErrorCount++
    }
}

func (m *HTTPMetrics) GetStats() (int64, int64, int64, time.Duration) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    return m.RequestCount, m.SuccessCount, m.ErrorCount, m.AverageDuration
}
```

## 连接池配置

### 自定义传输

```go
func createCustomTransport() *http.Transport {
    return &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
    }
}

// 使用自定义传输创建客户端
httpClient := &http.Client{
    Transport: createCustomTransport(),
    Timeout:   30 * time.Second,
}

client := cwe.NewHTTPClientWithOptions(
    httpClient,
    cwe.NewHTTPRateLimiter(time.Second),
    3,
    time.Second,
)
```

## 最佳实践

1. **合理设置超时** - 根据网络环境设置适当的超时时间
2. **速率限制** - 遵守API提供商的速率限制要求
3. **错误处理** - 实现完善的错误处理和重试机制
4. **资源管理** - 及时关闭响应体，避免资源泄漏
5. **监控日志** - 记录请求日志，便于问题排查

## 下一步

- 了解[速率限制器](./rate-limiter)的详细配置
- 学习[API客户端](./api-client)的高级用法
- 查看[示例](/zh/examples/)中的实际应用
