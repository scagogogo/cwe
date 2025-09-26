# HTTP客户端

`HTTPClient` 提供了一个功能完整的HTTP客户端，内置速率限制、自动重试机制和线程安全操作。它专为可靠的API通信而设计，具有适当的错误处理和资源管理。

## HTTPClient

```go
type HTTPClient struct {
    client      *http.Client     // 底层HTTP客户端
    rateLimiter *HTTPRateLimiter // 速率限制控制器
    maxRetries  int              // 最大重试次数
    retryDelay  time.Duration    // 重试间隔
}
```

HTTPClient是线程安全的，可以在多个goroutine中并发使用。

## 配置选项

### ClientOption

```go
type ClientOption func(*HTTPClient)
```

用于配置HTTPClient实例的函数类型。

### WithMaxRetries

```go
func WithMaxRetries(maxRetries int) ClientOption
```

设置最大重试次数。

**参数:**
- `maxRetries` - 重试次数（必须 > 0）

### WithRetryInterval

```go
func WithRetryInterval(interval time.Duration) ClientOption
```

设置重试间隔。

**参数:**
- `interval` - 重试间隔时间（必须 > 0）

### WithRateLimit

```go
func WithRateLimit(requestsPerSecond float64) ClientOption
```

设置每秒请求数的速率限制。

**参数:**
- `requestsPerSecond` - 每秒请求数（必须 > 0）

## 构造函数

### NewHttpClient

```go
func NewHttpClient(options ...ClientOption) *HTTPClient
```

创建一个新的HTTP客户端，带有可选配置。

**默认配置:**
- 超时: 30秒
- 速率限制: 每10秒1个请求
- 最大重试次数: 3
- 重试间隔: 1秒

**参数:**
- `options` - 可变数量的配置选项

**示例:**
```go
// 默认客户端
client := cwe.NewHttpClient()
// 输出: 创建一个具有默认设置的新HTTP客户端

// 自定义配置
client := cwe.NewHttpClient(
    cwe.WithMaxRetries(5),
    cwe.WithRetryInterval(2 * time.Second),
    cwe.WithRateLimit(0.5), // 每2秒1个请求
)
// 输出: 创建一个具有5次重试、2秒重试间隔和0.5请求/秒速率限制的客户端
```

### NewHTTPClient

```go
func NewHTTPClient(httpClient *http.Client, rateLimiter *HTTPRateLimiter, maxRetries int, retryDelay time.Duration) *HTTPClient
```

使用显式参数创建一个新的HTTP客户端。

**参数:**
- `httpClient` - 底层HTTP客户端
- `rateLimiter` - 速率限制器实例
- `maxRetries` - 最大重试次数
- `retryDelay` - 重试间隔

**示例:**
```go
httpClient := &http.Client{Timeout: 60 * time.Second}
rateLimiter := cwe.NewHTTPRateLimiter(5 * time.Second)

client := cwe.NewHTTPClient(httpClient, rateLimiter, 3, time.Second)
// 输出: 创建一个具有自定义HTTP客户端、5秒速率限制、3次重试和1秒间隔的客户端
```

## HTTP方法

### Get

```go
func (c *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error)
```

发送带有上下文支持的HTTP GET请求。

**参数:**
- `ctx` - 用于取消/超时的请求上下文
- `url` - 目标URL

**返回值:**
- `*http.Response` - HTTP响应
- `error` - 请求错误

**示例:**
```go
ctx := context.Background()
resp, err := client.Get(ctx, "https://api.example.com/data")
if err != nil {
    log.Fatalf("GET请求失败: %v", err)
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
if err != nil {
    log.Fatalf("读取响应失败: %v", err)
}
// 输出: 发送GET请求并读取响应体
```

### Post

```go
func (c *HTTPClient) Post(ctx context.Context, url string, data []byte) (*http.Response, error)
```

发送带有JSON数据的HTTP POST请求。

**参数:**
- `ctx` - 请求上下文
- `url` - 目标URL
- `data` - 请求体数据

**返回值:**
- `*http.Response` - HTTP响应
- `error` - 请求错误

**示例:**
```go
data := []byte(`{"key": "value"}`)
resp, err := client.Post(ctx, "https://api.example.com/data", data)
if err != nil {
    log.Fatalf("POST请求失败: %v", err)
}
defer resp.Body.Close()
// 输出: 发送带有JSON数据的POST请求
```

### PostForm

```go
func (c *HTTPClient) PostForm(ctx context.Context, url string, data url.Values) (*http.Response, error)
```

发送带有表单数据的HTTP POST请求。

**参数:**
- `ctx` - 请求上下文
- `url` - 目标URL
- `data` - 表单值

**返回值:**
- `*http.Response` - HTTP响应
- `error` - 请求错误

**示例:**
```go
formData := url.Values{
    "username": []string{"user123"},
    "password": []string{"secret"},
}

resp, err := client.PostForm(ctx, "https://api.example.com/login", formData)
if err != nil {
    log.Fatalf("POST表单请求失败: %v", err)
}
defer resp.Body.Close()
// 输出: 发送带有表单数据的POST请求
```

## 代理配置

### 使用带代理的HTTP客户端

```go
import (
    "net/http"
    "net/url"
    "time"
    "github.com/scagogogo/cwe"
)

// 配置代理URL
proxyURL, err := url.Parse("http://proxy.example.com:8080")
if err != nil {
    log.Fatalf("解析代理URL失败: %v", err)
}

// 创建带代理的传输
transport := &http.Transport{
    Proxy: http.ProxyURL(proxyURL),
}

// 创建带代理的HTTP客户端
httpClient := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}

// 创建CWE HTTP客户端
cweClient := cwe.NewHttpClient(
    cwe.WithMaxRetries(3),
    cwe.WithRetryInterval(time.Second),
    cwe.WithRateLimit(1), // 每秒1个请求
)

// 设置带代理的自定义HTTP客户端
cweClient.SetClient(httpClient)

// 使用客户端通过代理发出请求
resp, err := cweClient.Get(context.Background(), "https://cwe-api.mitre.org/api/v1/version")
if err != nil {
    log.Fatalf("请求失败: %v", err)
}
defer resp.Body.Close()

// 输出: 通过代理服务器发出请求并返回响应
```

## 速率限制

### 自定义速率限制

```go
// 创建带自定义速率限制的客户端
client := cwe.NewHttpClient(
    cwe.WithRateLimit(2), // 每秒2个请求
)
// 输出: 创建具有每秒2个请求速率限制的客户端

// 动态调整速率限制
client.GetRateLimiter().SetInterval(5 * time.Second)
// 输出: 将速率限制更新为每5秒1个请求
```

## 错误处理

### 处理网络错误

```go
resp, err := client.Get(ctx, "https://api.example.com/data")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "timeout"):
        log.Println("请求超时")
        // 输出: 处理超时错误
    case strings.Contains(err.Error(), "connection refused"):
        log.Println("连接被拒绝")
        // 输出: 处理连接被拒绝错误
    default:
        log.Printf("网络错误: %v", err)
        // 输出: 处理其他网络错误
    }
    return
}
defer resp.Body.Close()
```

## 线程安全

HTTPClient是线程安全的，可以在多个goroutine中使用：

```go
var wg sync.WaitGroup

// 发出并发请求
for i := 0; i < 5; i++ {
    wg.Add(1)
    go func(requestID int) {
        defer wg.Done()
        
        resp, err := client.Get(ctx, fmt.Sprintf("https://api.example.com/data/%d", requestID))
        if err != nil {
            log.Printf("请求 %d 失败: %v", requestID, err)
            return
        }
        defer resp.Body.Close()
        
        // 处理响应
        log.Printf("请求 %d 完成，状态码 %d", requestID, resp.StatusCode)
    }(i)
}

wg.Wait()
// 输出: 执行5个并发请求并正确同步
```