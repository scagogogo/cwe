# HTTP Client

The `HTTPClient` provides a comprehensive HTTP client with built-in rate limiting, automatic retry logic, and thread-safe operation. It's designed for reliable API communication with proper error handling and resource management.

## HTTPClient

```go
type HTTPClient struct {
    client      *http.Client     // Underlying HTTP client
    rateLimiter *HTTPRateLimiter // Rate limiting controller
    maxRetries  int              // Maximum retry attempts
    retryDelay  time.Duration    // Delay between retries
}
```

The HTTPClient is thread-safe and can be used concurrently across multiple goroutines.

## Configuration Options

### ClientOption

```go
type ClientOption func(*HTTPClient)
```

Function type for configuring HTTPClient instances.

### WithMaxRetries

```go
func WithMaxRetries(maxRetries int) ClientOption
```

Sets the maximum number of retry attempts.

**Parameters:**
- `maxRetries` - Number of retries (must be > 0)

### WithRetryInterval

```go
func WithRetryInterval(interval time.Duration) ClientOption
```

Sets the delay between retry attempts.

**Parameters:**
- `interval` - Retry delay duration (must be > 0)

### WithRateLimit

```go
func WithRateLimit(requestsPerSecond float64) ClientOption
```

Sets the rate limit in requests per second.

**Parameters:**
- `requestsPerSecond` - Requests per second (must be > 0)

## Constructors

### NewHttpClient

```go
func NewHttpClient(options ...ClientOption) *HTTPClient
```

Creates a new HTTP client with optional configuration.

**Default Configuration:**
- Timeout: 30 seconds
- Rate limit: 1 request per 10 seconds
- Max retries: 3
- Retry delay: 1 second

**Parameters:**
- `options` - Variable number of configuration options

**Example:**
```go
// Default client
client := cwe.NewHttpClient()

// Custom configuration
client := cwe.NewHttpClient(
    cwe.WithMaxRetries(5),
    cwe.WithRetryInterval(2 * time.Second),
    cwe.WithRateLimit(0.5), // 1 request per 2 seconds
)
```

### NewHTTPClient

```go
func NewHTTPClient(httpClient *http.Client, rateLimiter *HTTPRateLimiter, maxRetries int, retryDelay time.Duration) *HTTPClient
```

Creates a new HTTP client with explicit parameters.

**Parameters:**
- `httpClient` - Underlying HTTP client
- `rateLimiter` - Rate limiter instance
- `maxRetries` - Maximum retry attempts
- `retryDelay` - Delay between retries

**Example:**
```go
httpClient := &http.Client{Timeout: 60 * time.Second}
rateLimiter := cwe.NewHTTPRateLimiter(5 * time.Second)

client := cwe.NewHTTPClient(httpClient, rateLimiter, 3, time.Second)
```

## HTTP Methods

### Get

```go
func (c *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error)
```

Sends an HTTP GET request with context support.

**Parameters:**
- `ctx` - Request context for cancellation/timeout
- `url` - Target URL

**Returns:**
- `*http.Response` - HTTP response
- `error` - Request error

**Example:**
```go
ctx := context.Background()
resp, err := client.Get(ctx, "https://api.example.com/data")
if err != nil {
    log.Fatalf("GET request failed: %v", err)
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
if err != nil {
    log.Fatalf("Failed to read response: %v", err)
}
```

### Post

```go
func (c *HTTPClient) Post(ctx context.Context, url string, data []byte) (*http.Response, error)
```

Sends an HTTP POST request with JSON data.

**Parameters:**
- `ctx` - Request context
- `url` - Target URL
- `data` - Request body data

**Returns:**
- `*http.Response` - HTTP response
- `error` - Request error

**Example:**
```go
data := []byte(`{"key": "value"}`)
resp, err := client.Post(ctx, "https://api.example.com/data", data)
if err != nil {
    log.Fatalf("POST request failed: %v", err)
}
defer resp.Body.Close()
```

### PostForm

```go
func (c *HTTPClient) PostForm(ctx context.Context, url string, data url.Values) (*http.Response, error)
```

Sends an HTTP POST request with form data.

**Parameters:**
- `ctx` - Request context
- `url` - Target URL
- `data` - Form values

**Returns:**
- `*http.Response` - HTTP response
- `error` - Request error

**Example:**
```go
formData := url.Values{
    "username": []string{"user123"},
    "password": []string{"secret"},
}

resp, err := client.PostForm(ctx, "https://api.example.com/login", formData)
if err != nil {
    log.Fatalf("Form POST failed: %v", err)
}
defer resp.Body.Close()
```

### Do

```go
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error)
```

Executes an HTTP request with rate limiting and retry logic.

**Parameters:**
- `req` - HTTP request to execute

**Returns:**
- `*http.Response` - HTTP response
- `error` - Request error

**Example:**
```go
req, err := http.NewRequest("PUT", "https://api.example.com/data", strings.NewReader("data"))
if err != nil {
    log.Fatalf("Failed to create request: %v", err)
}

req.Header.Set("Content-Type", "application/json")
req.Header.Set("Authorization", "Bearer token123")

resp, err := client.Do(req)
if err != nil {
    log.Fatalf("Request failed: %v", err)
}
defer resp.Body.Close()
```

## Configuration Methods

### SetClient

```go
func (c *HTTPClient) SetClient(client *http.Client)
```

Sets the underlying HTTP client.

**Parameters:**
- `client` - New HTTP client (nil values are ignored)

### GetClient

```go
func (c *HTTPClient) GetClient() *http.Client
```

Returns the underlying HTTP client.

### SetRateLimiter

```go
func (c *HTTPClient) SetRateLimiter(limiter *HTTPRateLimiter)
```

Sets a new rate limiter.

**Parameters:**
- `limiter` - New rate limiter (nil values are ignored)

### GetRateLimiter

```go
func (c *HTTPClient) GetRateLimiter() *HTTPRateLimiter
```

Returns the current rate limiter.

### SetMaxRetries

```go
func (c *HTTPClient) SetMaxRetries(maxRetries int)
```

Sets the maximum number of retry attempts.

### SetRetryDelay

```go
func (c *HTTPClient) SetRetryDelay(delay time.Duration)
```

Sets the delay between retry attempts.

### Close

```go
func (c *HTTPClient) Close()
```

Closes the HTTP client and cleans up resources.

## Global Instances

### DefaultHTTPClient

```go
var DefaultHTTPClient = NewHttpClient()
```

Default HTTP client instance with standard configuration.

## Usage Examples

### Basic Usage

```go
// Create client with default settings
client := cwe.NewHttpClient()
defer client.Close()

// Simple GET request
ctx := context.Background()
resp, err := client.Get(ctx, "https://api.example.com/data")
if err != nil {
    log.Fatalf("Request failed: %v", err)
}
defer resp.Body.Close()

fmt.Printf("Status: %d\n", resp.StatusCode)
```

### Custom Configuration

```go
// Create client with custom settings
client := cwe.NewHttpClient(
    cwe.WithMaxRetries(5),                    // Retry up to 5 times
    cwe.WithRetryInterval(2 * time.Second),   // Wait 2 seconds between retries
    cwe.WithRateLimit(0.2),                   // 1 request per 5 seconds
)

// Set custom timeout
customHTTPClient := &http.Client{
    Timeout: 60 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        10,
        IdleConnTimeout:     30 * time.Second,
        DisableCompression:  true,
    },
}
client.SetClient(customHTTPClient)
```

### Error Handling and Retries

```go
client := cwe.NewHttpClient(
    cwe.WithMaxRetries(3),
    cwe.WithRetryInterval(time.Second),
)

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

resp, err := client.Get(ctx, "https://unreliable-api.example.com/data")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "context deadline exceeded"):
        fmt.Println("Request timed out")
    case strings.Contains(err.Error(), "达到最大重试次数"):
        fmt.Println("Max retries reached")
    case strings.Contains(err.Error(), "connection refused"):
        fmt.Println("Connection failed")
    default:
        fmt.Printf("Unknown error: %v\n", err)
    }
    return
}
defer resp.Body.Close()
```

### Rate Limiting Management

```go
client := cwe.NewHttpClient()

// Get current rate limiter
limiter := client.GetRateLimiter()
fmt.Printf("Current interval: %v\n", limiter.GetInterval())

// Adjust rate limiting based on response
for i := 0; i < 10; i++ {
    resp, err := client.Get(context.Background(), "https://api.example.com/data")
    if err != nil {
        // Slow down on errors
        currentInterval := limiter.GetInterval()
        limiter.SetInterval(currentInterval * 2)
        continue
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 429 { // Too Many Requests
        // Increase delay
        currentInterval := limiter.GetInterval()
        limiter.SetInterval(currentInterval * 2)
    } else if resp.StatusCode == 200 {
        // Gradually speed up on success
        currentInterval := limiter.GetInterval()
        if currentInterval > time.Second {
            limiter.SetInterval(currentInterval / 2)
        }
    }
}
```

### Concurrent Usage

```go
client := cwe.NewHttpClient()
defer client.Close()

// Client is thread-safe
var wg sync.WaitGroup
urls := []string{
    "https://api.example.com/endpoint1",
    "https://api.example.com/endpoint2",
    "https://api.example.com/endpoint3",
}

for _, url := range urls {
    wg.Add(1)
    go func(u string) {
        defer wg.Done()
        
        resp, err := client.Get(context.Background(), u)
        if err != nil {
            log.Printf("Failed to fetch %s: %v", u, err)
            return
        }
        defer resp.Body.Close()
        
        fmt.Printf("Fetched %s: %d\n", u, resp.StatusCode)
    }(url)
}

wg.Wait()
```

## Performance Considerations

- **Rate Limiting**: Default 10-second intervals may be slow for high-throughput scenarios
- **Retry Logic**: Failed requests increase total response time
- **Memory Usage**: Request bodies are buffered in memory for retries
- **Connection Pooling**: Uses Go's default HTTP transport connection pooling

## Thread Safety

- ✅ **All Methods**: Thread-safe, can be called concurrently
- ✅ **Rate Limiter**: Protected by internal mutex
- ✅ **Configuration**: Safe to modify during operation
- ✅ **Concurrent Requests**: Supported with shared rate limiting
