# Rate Limiter

The `HTTPRateLimiter` provides thread-safe rate limiting for HTTP requests. It ensures that requests are spaced out according to a configurable time interval, preventing API overload and avoiding rate limit violations.

## HTTPRateLimiter

```go
type HTTPRateLimiter struct {
    interval    time.Duration // Minimum time between requests
    lastRequest time.Time     // Timestamp of last request
    mutex       sync.Mutex    // Thread safety protection
}
```

The HTTPRateLimiter is thread-safe and can be used concurrently across multiple goroutines.

## Constructor

### NewHTTPRateLimiter

```go
func NewHTTPRateLimiter(interval time.Duration) *HTTPRateLimiter
```

Creates a new rate limiter with the specified interval.

**Parameters:**
- `interval` - Minimum time between requests (must be > 0 for effective limiting)

**Returns:**
- `*HTTPRateLimiter` - Configured rate limiter instance

**Example:**
```go
// 1 request per 5 seconds
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// 1 request per 100 milliseconds
fastLimiter := cwe.NewHTTPRateLimiter(100 * time.Millisecond)

// No rate limiting (not recommended)
noLimiter := cwe.NewHTTPRateLimiter(0)
```

## Core Methods

### WaitForRequest

```go
func (l *HTTPRateLimiter) WaitForRequest()
```

Blocks until it's safe to send the next request according to the rate limit.

**Behavior:**
- If sufficient time has passed since the last request, returns immediately
- If not enough time has passed, blocks until the interval is satisfied
- Updates the last request timestamp
- Thread-safe for concurrent use

**Example:**
```go
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

for i := 0; i < 5; i++ {
    limiter.WaitForRequest()
    
    // Make HTTP request
    resp, err := http.Get("https://api.example.com/data")
    if err != nil {
        log.Printf("Request %d failed: %v", i+1, err)
        continue
    }
    defer resp.Body.Close()
    
    fmt.Printf("Request %d completed: %d\n", i+1, resp.StatusCode)
}
```

### GetInterval

```go
func (l *HTTPRateLimiter) GetInterval() time.Duration
```

Returns the current rate limiting interval.

**Returns:**
- `time.Duration` - Current interval between requests

**Example:**
```go
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
interval := limiter.GetInterval()
fmt.Printf("Current rate limit: 1 request per %v\n", interval)
```

### SetInterval

```go
func (l *HTTPRateLimiter) SetInterval(interval time.Duration)
```

Updates the rate limiting interval.

**Parameters:**
- `interval` - New interval between requests

**Thread Safety:**
- Safe to call from multiple goroutines
- Changes take effect immediately for subsequent requests

**Example:**
```go
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// Dynamically adjust based on conditions
if serverBusy {
    limiter.SetInterval(10 * time.Second) // Slow down
} else {
    limiter.SetInterval(2 * time.Second)  // Speed up
}
```

### ResetLastRequest

```go
func (l *HTTPRateLimiter) ResetLastRequest()
```

Resets the last request timestamp, allowing the next request to proceed immediately.

**Use Cases:**
- Error recovery scenarios
- Configuration changes
- Manual intervention for immediate requests

**Example:**
```go
limiter := cwe.NewHTTPRateLimiter(10 * time.Second)

// Make a request
limiter.WaitForRequest()
resp, err := http.Get("https://api.example.com/data")

if err != nil {
    // Reset on error to allow immediate retry
    limiter.ResetLastRequest()
    
    // Immediate retry
    limiter.WaitForRequest() // Returns immediately
    resp, err = http.Get("https://api.example.com/data")
}
```

## Global Instances

### DefaultRateLimiter

```go
var DefaultRateLimiter = NewHTTPRateLimiter(10 * time.Second)
```

Default rate limiter instance with 10-second intervals.

## Usage Examples

### Basic Rate Limiting

```go
// Create rate limiter
limiter := cwe.NewHTTPRateLimiter(3 * time.Second)

// Make rate-limited requests
urls := []string{
    "https://api.example.com/endpoint1",
    "https://api.example.com/endpoint2",
    "https://api.example.com/endpoint3",
}

for i, url := range urls {
    fmt.Printf("Making request %d...\n", i+1)
    
    // Wait for rate limit
    limiter.WaitForRequest()
    
    // Make request
    start := time.Now()
    resp, err := http.Get(url)
    if err != nil {
        log.Printf("Request failed: %v", err)
        continue
    }
    defer resp.Body.Close()
    
    fmt.Printf("Request %d completed in %v\n", i+1, time.Since(start))
}
```

### Adaptive Rate Limiting

```go
limiter := cwe.NewHTTPRateLimiter(1 * time.Second)

for i := 0; i < 10; i++ {
    limiter.WaitForRequest()
    
    resp, err := http.Get("https://api.example.com/data")
    if err != nil {
        log.Printf("Request failed: %v", err)
        continue
    }
    defer resp.Body.Close()
    
    switch resp.StatusCode {
    case 200:
        // Success - can speed up slightly
        current := limiter.GetInterval()
        if current > 500*time.Millisecond {
            limiter.SetInterval(current - 100*time.Millisecond)
        }
        
    case 429: // Too Many Requests
        // Slow down significantly
        current := limiter.GetInterval()
        limiter.SetInterval(current * 2)
        fmt.Printf("Rate limited! Slowing down to %v\n", limiter.GetInterval())
        
    case 500, 502, 503, 504:
        // Server error - slow down moderately
        current := limiter.GetInterval()
        limiter.SetInterval(current + 1*time.Second)
    }
}
```

### Concurrent Usage

```go
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// Multiple goroutines sharing the same rate limiter
var wg sync.WaitGroup
for i := 0; i < 5; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        
        for j := 0; j < 3; j++ {
            limiter.WaitForRequest()
            
            fmt.Printf("Goroutine %d, request %d at %v\n", 
                id, j+1, time.Now().Format("15:04:05.000"))
            
            // Simulate request
            time.Sleep(100 * time.Millisecond)
        }
    }(i)
}

wg.Wait()
```

### Integration with HTTP Client

```go
// Custom HTTP client with rate limiting
type RateLimitedClient struct {
    client  *http.Client
    limiter *cwe.HTTPRateLimiter
}

func NewRateLimitedClient(interval time.Duration) *RateLimitedClient {
    return &RateLimitedClient{
        client:  &http.Client{Timeout: 30 * time.Second},
        limiter: cwe.NewHTTPRateLimiter(interval),
    }
}

func (c *RateLimitedClient) Get(url string) (*http.Response, error) {
    c.limiter.WaitForRequest()
    return c.client.Get(url)
}

func (c *RateLimitedClient) Post(url string, body io.Reader) (*http.Response, error) {
    c.limiter.WaitForRequest()
    return c.client.Post(url, "application/json", body)
}

// Usage
client := NewRateLimitedClient(5 * time.Second)
resp, err := client.Get("https://api.example.com/data")
```

### Rate Limiting with Context

```go
func makeRequestWithTimeout(limiter *cwe.HTTPRateLimiter, url string, timeout time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    // Wait for rate limit with context
    done := make(chan struct{})
    go func() {
        limiter.WaitForRequest()
        close(done)
    }()
    
    select {
    case <-done:
        // Rate limit satisfied, make request
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
            return err
        }
        
        resp, err := http.DefaultClient.Do(req)
        if err != nil {
            return err
        }
        defer resp.Body.Close()
        
        fmt.Printf("Request completed: %d\n", resp.StatusCode)
        return nil
        
    case <-ctx.Done():
        return ctx.Err()
    }
}

// Usage
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
err := makeRequestWithTimeout(limiter, "https://api.example.com/data", 10*time.Second)
if err != nil {
    log.Printf("Request failed: %v", err)
}
```

### Monitoring Rate Limiter

```go
func monitorRateLimiter(limiter *cwe.HTTPRateLimiter) {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            interval := limiter.GetInterval()
            fmt.Printf("Current rate limit: 1 request per %v\n", interval)
        }
    }
}

// Start monitoring in background
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
go monitorRateLimiter(limiter)

// Use limiter for requests
for i := 0; i < 5; i++ {
    limiter.WaitForRequest()
    // Make request...
    
    // Adjust rate limiting based on some condition
    if i == 2 {
        limiter.SetInterval(2 * time.Second)
    }
}
```

## Performance Considerations

- **Blocking Behavior**: `WaitForRequest()` blocks the calling goroutine
- **Memory Usage**: Minimal memory footprint
- **CPU Usage**: Low CPU overhead, mainly time calculations
- **Precision**: Uses `time.Sleep()` for delays, subject to OS scheduling precision

## Thread Safety

- ✅ **All Methods**: Thread-safe with internal mutex protection
- ✅ **Concurrent Access**: Multiple goroutines can safely share a single instance
- ✅ **Configuration Changes**: Safe to modify interval during operation
- ✅ **State Consistency**: Guaranteed consistent state across concurrent operations

## Best Practices

1. **Choose Appropriate Intervals**: Balance between API limits and application performance
2. **Monitor API Responses**: Adjust rate limiting based on server responses (429, 503, etc.)
3. **Error Handling**: Consider resetting on certain error conditions
4. **Resource Cleanup**: Rate limiters don't require explicit cleanup
5. **Testing**: Use shorter intervals in tests to speed up execution
