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
// Output: Creates a new HTTP client with default settings

// Custom configuration
client := cwe.NewHttpClient(
    cwe.WithMaxRetries(5),
    cwe.WithRetryInterval(2 * time.Second),
    cwe.WithRateLimit(0.5), // 1 request per 2 seconds
)
// Output: Creates a client with 5 retries, 2s retry delay, and 0.5 requests/sec rate limit
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
// Output: Creates a client with custom HTTP client, 5s rate limit, 3 retries, and 1s delay
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
// Output: Sends GET request and reads response body
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
// Output: Sends POST request with JSON data
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
    log.Fatalf("POST form request failed: %v", err)
}
defer resp.Body.Close()
// Output: Sends POST request with form data
```

## Proxy Configuration

### Using HTTP Client with Proxy

```go
import (
    "net/http"
    "net/url"
    "time"
    "github.com/scagogogo/cwe"
)

// Configure proxy URL
proxyURL, err := url.Parse("http://proxy.example.com:8080")
if err != nil {
    log.Fatalf("Failed to parse proxy URL: %v", err)
}

// Create transport with proxy
transport := &http.Transport{
    Proxy: http.ProxyURL(proxyURL),
}

// Create HTTP client with proxy
httpClient := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}

// Create CWE HTTP client
cweClient := cwe.NewHttpClient(
    cwe.WithMaxRetries(3),
    cwe.WithRetryInterval(time.Second),
    cwe.WithRateLimit(1), // 1 request per second
)

// Set the custom HTTP client with proxy
cweClient.SetClient(httpClient)

// Use the client to make requests through proxy
resp, err := cweClient.Get(context.Background(), "https://cwe-api.mitre.org/api/v1/version")
if err != nil {
    log.Fatalf("Request failed: %v", err)
}
defer resp.Body.Close()

// Output: Makes request through proxy server and returns response
```

## Rate Limiting

### Custom Rate Limiting

```go
// Create client with custom rate limiting
client := cwe.NewHttpClient(
    cwe.WithRateLimit(2), // 2 requests per second
)
// Output: Creates client with 2 requests per second rate limit

// Adjust rate limit dynamically
client.GetRateLimiter().SetInterval(5 * time.Second)
// Output: Updates rate limit to 1 request per 5 seconds
```

## Error Handling

### Handling Network Errors

```go
resp, err := client.Get(ctx, "https://api.example.com/data")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "timeout"):
        log.Println("Request timed out")
        // Output: Handles timeout errors
    case strings.Contains(err.Error(), "connection refused"):
        log.Println("Connection refused")
        // Output: Handles connection refused errors
    default:
        log.Printf("Network error: %v", err)
        // Output: Handles other network errors
    }
    return
}
defer resp.Body.Close()
```

## Thread Safety

The HTTPClient is thread-safe and can be used across multiple goroutines:

```go
var wg sync.WaitGroup

// Make concurrent requests
for i := 0; i < 5; i++ {
    wg.Add(1)
    go func(requestID int) {
        defer wg.Done()
        
        resp, err := client.Get(ctx, fmt.Sprintf("https://api.example.com/data/%d", requestID))
        if err != nil {
            log.Printf("Request %d failed: %v", requestID, err)
            return
        }
        defer resp.Body.Close()
        
        // Process response
        log.Printf("Request %d completed with status %d", requestID, resp.StatusCode)
    }(i)
}

wg.Wait()
// Output: Executes 5 concurrent requests with proper synchronization
```