# API Client

The `APIClient` provides a comprehensive interface for interacting with the CWE REST API. It includes built-in rate limiting, retry logic, and support for all CWE API endpoints.

## APIClient

```go
type APIClient struct {
    client  *HTTPClient // HTTP client with rate limiting
    baseURL string      // API base URL
}
```

The APIClient is thread-safe and can be used concurrently across multiple goroutines.

## Constructors

### NewAPIClient

```go
func NewAPIClient() *APIClient
```

Creates a new API client with default configuration:
- Base URL: `https://cwe-api.mitre.org/api/v1`
- Timeout: 30 seconds
- Rate limit: 1 request per 10 seconds
- Max retries: 3
- Retry interval: 1 second

**Example:**
```go
client := cwe.NewAPIClient()
```

### NewAPIClientWithOptions

```go
func NewAPIClientWithOptions(baseURL string, timeout time.Duration, rateLimiter ...*HTTPRateLimiter) *APIClient
```

Creates a new API client with custom configuration.

**Parameters:**
- `baseURL` - Custom API base URL (empty string uses default)
- `timeout` - HTTP request timeout (≤0 uses default 30s)
- `rateLimiter` - Optional custom rate limiter

**Example:**
```go
// Custom configuration
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
client := cwe.NewAPIClientWithOptions(
    "https://custom-api.example.com/api/v1",
    60 * time.Second,
    limiter,
)
```

## Version Methods

### GetVersion

```go
func (c *APIClient) GetVersion() (*VersionResponse, error)
```

Retrieves the current CWE version information.

**Returns:**
- `*VersionResponse` - Version information
- `error` - Error if request fails

**Example:**
```go
version, err := client.GetVersion()
if err != nil {
    log.Fatalf("Failed to get version: %v", err)
}
fmt.Printf("CWE Version: %s, Release Date: %s\n", 
    version.Version, version.ReleaseDate)
```

## CWE Data Methods

### GetWeakness

```go
func (c *APIClient) GetWeakness(id string) (*CWEWeakness, error)
```

Retrieves a specific weakness by ID.

**Parameters:**
- `id` - CWE ID (with or without "CWE-" prefix)

**Returns:**
- `*CWEWeakness` - Weakness data
- `error` - Error if not found or request fails

**Example:**
```go
weakness, err := client.GetWeakness("79")
if err != nil {
    log.Fatalf("Failed to get weakness: %v", err)
}
fmt.Printf("CWE-79: %s\n", weakness.Name)
```

### GetCategory

```go
func (c *APIClient) GetCategory(id string) (*CWECategory, error)
```

Retrieves a specific category by ID.

**Parameters:**
- `id` - Category ID

**Returns:**
- `*CWECategory` - Category data
- `error` - Error if not found or request fails

### GetView

```go
func (c *APIClient) GetView(id string) (*CWEView, error)
```

Retrieves a specific view by ID.

**Parameters:**
- `id` - View ID

**Returns:**
- `*CWEView` - View data
- `error` - Error if not found or request fails

### GetCWEs

```go
func (c *APIClient) GetCWEs(ids []string) (map[string]*CWEWeakness, error)
```

Retrieves multiple CWEs in a single request.

**Parameters:**
- `ids` - Slice of CWE IDs

**Returns:**
- `map[string]*CWEWeakness` - Map of ID to weakness data
- `error` - Error if request fails

**Example:**
```go
ids := []string{"79", "89", "287"}
cweMap, err := client.GetCWEs(ids)
if err != nil {
    log.Fatalf("Failed to get CWEs: %v", err)
}

for id, weakness := range cweMap {
    fmt.Printf("%s: %s\n", id, weakness.Name)
}
```

## Relationship Methods

### GetParents

```go
func (c *APIClient) GetParents(id string, viewID string) ([]string, error)
```

Retrieves parent CWE IDs for a given CWE.

**Parameters:**
- `id` - CWE ID
- `viewID` - Optional view ID for context

**Returns:**
- `[]string` - Slice of parent CWE IDs
- `error` - Error if request fails

### GetChildren

```go
func (c *APIClient) GetChildren(id string, viewID string) ([]string, error)
```

Retrieves child CWE IDs for a given CWE.

**Parameters:**
- `id` - CWE ID
- `viewID` - Optional view ID for context

**Returns:**
- `[]string` - Slice of child CWE IDs
- `error` - Error if request fails

### GetAncestors

```go
func (c *APIClient) GetAncestors(id string, viewID string) ([]string, error)
```

Retrieves all ancestor CWE IDs for a given CWE.

### GetDescendants

```go
func (c *APIClient) GetDescendants(id string, viewID string) ([]string, error)
```

Retrieves all descendant CWE IDs for a given CWE.

## Rate Limiting Methods

### GetRateLimiter

```go
func (c *APIClient) GetRateLimiter() *HTTPRateLimiter
```

Returns the current rate limiter instance.

### SetRateLimiter

```go
func (c *APIClient) SetRateLimiter(limiter *HTTPRateLimiter)
```

Sets a new rate limiter for the client.

**Example:**
```go
// Get current limiter and modify
limiter := client.GetRateLimiter()
limiter.SetInterval(2 * time.Second)

// Or set a new limiter
newLimiter := cwe.NewHTTPRateLimiter(5 * time.Second)
client.SetRateLimiter(newLimiter)
```

## Error Handling

The API client returns detailed errors for different scenarios:

```go
weakness, err := client.GetWeakness("invalid-id")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "404"):
        fmt.Println("CWE not found")
    case strings.Contains(err.Error(), "timeout"):
        fmt.Println("Request timed out")
    case strings.Contains(err.Error(), "rate limit"):
        fmt.Println("Rate limit exceeded")
    default:
        fmt.Printf("Unknown error: %v\n", err)
    }
}
```

## Usage Examples

### Basic Usage

```go
// Create client
client := cwe.NewAPIClient()

// Get version
version, err := client.GetVersion()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("CWE Version: %s\n", version.Version)

// Get specific weakness
xss, err := client.GetWeakness("79")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("XSS: %s\n", xss.Name)
```

### Batch Operations

```go
// Get multiple CWEs
ids := []string{"79", "89", "287", "22", "78"}
cweMap, err := client.GetCWEs(ids)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Retrieved %d CWEs:\n", len(cweMap))
for id, cwe := range cweMap {
    fmt.Printf("  %s: %s\n", id, cwe.Name)
}
```

### Exploring Relationships

```go
// Get children of a category
children, err := client.GetChildren("1000", "")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("CWE-1000 has %d children:\n", len(children))
for _, childID := range children {
    fmt.Printf("  - %s\n", childID)
}
```

### Custom Rate Limiting

```go
// Create client with custom rate limiting
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)
client := cwe.NewAPIClientWithOptions("", 0, limiter)

// Dynamically adjust rate limiting
client.GetRateLimiter().SetInterval(5 * time.Second)
```

## Performance Considerations

- **Rate Limiting**: Default 10-second intervals between requests
- **Batch Requests**: Use `GetCWEs()` for multiple items
- **Caching**: Consider caching responses for frequently accessed data
- **Concurrent Usage**: Client is thread-safe but shares rate limiter across goroutines
