# Examples

This section provides practical examples demonstrating how to use the CWE Go library for various tasks. Each example includes complete, runnable code with explanations.

## Available Examples

### [Basic Usage](./basic-usage)
Learn the fundamentals of using the CWE library:
- Creating API clients
- Fetching CWE data
- Working with CWE structures
- Basic error handling

### [Fetching CWE Data](./fetch-cwe)
Comprehensive guide to data fetching:
- Getting version information
- Fetching individual weaknesses, categories, and views
- Batch operations
- Working with relationships

### [Building Trees](./build-tree)
Build and work with CWE hierarchical structures:
- Creating tree structures from views
- Recursive data fetching
- Tree traversal and analysis
- Working with parent-child relationships

### [Search & Filter](./search-filter)
Search and filter CWE data effectively:
- Name-based searching
- Description filtering
- Severity-based filtering
- Custom search criteria

### [Export & Import](./export-import)
Data persistence and serialization:
- JSON export/import
- XML serialization
- Registry management
- Data backup and restore

### [Rate Limited Client](./rate-limited)
Advanced HTTP client usage:
- Custom rate limiting
- Retry strategies
- Error handling
- Performance optimization

## Quick Start Example

Here's a simple example to get you started:

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // Create a new API client
    client := cwe.NewAPIClient()
    
    // Get the current CWE version
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }
    
    fmt.Printf("CWE Version: %s\n", version.Version)
    fmt.Printf("Release Date: %s\n", version.ReleaseDate)
    
    // Fetch a specific weakness
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("Failed to get weakness: %v", err)
    }
    
    fmt.Printf("\nCWE-79: %s\n", weakness.Name)
    fmt.Printf("Description: %s\n", weakness.Description)
}
```

## Running Examples

All examples in this documentation are based on the actual example programs in the `examples/` directory of the repository. You can run them directly:

```bash
# Clone the repository
git clone https://github.com/scagogogo/cwe.git
cd cwe

# Run a specific example
go run examples/01_basic_usage/main.go
go run examples/02_fetch_cwe/main.go
go run examples/03_build_tree/main.go

# Or use the example runner
go run examples/run_examples.go basic_usage
go run examples/run_examples.go fetch_cwe
```

## Common Patterns

### Error Handling

```go
weakness, err := client.GetWeakness("79")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "not found"):
        fmt.Println("CWE not found")
    case strings.Contains(err.Error(), "timeout"):
        fmt.Println("Request timed out")
    case strings.Contains(err.Error(), "rate limit"):
        fmt.Println("Rate limit exceeded")
    default:
        fmt.Printf("Unknown error: %v\n", err)
    }
    return
}
```

### Rate Limiting

```go
// Create client with custom rate limiting
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)
client := cwe.NewAPIClientWithOptions("", 0, limiter)

// Adjust rate limiting dynamically
client.GetRateLimiter().SetInterval(2 * time.Second)
```

### Batch Processing

```go
// Fetch multiple CWEs efficiently
ids := []string{"79", "89", "287", "22", "78"}
cweMap, err := client.GetCWEs(ids)
if err != nil {
    log.Fatal(err)
}

for id, weakness := range cweMap {
    fmt.Printf("%s: %s\n", id, weakness.Name)
}
```

### Working with Registries

```go
// Create and populate registry
registry := cwe.NewRegistry()

// Add CWEs
for id, weakness := range cweMap {
    cweInstance := &cwe.CWE{
        ID:          id,
        Name:        weakness.Name,
        Description: weakness.Description,
        URL:         weakness.URL,
    }
    registry.Register(cweInstance)
}

// Search within registry
results := registry.SearchByName("injection")
fmt.Printf("Found %d injection-related CWEs\n", len(results))
```

## Best Practices

### 1. Use Data Fetcher for High-Level Operations

```go
// Prefer DataFetcher over direct API client for most use cases
fetcher := cwe.NewDataFetcher()
cwe, err := fetcher.FetchWeakness("79")
```

### 2. Handle Rate Limiting Appropriately

```go
// For production use, consider longer intervals
limiter := cwe.NewHTTPRateLimiter(10 * time.Second)
client := cwe.NewAPIClientWithOptions("", 0, limiter)
```

### 3. Cache Frequently Used Data

```go
// Cache version information
var cachedVersion *cwe.VersionResponse
var versionCacheTime time.Time

func getVersion(client *cwe.APIClient) (*cwe.VersionResponse, error) {
    if cachedVersion != nil && time.Since(versionCacheTime) < 24*time.Hour {
        return cachedVersion, nil
    }
    
    version, err := client.GetVersion()
    if err != nil {
        return nil, err
    }
    
    cachedVersion = version
    versionCacheTime = time.Now()
    return version, nil
}
```

### 4. Use Context for Timeouts

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Use context-aware methods when available
resp, err := client.GetWithContext(ctx, url)
```

### 5. Graceful Error Recovery

```go
func fetchWithRetry(client *cwe.APIClient, id string, maxRetries int) (*cwe.CWEWeakness, error) {
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        weakness, err := client.GetWeakness(id)
        if err == nil {
            return weakness, nil
        }
        
        lastErr = err
        
        // Exponential backoff
        time.Sleep(time.Duration(1<<i) * time.Second)
    }
    
    return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}
```

## Testing Examples

When writing tests for code using the CWE library:

```go
func TestCWEFetching(t *testing.T) {
    // Use a custom client with shorter timeouts for tests
    client := cwe.NewAPIClientWithOptions(
        "",
        5*time.Second,
        cwe.NewHTTPRateLimiter(100*time.Millisecond),
    )
    
    weakness, err := client.GetWeakness("79")
    if err != nil {
        t.Fatalf("Failed to fetch CWE-79: %v", err)
    }
    
    if weakness.ID != "CWE-79" {
        t.Errorf("Expected ID CWE-79, got %s", weakness.ID)
    }
}
```

## Next Steps

- Start with [Basic Usage](./basic-usage) if you're new to the library
- Check [Fetching CWE Data](./fetch-cwe) for comprehensive data operations
- Explore [Building Trees](./build-tree) for hierarchical data structures
- See the [API Reference](/api/) for detailed documentation
