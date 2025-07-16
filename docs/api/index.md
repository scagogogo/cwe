# API Reference

The CWE Go library provides a comprehensive set of APIs for working with Common Weakness Enumeration (CWE) data. This documentation covers all public types, functions, and methods available in the library.

## Overview

The library is organized into several key components:

### Core Components

- **[Core Types](./core-types)** - Basic data structures and models
- **[API Client](./api-client)** - REST API client for CWE data
- **[Data Fetcher](./data-fetcher)** - High-level data fetching interface
- **[Registry](./registry)** - CWE collection management
- **[HTTP Client](./http-client)** - Rate-limited HTTP client
- **[Rate Limiter](./rate-limiter)** - Request rate limiting
- **[Search & Utils](./search-utils)** - Search and utility functions
- **[Tree Operations](./tree)** - Tree building and traversal

## Package Constants

```go
const (
    // BaseURL is the root URL for CWE REST API
    BaseURL = "https://cwe-api.mitre.org/api/v1"
    
    // DefaultTimeout is the default HTTP request timeout
    DefaultTimeout = 30 * time.Second
)
```

## Quick Reference

### Creating Clients

```go
// Create default API client
client := cwe.NewAPIClient()

// Create API client with custom options
client := cwe.NewAPIClientWithOptions(
    "https://custom-api.example.com/api/v1",
    60 * time.Second,
    cwe.NewHTTPRateLimiter(5 * time.Second),
)

// Create data fetcher
fetcher := cwe.NewDataFetcher()
```

### Basic Operations

```go
// Get CWE version
version, err := client.GetVersion()

// Get a specific weakness
weakness, err := client.GetWeakness("79")

// Get multiple CWEs
cweMap, err := client.GetCWEs([]string{"79", "89", "287"})

// Fetch and convert to local structure
cwe, err := fetcher.FetchWeakness("79")
```

### Registry Operations

```go
// Create registry
registry := cwe.NewRegistry()

// Register CWE
err := registry.Register(cweInstance)

// Get by ID
cwe, exists := registry.GetByID("CWE-79")

// Export to JSON
jsonData, err := registry.ExportToJSON()
```

### Rate Limiting

```go
// Create rate limiter
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// Wait for request
limiter.WaitForRequest()

// Set new interval
limiter.SetInterval(2 * time.Second)
```

## Error Handling

All API methods return errors that should be checked:

```go
weakness, err := client.GetWeakness("79")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "not found"):
        log.Printf("CWE not found: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Request timeout: %v", err)
    default:
        log.Printf("Unknown error: %v", err)
    }
    return
}
```

## Thread Safety

Most components in the library are thread-safe:

- ✅ **APIClient** - Thread-safe, can be used concurrently
- ✅ **HTTPClient** - Thread-safe with internal synchronization
- ✅ **HTTPRateLimiter** - Thread-safe with mutex protection
- ✅ **Registry** - Thread-safe for read operations
- ⚠️ **CWE** - Not thread-safe for modifications
- ⚠️ **TreeNode** - Not thread-safe for modifications

## Performance Considerations

- **Rate Limiting**: All API requests are rate-limited by default (10 seconds per request)
- **Retry Logic**: Failed requests are automatically retried up to 3 times
- **Memory Usage**: Large CWE trees may consume significant memory
- **Concurrent Access**: Use separate client instances for high-concurrency scenarios

## Next Steps

- Explore [Core Types](./core-types) to understand the data structures
- Check [API Client](./api-client) for REST API operations
- See [Examples](/examples/) for practical usage patterns
