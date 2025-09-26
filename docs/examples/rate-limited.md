# Rate Limited Client

This example demonstrates advanced usage of the rate-limited HTTP client, including custom configurations, adaptive rate limiting, and performance optimization strategies.

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "strings"
    "sync"
    "time"
    
    "github.com/scagogogo/cwe"
)

func main() {
    fmt.Println("==== Rate Limited Client Example ====")
    
    // 1. Basic rate limiting
    fmt.Println("\n1. Basic Rate Limiting")
    basicRateLimitingExample()
    
    // 2. Custom rate limiting configuration
    fmt.Println("\n2. Custom Rate Limiting Configuration")
    customConfigurationExample()
    
    // 3. Adaptive rate limiting
    fmt.Println("\n3. Adaptive Rate Limiting")
    adaptiveRateLimitingExample()
    
    // 4. Concurrent usage with rate limiting
    fmt.Println("\n4. Concurrent Usage")
    concurrentUsageExample()
    
    // 5. Rate limiting with error handling
    fmt.Println("\n5. Error Handling and Recovery")
    errorHandlingExample()
    
    // 6. Performance monitoring
    fmt.Println("\n6. Performance Monitoring")
    performanceMonitoringExample()
    
    fmt.Println("\n==== Rate Limited Client Example Complete ====")
}

func basicRateLimitingExample() {
    // Create client with default rate limiting (10 seconds)
    client := cwe.NewAPIClient()
    
    fmt.Printf("Default rate limit: %v\n", client.GetRateLimiter().GetInterval())
    // Output: Default rate limit: 10s
    
    // Make a few requests to demonstrate rate limiting
    start := time.Now()
    
    for i := 0; i < 3; i++ {
        fmt.Printf("Making request %d at %v\n", i+1, time.Since(start))
        
        version, err := client.GetVersion()
        if err != nil {
            log.Printf("Request %d failed: %v", i+1, err)
            continue
        }
        
        fmt.Printf("  Response: CWE version %s\n", version.Version)
        // Output: Response: CWE version 4.12
    }
    
    fmt.Printf("Total time: %v\n", time.Since(start))
    // Output: Total time: 20.045s (approximately, due to 10s rate limit between requests)
}

func customConfigurationExample() {
    // Create client with custom rate limiting
    customLimiter := cwe.NewHTTPRateLimiter(2 * time.Second)
    client := cwe.NewAPIClientWithOptions(
        "",                    // Default base URL
        30 * time.Second,      // 30-second timeout
        customLimiter,         // Custom rate limiter
    )
    
    fmt.Printf("Custom rate limit: %v\n", client.GetRateLimiter().GetInterval())
    // Output: Custom rate limit: 2s
    
    // Demonstrate faster requests
    start := time.Now()
    
    ids := []string{"79", "89", "287"}
    for i, id := range ids {
        fmt.Printf("Fetching CWE-%s at %v\n", id, time.Since(start))
        
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("Failed to fetch CWE-%s: %v", id, err)
            continue
        }
        
        fmt.Printf("  CWE-%s: %s\n", id, weakness.Name)
        // Output: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    }
    
    fmt.Printf("Total time: %v\n", time.Since(start))
    // Output: Total time: 4.023s (approximately, due to 2s rate limit between requests)
}

func adaptiveRateLimitingExample() {
    client := cwe.NewAPIClient()
    limiter := client.GetRateLimiter()
    
    // Start with aggressive rate limiting
    limiter.SetInterval(1 * time.Second)
    
    fmt.Printf("Starting with %v interval\n", limiter.GetInterval())
    // Output: Starting with 1s interval
    
    // Simulate adaptive behavior based on responses
    testIDs := []string{"79", "89", "287", "22", "78"}
    
    for i, id := range testIDs {
        start := time.Now()
        weakness, err := client.GetWeakness(id)
        requestTime := time.Since(start)
        
        if err != nil {
            // Error occurred - slow down
            currentInterval := limiter.GetInterval()
            newInterval := currentInterval * 2
            limiter.SetInterval(newInterval)
            
            fmt.Printf("Request %d failed, slowing down to %v\n", i+1, newInterval)
            // Output: Request 1 failed, slowing down to 2s
            continue
        }
        
        fmt.Printf("Request %d succeeded in %v\n", i+1, requestTime)
        // Output: Request 1 succeeded in 1.234s
        
        // Success - can potentially speed up
        if requestTime < 500*time.Millisecond {
            currentInterval := limiter.GetInterval()
            if currentInterval > 500*time.Millisecond {
                newInterval := currentInterval - 200*time.Millisecond
                limiter.SetInterval(newInterval)
                fmt.Printf("  Speeding up to %v\n", newInterval)
                // Output: Speeding up to 800ms
            }
        }
        
        fmt.Printf("  CWE-%s: %s\n", id, weakness.Name)
        // Output: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    }
}

func concurrentUsageExample() {
    client := cwe.NewAPIClient()
    
    // Set moderate rate limiting for concurrent usage
    client.GetRateLimiter().SetInterval(3 * time.Second)
    
    var wg sync.WaitGroup
    results := make(chan string, 5)
    
    ids := []string{"79", "89", "287", "22", "78"}
    
    fmt.Printf("Starting %d concurrent requests with %v rate limit\n", 
        len(ids), client.GetRateLimiter().GetInterval())
    // Output: Starting 5 concurrent requests with 3s rate limit
    
    start := time.Now()
    
    for i, id := range ids {
        wg.Add(1)
        go func(goroutineID int, cweID string) {
            defer wg.Done()
            
            requestStart := time.Now()
            weakness, err := client.GetWeakness(cweID)
            requestTime := time.Since(requestStart)
            
            if err != nil {
                results <- fmt.Sprintf("Goroutine %d: CWE-%s failed after %v: %v", 
                    goroutineID, cweID, requestTime, err)
                // Output: Goroutine 1: CWE-79 failed after 1.234s: [error details]
                return
            }
            
            results <- fmt.Sprintf("Goroutine %d: CWE-%s completed in %v: %s", 
                goroutineID, cweID, requestTime, weakness.Name)
            // Output: Goroutine 1: CWE-79 completed in 1.234s: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
        }(i+1, id)
    }
    
    // Close results channel when all goroutines complete
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // Print results as they come in
    for result := range results {
        fmt.Printf("  %s\n", result)
    }
    
    fmt.Printf("All concurrent requests completed in %v\n", time.Since(start))
    // Output: All concurrent requests completed in 15.678s (approximately)
}

func errorHandlingExample() {
    client := cwe.NewAPIClient()
    
    // Test with invalid CWE ID to demonstrate error handling
    _, err := client.GetWeakness("invalid-id")
    if err != nil {
        fmt.Printf("Expected error for invalid ID: %v\n", err)
        // Output: Expected error for invalid ID: [error details]
        
        // Check if it's a rate limit error
        if strings.Contains(err.Error(), "rate limit") {
            fmt.Println("Rate limit error detected")
            // Output: Rate limit error detected
        }
    }
    
    // Demonstrate successful request after error
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("Failed to get weakness after error: %v", err)
    }
    
    fmt.Printf("Successfully retrieved CWE-79: %s\n", weakness.Name)
    // Output: Successfully retrieved CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
}

func performanceMonitoringExample() {
    client := cwe.NewAPIClient()
    
    // Track request performance
    var totalRequests int
    var totalTime time.Duration
    var errors int
    
    ids := []string{"79", "89", "287", "22", "78"}
    
    for _, id := range ids {
        start := time.Now()
        _, err := client.GetWeakness(id)
        duration := time.Since(start)
        
        totalRequests++
        totalTime += duration
        
        if err != nil {
            errors++
            fmt.Printf("Request for CWE-%s failed after %v: %v\n", id, duration, err)
            // Output: Request for CWE-79 failed after 1.234s: [error details]
            continue
        }
        
        fmt.Printf("Request for CWE-%s completed in %v\n", id, duration)
        // Output: Request for CWE-79 completed in 1.234s
    }
    
    avgTime := totalTime / time.Duration(totalRequests)
    successRate := float64(totalRequests-errors) / float64(totalRequests) * 100
    
    fmt.Printf("\nPerformance Summary:\n")
    fmt.Printf("  Total requests: %d\n", totalRequests)
    // Output: Total requests: 5
    fmt.Printf("  Average response time: %v\n", avgTime)
    // Output: Average response time: 1.234s
    fmt.Printf("  Success rate: %.1f%%\n", successRate)
    // Output: Success rate: 100.0%
    fmt.Printf("  Errors: %d\n", errors)
    // Output: Errors: 0
}
```

## Key Concepts

### Rate Limiting Strategies

1. **Fixed Rate Limiting** - Consistent delay between requests
2. **Adaptive Rate Limiting** - Adjust based on response times and errors
3. **Concurrency Control** - Manage multiple simultaneous requests

### Best Practices

1. **Start Conservative** - Begin with slower rates and increase as needed
2. **Monitor Performance** - Track request times and success rates
3. **Handle Errors Gracefully** - Implement retry logic and error recovery
4. **Respect API Limits** - Avoid overwhelming the target server

### Common Patterns

```go
// Pattern 1: Simple rate limiting
client := cwe.NewAPIClient()
// Uses default 10-second rate limit

// Pattern 2: Custom rate limiting
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)
client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)

// Pattern 3: Adaptive rate limiting
func adaptiveClient() *cwe.APIClient {
    client := cwe.NewAPIClient()
    
    // Monitor responses and adjust rate limit
    go func() {
        for {
            // Check response times and error rates
            // Adjust rate limit accordingly
            time.Sleep(1 * time.Minute)
        }
    }()
    
    return client
}
```


## Advanced Rate Limiting Patterns

### Circuit Breaker Pattern

```go
type CircuitBreaker struct {
    client       *cwe.APIClient
    failureCount int
    maxFailures  int
    resetTimeout time.Duration
    lastFailure  time.Time
    state        string // "closed", "open", "half-open"
    mutex        sync.Mutex
}

func NewCircuitBreaker(client *cwe.APIClient, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
    return &CircuitBreaker{
        client:       client,
        maxFailures:  maxFailures,
        resetTimeout: resetTimeout,
        state:        "closed",
    }
}

func (cb *CircuitBreaker) GetWeakness(id string) (*cwe.CWEWeakness, error) {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    // Check if circuit should be reset
    if cb.state == "open" && time.Since(cb.lastFailure) > cb.resetTimeout {
        cb.state = "half-open"
        cb.failureCount = 0
    }
    
    // Reject requests if circuit is open
    if cb.state == "open" {
        return nil, fmt.Errorf("circuit breaker is open")
    }
    
    // Make request
    weakness, err := cb.client.GetWeakness(id)
    
    if err != nil {
        cb.failureCount++
        cb.lastFailure = time.Now()
        
        if cb.failureCount >= cb.maxFailures {
            cb.state = "open"
        }
        
        return nil, err
    }
    
    // Success - reset failure count
    cb.failureCount = 0
    if cb.state == "half-open" {
        cb.state = "closed"
    }
    
    return weakness, nil
}
```

### Exponential Backoff

```go
func fetchWithExponentialBackoff(client *cwe.APIClient, id string, maxRetries int) (*cwe.CWEWeakness, error) {
    var lastErr error
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        weakness, err := client.GetWeakness(id)
        if err == nil {
            return weakness, nil
        }
        
        lastErr = err
        
        // Calculate backoff delay
        backoffDelay := time.Duration(1<<attempt) * time.Second
        if backoffDelay > 30*time.Second {
            backoffDelay = 30 * time.Second
        }
        
        fmt.Printf("Attempt %d failed, backing off for %v: %v\n", 
            attempt+1, backoffDelay, err)
        
        time.Sleep(backoffDelay)
    }
    
    return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}
```

### Adaptive Rate Limiting

```go
type AdaptiveRateLimiter struct {
    client           *cwe.APIClient
    baseInterval     time.Duration
    currentInterval  time.Duration
    successCount     int
    errorCount       int
    adjustmentFactor float64
    mutex            sync.Mutex
}

func NewAdaptiveRateLimiter(client *cwe.APIClient, baseInterval time.Duration) *AdaptiveRateLimiter {
    return &AdaptiveRateLimiter{
        client:           client,
        baseInterval:     baseInterval,
        currentInterval:  baseInterval,
        adjustmentFactor: 1.5,
    }
}

func (arl *AdaptiveRateLimiter) GetWeakness(id string) (*cwe.CWEWeakness, error) {
    arl.mutex.Lock()
    defer arl.mutex.Unlock()
    
    // Apply current rate limiting
    arl.client.GetRateLimiter().SetInterval(arl.currentInterval)
    
    weakness, err := arl.client.GetWeakness(id)
    
    if err != nil {
        arl.errorCount++
        
        // Increase interval on error
        arl.currentInterval = time.Duration(float64(arl.currentInterval) * arl.adjustmentFactor)
        if arl.currentInterval > 60*time.Second {
            arl.currentInterval = 60 * time.Second
        }
        
        return nil, err
    }
    
    arl.successCount++
    
    // Decrease interval on success (but not below base)
    if arl.successCount%5 == 0 { // Adjust every 5 successes
        arl.currentInterval = time.Duration(float64(arl.currentInterval) / arl.adjustmentFactor)
        if arl.currentInterval < arl.baseInterval {
            arl.currentInterval = arl.baseInterval
        }
    }
    
    return weakness, nil
}
```

## Running the Example

```bash
go run main.go
```

Expected output shows different rate limiting behaviors, timing information, and performance metrics.

## Best Practices

1. **Start Conservative**: Begin with longer intervals and adjust based on API behavior
2. **Monitor Performance**: Track success rates and response times
3. **Handle Errors Gracefully**: Implement backoff strategies for failures
4. **Use Circuit Breakers**: Prevent cascading failures in distributed systems
5. **Consider Concurrent Usage**: Account for multiple goroutines sharing rate limiters

## Next Steps

- Review all [Examples](./index) for comprehensive usage patterns
- Check the [API Reference](/api/) for detailed rate limiting documentation
- Explore [Building Trees](./build-tree) for large-scale data operations
