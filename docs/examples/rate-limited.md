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
    }
    
    fmt.Printf("Total time: %v\n", time.Since(start))
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
    }
    
    fmt.Printf("Total time: %v\n", time.Since(start))
}

func adaptiveRateLimitingExample() {
    client := cwe.NewAPIClient()
    limiter := client.GetRateLimiter()
    
    // Start with aggressive rate limiting
    limiter.SetInterval(1 * time.Second)
    
    fmt.Printf("Starting with %v interval\n", limiter.GetInterval())
    
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
            continue
        }
        
        fmt.Printf("Request %d succeeded in %v\n", i+1, requestTime)
        
        // Success - can potentially speed up
        if requestTime < 500*time.Millisecond {
            currentInterval := limiter.GetInterval()
            if currentInterval > 500*time.Millisecond {
                newInterval := currentInterval - 200*time.Millisecond
                limiter.SetInterval(newInterval)
                fmt.Printf("  Speeding up to %v\n", newInterval)
            }
        }
        
        fmt.Printf("  CWE-%s: %s\n", id, weakness.Name)
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
                return
            }
            
            results <- fmt.Sprintf("Goroutine %d: CWE-%s completed in %v: %s", 
                goroutineID, cweID, requestTime, weakness.Name)
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
}

func errorHandlingExample() {
    client := cwe.NewAPIClient()
    
    // Set aggressive rate limiting to potentially trigger errors
    client.GetRateLimiter().SetInterval(500 * time.Millisecond)
    
    // Try to fetch some invalid CWEs to demonstrate error handling
    testCases := []struct {
        id          string
        expectError bool
    }{
        {"79", false},        // Valid CWE
        {"99999", true},      // Invalid CWE
        {"89", false},        // Valid CWE
        {"invalid", true},    // Invalid format
        {"287", false},       // Valid CWE
    }
    
    successCount := 0
    errorCount := 0
    
    for i, testCase := range testCases {
        fmt.Printf("Test %d: Fetching CWE-%s\n", i+1, testCase.id)
        
        weakness, err := client.GetWeakness(testCase.id)
        
        if err != nil {
            errorCount++
            fmt.Printf("  Error (expected: %v): %v\n", testCase.expectError, err)
            
            // Implement error recovery
            if strings.Contains(err.Error(), "rate limit") {
                // Rate limit hit - slow down
                currentInterval := client.GetRateLimiter().GetInterval()
                newInterval := currentInterval * 2
                client.GetRateLimiter().SetInterval(newInterval)
                fmt.Printf("  Rate limit detected, slowing down to %v\n", newInterval)
            } else if strings.Contains(err.Error(), "timeout") {
                // Timeout - reset rate limiter
                client.GetRateLimiter().ResetLastRequest()
                fmt.Printf("  Timeout detected, resetting rate limiter\n")
            }
        } else {
            successCount++
            fmt.Printf("  Success: %s\n", weakness.Name)
        }
    }
    
    fmt.Printf("Results: %d successes, %d errors\n", successCount, errorCount)
}

func performanceMonitoringExample() {
    client := cwe.NewAPIClient()
    
    // Create performance monitor
    monitor := NewPerformanceMonitor()
    
    // Test different rate limiting intervals
    intervals := []time.Duration{
        500 * time.Millisecond,
        1 * time.Second,
        2 * time.Second,
        5 * time.Second,
    }
    
    testIDs := []string{"79", "89", "287"}
    
    for _, interval := range intervals {
        fmt.Printf("Testing with %v interval:\n", interval)
        
        client.GetRateLimiter().SetInterval(interval)
        client.GetRateLimiter().ResetLastRequest()
        
        start := time.Now()
        
        for _, id := range testIDs {
            requestStart := time.Now()
            weakness, err := client.GetWeakness(id)
            requestDuration := time.Since(requestStart)
            
            if err != nil {
                monitor.RecordError(err)
                fmt.Printf("  CWE-%s: ERROR (%v)\n", id, requestDuration)
            } else {
                monitor.RecordSuccess(requestDuration)
                fmt.Printf("  CWE-%s: OK (%v)\n", id, requestDuration)
            }
        }
        
        totalTime := time.Since(start)
        fmt.Printf("  Total time: %v\n", totalTime)
        fmt.Printf("  Average per request: %v\n", totalTime/time.Duration(len(testIDs)))
        
        // Print monitor stats
        stats := monitor.GetStats()
        fmt.Printf("  Success rate: %.1f%%\n", stats.SuccessRate*100)
        fmt.Printf("  Average response time: %v\n", stats.AverageResponseTime)
        fmt.Printf("  Error count: %d\n", stats.ErrorCount)
        
        monitor.Reset()
        fmt.Println()
    }
}

// Performance monitoring utility
type PerformanceMonitor struct {
    mutex           sync.Mutex
    successCount    int
    errorCount      int
    totalTime       time.Duration
    errors          []error
}

func NewPerformanceMonitor() *PerformanceMonitor {
    return &PerformanceMonitor{
        errors: make([]error, 0),
    }
}

func (pm *PerformanceMonitor) RecordSuccess(duration time.Duration) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    pm.successCount++
    pm.totalTime += duration
}

func (pm *PerformanceMonitor) RecordError(err error) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    pm.errorCount++
    pm.errors = append(pm.errors, err)
}

type PerformanceStats struct {
    SuccessRate         float64
    ErrorCount          int
    AverageResponseTime time.Duration
    TotalRequests       int
}

func (pm *PerformanceMonitor) GetStats() PerformanceStats {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    totalRequests := pm.successCount + pm.errorCount
    successRate := 0.0
    if totalRequests > 0 {
        successRate = float64(pm.successCount) / float64(totalRequests)
    }
    
    averageTime := time.Duration(0)
    if pm.successCount > 0 {
        averageTime = pm.totalTime / time.Duration(pm.successCount)
    }
    
    return PerformanceStats{
        SuccessRate:         successRate,
        ErrorCount:          pm.errorCount,
        AverageResponseTime: averageTime,
        TotalRequests:       totalRequests,
    }
}

func (pm *PerformanceMonitor) Reset() {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()
    
    pm.successCount = 0
    pm.errorCount = 0
    pm.totalTime = 0
    pm.errors = pm.errors[:0]
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
