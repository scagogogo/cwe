# Fetching CWE Data

This example demonstrates comprehensive data fetching operations, including getting individual CWEs, batch operations, and working with relationships.

## Complete Example

```go
package main

import (
    "fmt"
    "log"
    "strings"
    
    "github.com/scagogogo/cwe"
)

func main() {
    fmt.Println("==== CWE Data Fetching Example ====")
    
    // Create API client and data fetcher
    client := cwe.NewAPIClient()
    fetcher := cwe.NewDataFetcher()
    
    // 1. Get current version
    fmt.Println("\n1. Getting CWE Version")
    version, err := fetcher.GetCurrentVersion()
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }
    fmt.Printf("Current CWE version: %s\n", version)
    
    // 2. Fetch individual weakness
    fmt.Println("\n2. Fetching Individual Weakness (CWE-79)")
    xss, err := fetcher.FetchWeakness("79")
    if err != nil {
        log.Fatalf("Failed to fetch CWE-79: %v", err)
    }
    fmt.Printf("ID: %s\n", xss.ID)
    fmt.Printf("Name: %s\n", xss.Name)
    fmt.Printf("URL: %s\n", xss.URL)
    
    // 3. Fetch category
    fmt.Println("\n3. Fetching Category (CWE-74 - Injection)")
    injection, err := fetcher.FetchCategory("74")
    if err != nil {
        log.Fatalf("Failed to fetch category: %v", err)
    }
    fmt.Printf("Category: %s - %s\n", injection.ID, injection.Name)
    
    // 4. Fetch view
    fmt.Println("\n4. Fetching View (CWE-1000 - Research View)")
    researchView, err := fetcher.FetchView("1000")
    if err != nil {
        log.Fatalf("Failed to fetch view: %v", err)
    }
    fmt.Printf("View: %s - %s\n", researchView.ID, researchView.Name)
    
    // 5. Batch fetching
    fmt.Println("\n5. Batch Fetching Multiple CWEs")
    ids := []string{"79", "89", "287", "22", "78"}
    registry, err := fetcher.FetchMultiple(ids)
    if err != nil {
        log.Fatalf("Failed to fetch multiple CWEs: %v", err)
    }
    
    fmt.Printf("Fetched %d CWEs:\n", len(registry.Entries))
    for id, cwe := range registry.Entries {
        fmt.Printf("  %s: %s\n", id, cwe.Name)
    }
    
    // 6. Working with relationships
    fmt.Println("\n6. Exploring CWE Relationships")
    
    // Get parents of CWE-79
    parents, err := client.GetParents("79", "")
    if err != nil {
        log.Printf("Failed to get parents: %v", err)
    } else {
        fmt.Printf("CWE-79 parents: %s\n", strings.Join(parents, ", "))
    }
    
    // Get children of CWE-74 (Injection)
    children, err := client.GetChildren("74", "")
    if err != nil {
        log.Printf("Failed to get children: %v", err)
    } else {
        fmt.Printf("CWE-74 has %d children\n", len(children))
        if len(children) > 0 {
            fmt.Printf("First few children: %s\n", 
                strings.Join(children[:min(5, len(children))], ", "))
        }
    }
    
    // 7. Fetch with relationships
    fmt.Println("\n7. Fetching CWE with Relationships")
    injectionWithChildren, err := fetcher.FetchCWEByIDWithRelations("74", "1000")
    if err != nil {
        log.Printf("Failed to fetch with relations: %v", err)
    } else {
        fmt.Printf("CWE-74 with children loaded: %d direct children\n", 
            len(injectionWithChildren.Children))
        
        // Print first few children
        for i, child := range injectionWithChildren.Children {
            if i >= 3 { // Limit output
                fmt.Printf("  ... and %d more\n", len(injectionWithChildren.Children)-3)
                break
            }
            fmt.Printf("  - %s: %s\n", child.ID, child.Name)
        }
    }
    
    fmt.Println("\n==== Data Fetching Example Complete ====")
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

## Key Concepts

### 1. Version Information

```go
// Get version through client
versionResp, err := client.GetVersion()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Version: %s, Release: %s\n", versionResp.Version, versionResp.ReleaseDate)

// Get version through fetcher (simplified)
version, err := fetcher.GetCurrentVersion()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Version: %s\n", version)
```

### 2. Different CWE Types

```go
// Weakness - specific vulnerability
weakness, err := fetcher.FetchWeakness("79")

// Category - grouping of related weaknesses
category, err := fetcher.FetchCategory("74")

// View - organizational perspective
view, err := fetcher.FetchView("1000")
```

### 3. Batch Operations

```go
// Efficient batch fetching
ids := []string{"79", "89", "287"}
registry, err := fetcher.FetchMultiple(ids)

// Process results
for id, cwe := range registry.Entries {
    fmt.Printf("%s: %s\n", id, cwe.Name)
}
```

### 4. Relationship Exploration

```go
// Get direct relationships
parents, err := client.GetParents("79", "")
children, err := client.GetChildren("74", "")

// Get all ancestors/descendants
ancestors, err := client.GetAncestors("79", "1000")
descendants, err := client.GetDescendants("74", "1000")
```

## Advanced Fetching Patterns

### Error-Resilient Batch Fetching

```go
func fetchMultipleWithErrorHandling(fetcher *cwe.DataFetcher, ids []string) *cwe.Registry {
    registry := cwe.NewRegistry()
    
    for _, id := range ids {
        cwe, err := fetcher.FetchWeakness(id)
        if err != nil {
            log.Printf("Failed to fetch %s: %v", id, err)
            continue
        }
        
        err = registry.Register(cwe)
        if err != nil {
            log.Printf("Failed to register %s: %v", id, err)
        }
    }
    
    return registry
}
```

### Fetching with Retry Logic

```go
func fetchWithRetry(fetcher *cwe.DataFetcher, id string, maxRetries int) (*cwe.CWE, error) {
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        cwe, err := fetcher.FetchWeakness(id)
        if err == nil {
            return cwe, nil
        }
        
        lastErr = err
        time.Sleep(time.Duration(i+1) * time.Second)
    }
    
    return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}
```

### Parallel Fetching

```go
func fetchParallel(fetcher *cwe.DataFetcher, ids []string) map[string]*cwe.CWE {
    results := make(map[string]*cwe.CWE)
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    for _, id := range ids {
        wg.Add(1)
        go func(cweID string) {
            defer wg.Done()
            
            cwe, err := fetcher.FetchWeakness(cweID)
            if err != nil {
                log.Printf("Failed to fetch %s: %v", cweID, err)
                return
            }
            
            mu.Lock()
            results[cweID] = cwe
            mu.Unlock()
        }(id)
    }
    
    wg.Wait()
    return results
}
```

## Working with Different Data Types

### Processing API Responses

```go
// Raw API data
weakness, err := client.GetWeakness("79")
if err != nil {
    log.Fatal(err)
}

// Convert to structured format
cweInstance := &cwe.CWE{
    ID:          weakness.ID,
    Name:        weakness.Name,
    Description: weakness.Description,
    URL:         weakness.URL,
}
```

### Handling Missing Data

```go
func safeFetch(fetcher *cwe.DataFetcher, id string) (*cwe.CWE, error) {
    // Try as weakness first
    cwe, err := fetcher.FetchWeakness(id)
    if err == nil {
        return cwe, nil
    }
    
    // Try as category
    cwe, err = fetcher.FetchCategory(id)
    if err == nil {
        return cwe, nil
    }
    
    // Try as view
    cwe, err = fetcher.FetchView(id)
    if err == nil {
        return cwe, nil
    }
    
    return nil, fmt.Errorf("CWE %s not found in any category", id)
}
```

## Performance Optimization

### Caching Frequently Used Data

```go
type CachedFetcher struct {
    fetcher *cwe.DataFetcher
    cache   map[string]*cwe.CWE
    mutex   sync.RWMutex
}

func NewCachedFetcher() *CachedFetcher {
    return &CachedFetcher{
        fetcher: cwe.NewDataFetcher(),
        cache:   make(map[string]*cwe.CWE),
    }
}

func (cf *CachedFetcher) FetchWeakness(id string) (*cwe.CWE, error) {
    cf.mutex.RLock()
    if cached, exists := cf.cache[id]; exists {
        cf.mutex.RUnlock()
        return cached, nil
    }
    cf.mutex.RUnlock()
    
    cwe, err := cf.fetcher.FetchWeakness(id)
    if err != nil {
        return nil, err
    }
    
    cf.mutex.Lock()
    cf.cache[id] = cwe
    cf.mutex.Unlock()
    
    return cwe, nil
}
```

### Rate Limiting for Large Operations

```go
func fetchLargeSet(fetcher *cwe.DataFetcher, ids []string) *cwe.Registry {
    registry := cwe.NewRegistry()
    
    // Process in batches to respect rate limits
    batchSize := 10
    for i := 0; i < len(ids); i += batchSize {
        end := i + batchSize
        if end > len(ids) {
            end = len(ids)
        }
        
        batch := ids[i:end]
        batchRegistry, err := fetcher.FetchMultiple(batch)
        if err != nil {
            log.Printf("Batch %d failed: %v", i/batchSize, err)
            continue
        }
        
        // Merge into main registry
        for id, cwe := range batchRegistry.Entries {
            registry.Register(cwe)
        }
        
        // Small delay between batches
        time.Sleep(1 * time.Second)
    }
    
    return registry
}
```

## Running the Example

```bash
# Save the code to main.go and run
go run main.go
```

Expected output includes version information, individual CWE details, batch results, and relationship data.

## Next Steps

- Learn about [Building Trees](./build-tree) for hierarchical structures
- Explore [Search & Filter](./search-filter) for finding specific CWEs
- Check [Export & Import](./export-import) for data persistence
