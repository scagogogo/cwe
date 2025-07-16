# Basic Usage

This example demonstrates the fundamental operations of the CWE Go library, including creating clients, fetching data, and working with CWE structures.

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
    fmt.Println("==== CWE Library Basic Usage Example ====")
    
    // 1. Create an API client
    fmt.Println("\n1. Creating API Client")
    client := cwe.NewAPIClient()
    
    // 2. Get CWE version information
    fmt.Println("\n2. Getting CWE Version")
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("Failed to get CWE version: %v", err)
    }
    
    fmt.Printf("Current CWE Version: %s\n", version.Version)
    fmt.Printf("Release Date: %s\n", version.ReleaseDate)
    
    // 3. Fetch a specific weakness
    fmt.Println("\n3. Fetching CWE-79 (Cross-site Scripting)")
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("Failed to get CWE-79: %v", err)
    }
    
    fmt.Printf("ID: %s\n", weakness.ID)
    fmt.Printf("Name: %s\n", weakness.Name)
    fmt.Printf("URL: %s\n", weakness.URL)
    
    // Truncate description for display
    description := weakness.Description
    if len(description) > 200 {
        description = description[:200] + "..."
    }
    fmt.Printf("Description: %s\n", description)
    
    // 4. Create a CWE instance using the data fetcher
    fmt.Println("\n4. Using Data Fetcher")
    fetcher := cwe.NewDataFetcher()
    
    cweInstance, err := fetcher.FetchWeakness("89")
    if err != nil {
        log.Fatalf("Failed to fetch CWE-89: %v", err)
    }
    
    fmt.Printf("Fetched CWE: %s - %s\n", cweInstance.ID, cweInstance.Name)
    fmt.Printf("Has %d children\n", len(cweInstance.Children))
    
    // 5. Work with a registry
    fmt.Println("\n5. Working with Registry")
    registry := cwe.NewRegistry()
    
    // Create some CWE instances
    xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
    xss.Description = "Improper neutralization of input during web page generation"
    xss.Severity = "High"
    
    sqli := cwe.NewCWE("CWE-89", "SQL Injection")
    sqli.Description = "Improper neutralization of special elements used in SQL commands"
    sqli.Severity = "High"
    
    auth := cwe.NewCWE("CWE-287", "Improper Authentication")
    auth.Description = "Occurs when an actor claims to have a given identity"
    auth.Severity = "Medium"
    
    // Register CWEs
    registry.Register(xss)
    registry.Register(sqli)
    registry.Register(auth)
    
    fmt.Printf("Registry contains %d CWEs\n", registry.Count())
    
    // Search in registry
    results := registry.SearchByName("injection")
    fmt.Printf("Found %d CWEs with 'injection' in name:\n", len(results))
    for _, cwe := range results {
        fmt.Printf("  - %s: %s\n", cwe.ID, cwe.Name)
    }
    
    // 6. Demonstrate error handling
    fmt.Println("\n6. Error Handling Example")
    _, err = client.GetWeakness("99999")
    if err != nil {
        fmt.Printf("Expected error for invalid CWE: %v\n", err)
    }
    
    // 7. Rate limiting demonstration
    fmt.Println("\n7. Rate Limiting")
    limiter := client.GetRateLimiter()
    fmt.Printf("Current rate limit interval: %v\n", limiter.GetInterval())
    
    // Adjust rate limiting
    limiter.SetInterval(2 * time.Second)
    fmt.Printf("Updated rate limit interval: %v\n", limiter.GetInterval())
    
    fmt.Println("\n==== Basic Usage Example Complete ====")
}
```

## Step-by-Step Breakdown

### 1. Creating an API Client

```go
// Create a client with default settings
client := cwe.NewAPIClient()

// Or create with custom options
customClient := cwe.NewAPIClientWithOptions(
    "",                                    // Use default base URL
    30 * time.Second,                     // 30-second timeout
    cwe.NewHTTPRateLimiter(5 * time.Second), // 5-second rate limit
)
```

The API client handles all communication with the CWE REST API and includes built-in rate limiting and retry logic.

### 2. Getting Version Information

```go
version, err := client.GetVersion()
if err != nil {
    log.Fatalf("Failed to get version: %v", err)
}

fmt.Printf("Version: %s, Released: %s\n", version.Version, version.ReleaseDate)
```

Version information helps ensure you're working with the expected CWE data version.

### 3. Fetching Individual CWEs

```go
// Fetch by ID (with or without CWE- prefix)
weakness, err := client.GetWeakness("79")
// or
weakness, err := client.GetWeakness("CWE-79")

if err != nil {
    log.Fatalf("Failed to fetch: %v", err)
}

fmt.Printf("CWE-%s: %s\n", weakness.ID, weakness.Name)
```

The `GetWeakness` method returns raw API data. For structured CWE objects, use the DataFetcher.

### 4. Using the Data Fetcher

```go
fetcher := cwe.NewDataFetcher()

// Fetch and convert to CWE structure
cweInstance, err := fetcher.FetchWeakness("79")
if err != nil {
    log.Fatalf("Failed to fetch: %v", err)
}

// Now you have a full CWE object with methods
fmt.Printf("Depth in tree: %d\n", cweInstance.GetDepth())
fmt.Printf("Is leaf: %v\n", cweInstance.IsLeaf())
```

The DataFetcher provides a higher-level interface that returns structured CWE objects.

### 5. Working with Registries

```go
registry := cwe.NewRegistry()

// Create CWE instances
xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
xss.Severity = "High"

// Register in collection
err := registry.Register(xss)
if err != nil {
    log.Printf("Registration failed: %v", err)
}

// Query the registry
if cwe, exists := registry.GetByID("CWE-79"); exists {
    fmt.Printf("Found: %s\n", cwe.Name)
}

// Search operations
results := registry.SearchByName("script")
highSeverity := registry.FilterBySeverity("High")
```

Registries provide collection management with search and filtering capabilities.

### 6. Error Handling Patterns

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

Always check for errors and handle different error types appropriately.

### 7. Rate Limiting Management

```go
// Get current rate limiter
limiter := client.GetRateLimiter()
fmt.Printf("Current interval: %v\n", limiter.GetInterval())

// Adjust rate limiting
limiter.SetInterval(5 * time.Second)

// Or set a new rate limiter
newLimiter := cwe.NewHTTPRateLimiter(2 * time.Second)
client.SetRateLimiter(newLimiter)
```

Rate limiting prevents API overload and ensures reliable operation.

## Common Use Cases

### Checking if a CWE Exists

```go
func cweExists(client *cwe.APIClient, id string) bool {
    _, err := client.GetWeakness(id)
    return err == nil
}

// Usage
if cweExists(client, "79") {
    fmt.Println("CWE-79 exists")
}
```

### Building a Simple CWE Collection

```go
func buildTopCWECollection() *cwe.Registry {
    registry := cwe.NewRegistry()
    
    topCWEs := map[string]string{
        "CWE-79":  "Cross-site Scripting",
        "CWE-89":  "SQL Injection",
        "CWE-287": "Improper Authentication",
        "CWE-22":  "Path Traversal",
        "CWE-78":  "OS Command Injection",
    }
    
    for id, name := range topCWEs {
        cweInstance := cwe.NewCWE(id, name)
        cweInstance.Severity = "High" // Assume high severity
        registry.Register(cweInstance)
    }
    
    return registry
}
```

### Simple Search Function

```go
func searchCWEs(registry *cwe.Registry, query string) {
    nameResults := registry.SearchByName(query)
    descResults := registry.SearchByDescription(query)
    
    fmt.Printf("Search results for '%s':\n", query)
    fmt.Printf("  By name: %d results\n", len(nameResults))
    fmt.Printf("  By description: %d results\n", len(descResults))
    
    // Combine and deduplicate results
    allResults := append(nameResults, descResults...)
    unique := cwe.RemoveDuplicateCWEs(allResults)
    
    fmt.Printf("  Total unique: %d results\n", len(unique))
}
```

## Running the Example

To run this example:

1. **Install the library:**
   ```bash
   go get github.com/scagogogo/cwe
   ```

2. **Create the example file:**
   ```bash
   # Save the complete example code to main.go
   ```

3. **Run the example:**
   ```bash
   go run main.go
   ```

4. **Expected output:**
   ```
   ==== CWE Library Basic Usage Example ====
   
   1. Creating API Client
   
   2. Getting CWE Version
   Current CWE Version: 4.12
   Release Date: 2023-06-29
   
   3. Fetching CWE-79 (Cross-site Scripting)
   ID: CWE-79
   Name: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
   URL: https://cwe.mitre.org/data/definitions/79.html
   Description: The product does not neutralize or incorrectly neutralizes user-controllable input...
   
   4. Using Data Fetcher
   Fetched CWE: CWE-89 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
   Has 0 children
   
   5. Working with Registry
   Registry contains 3 CWEs
   Found 1 CWEs with 'injection' in name:
     - CWE-89: SQL Injection
   
   6. Error Handling Example
   Expected error for invalid CWE: API request failed, status code: 404
   
   7. Rate Limiting
   Current rate limit interval: 10s
   Updated rate limit interval: 2s
   
   ==== Basic Usage Example Complete ====
   ```

## Next Steps

- Explore [Fetching CWE Data](./fetch-cwe) for more advanced data operations
- Learn about [Building Trees](./build-tree) for hierarchical structures
- Check [Search & Filter](./search-filter) for advanced search capabilities
- See the [API Reference](/api/) for complete documentation
