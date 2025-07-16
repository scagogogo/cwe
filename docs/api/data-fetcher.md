# Data Fetcher

The `DataFetcher` provides a high-level interface for fetching CWE data from the API and converting it to local data structures. It builds upon the `APIClient` to offer more convenient methods for common operations.

## DataFetcher

```go
type DataFetcher struct {
    client *APIClient // Underlying API client
}
```

The DataFetcher wraps an APIClient and provides methods that return `*CWE` instances instead of raw API response structures.

## Constructors

### NewDataFetcher

```go
func NewDataFetcher() *DataFetcher
```

Creates a new data fetcher with a default API client.

**Example:**
```go
fetcher := cwe.NewDataFetcher()
```

### NewDataFetcherWithClient

```go
func NewDataFetcherWithClient(client *APIClient) *DataFetcher
```

Creates a new data fetcher with a custom API client.

**Parameters:**
- `client` - Custom API client instance

**Example:**
```go
// Create custom client
customClient := cwe.NewAPIClientWithOptions(
    "https://custom-api.example.com/api/v1",
    60 * time.Second,
)

// Create fetcher with custom client
fetcher := cwe.NewDataFetcherWithClient(customClient)
```

## Basic Fetching Methods

### FetchWeakness

```go
func (f *DataFetcher) FetchWeakness(id string) (*CWE, error)
```

Fetches a weakness by ID and converts it to a CWE structure.

**Parameters:**
- `id` - CWE ID (with or without "CWE-" prefix)

**Returns:**
- `*CWE` - CWE instance with populated data
- `error` - Error if fetching or conversion fails

**Example:**
```go
cwe, err := fetcher.FetchWeakness("79")
if err != nil {
    log.Fatalf("Failed to fetch weakness: %v", err)
}
fmt.Printf("Fetched: %s - %s\n", cwe.ID, cwe.Name)
```

### FetchCategory

```go
func (f *DataFetcher) FetchCategory(id string) (*CWE, error)
```

Fetches a category by ID and converts it to a CWE structure.

**Parameters:**
- `id` - Category ID

**Returns:**
- `*CWE` - CWE instance representing the category
- `error` - Error if fetching or conversion fails

### FetchView

```go
func (f *DataFetcher) FetchView(id string) (*CWE, error)
```

Fetches a view by ID and converts it to a CWE structure.

**Parameters:**
- `id` - View ID

**Returns:**
- `*CWE` - CWE instance representing the view
- `error` - Error if fetching or conversion fails

## Batch Operations

### FetchMultiple

```go
func (f *DataFetcher) FetchMultiple(ids []string) (*Registry, error)
```

Fetches multiple CWEs and returns them in a Registry.

**Parameters:**
- `ids` - Slice of CWE IDs to fetch

**Returns:**
- `*Registry` - Registry containing all fetched CWEs
- `error` - Error if any fetch operation fails

**Example:**
```go
ids := []string{"79", "89", "287"}
registry, err := fetcher.FetchMultiple(ids)
if err != nil {
    log.Fatalf("Failed to fetch multiple CWEs: %v", err)
}

fmt.Printf("Fetched %d CWEs\n", len(registry.Entries))
for id, cwe := range registry.Entries {
    fmt.Printf("  %s: %s\n", id, cwe.Name)
}
```

## Tree Building Methods

### BuildCWETreeWithView

```go
func (f *DataFetcher) BuildCWETreeWithView(viewID string) (*Registry, error)
```

Builds a complete CWE tree starting from a specific view.

**Parameters:**
- `viewID` - View ID to use as the root

**Returns:**
- `*Registry` - Registry containing the complete tree
- `error` - Error if tree building fails

**Example:**
```go
// Build tree from Research View (CWE-1000)
registry, err := fetcher.BuildCWETreeWithView("1000")
if err != nil {
    log.Fatalf("Failed to build tree: %v", err)
}

fmt.Printf("Built tree with %d nodes\n", len(registry.Entries))
```

### FetchCWEByIDWithRelations

```go
func (f *DataFetcher) FetchCWEByIDWithRelations(id string, viewID string) (*CWE, error)
```

Fetches a CWE and populates its relationships (children) recursively.

**Parameters:**
- `id` - CWE ID to fetch
- `viewID` - View context for relationships

**Returns:**
- `*CWE` - CWE with populated children
- `error` - Error if fetching fails

**Example:**
```go
// Fetch CWE with all its children
cwe, err := fetcher.FetchCWEByIDWithRelations("74", "1000")
if err != nil {
    log.Fatalf("Failed to fetch with relations: %v", err)
}

fmt.Printf("CWE %s has %d children\n", cwe.ID, len(cwe.Children))
```

### PopulateChildrenRecursive

```go
func (f *DataFetcher) PopulateChildrenRecursive(cwe *CWE, viewID string) error
```

Recursively populates children for an existing CWE instance.

**Parameters:**
- `cwe` - CWE instance to populate
- `viewID` - View context for relationships

**Returns:**
- `error` - Error if population fails

## Version Information

### GetCurrentVersion

```go
func (f *DataFetcher) GetCurrentVersion() (string, error)
```

Gets the current CWE version string.

**Returns:**
- `string` - Version string (e.g., "4.12")
- `error` - Error if version retrieval fails

**Example:**
```go
version, err := fetcher.GetCurrentVersion()
if err != nil {
    log.Fatalf("Failed to get version: %v", err)
}
fmt.Printf("Current CWE version: %s\n", version)
```

## Usage Examples

### Basic Fetching

```go
fetcher := cwe.NewDataFetcher()

// Fetch individual items
xss, err := fetcher.FetchWeakness("79")
if err != nil {
    log.Fatal(err)
}

injection, err := fetcher.FetchCategory("74")
if err != nil {
    log.Fatal(err)
}

researchView, err := fetcher.FetchView("1000")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("XSS: %s\n", xss.Name)
fmt.Printf("Injection: %s\n", injection.Name)
fmt.Printf("Research View: %s\n", researchView.Name)
```

### Building Complete Trees

```go
fetcher := cwe.NewDataFetcher()

// Build complete tree from research view
fmt.Println("Building CWE tree (this may take a while)...")
registry, err := fetcher.BuildCWETreeWithView("1000")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Tree built with %d nodes\n", len(registry.Entries))

// Find root and traverse
if root := registry.Root; root != nil {
    fmt.Printf("Root: %s - %s\n", root.ID, root.Name)
    fmt.Printf("Root has %d direct children\n", len(root.Children))
    
    // Print first level children
    for _, child := range root.Children {
        fmt.Printf("  - %s: %s\n", child.ID, child.Name)
    }
}
```

### Batch Processing

```go
fetcher := cwe.NewDataFetcher()

// Define CWEs of interest
topCWEs := []string{
    "79",  // XSS
    "89",  // SQL Injection
    "287", // Authentication
    "22",  // Path Traversal
    "78",  // OS Command Injection
}

// Fetch all at once
registry, err := fetcher.FetchMultiple(topCWEs)
if err != nil {
    log.Fatal(err)
}

// Process results
fmt.Printf("Top %d CWEs:\n", len(registry.Entries))
for _, id := range topCWEs {
    if cwe, exists := registry.GetByID("CWE-" + id); exists {
        fmt.Printf("  CWE-%s: %s\n", id, cwe.Name)
        if cwe.Severity != "" {
            fmt.Printf("    Severity: %s\n", cwe.Severity)
        }
    }
}
```

### Working with Relationships

```go
fetcher := cwe.NewDataFetcher()

// Fetch injection category with all children
injection, err := fetcher.FetchCWEByIDWithRelations("74", "1000")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Injection (%s) hierarchy:\n", injection.ID)
printTree(injection, 0)

func printTree(cwe *cwe.CWE, depth int) {
    indent := strings.Repeat("  ", depth)
    fmt.Printf("%s- %s: %s\n", indent, cwe.ID, cwe.Name)
    
    for _, child := range cwe.Children {
        printTree(child, depth+1)
    }
}
```

## Performance Considerations

- **Rate Limiting**: Inherits rate limiting from underlying APIClient
- **Tree Building**: Large trees can take significant time due to recursive API calls
- **Memory Usage**: Complete trees may consume substantial memory
- **Error Handling**: Failed child fetches are logged but don't stop the process

## Error Handling

The DataFetcher provides detailed error information:

```go
cwe, err := fetcher.FetchWeakness("invalid-id")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "not found"):
        fmt.Println("CWE does not exist")
    case strings.Contains(err.Error(), "parse"):
        fmt.Println("Failed to parse CWE ID")
    case strings.Contains(err.Error(), "convert"):
        fmt.Println("Failed to convert API response")
    default:
        fmt.Printf("Unknown error: %v\n", err)
    }
}
```
