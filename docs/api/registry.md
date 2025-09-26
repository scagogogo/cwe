# Registry

The `Registry` provides a centralized collection for managing CWE entries. It offers storage, retrieval, hierarchy building, and import/export functionality.

## Registry

```go
type Registry struct {
    Entries map[string]*CWE // CWE entries indexed by ID
    Root    *CWE            // Root node of the hierarchy
}
```

The Registry is thread-safe for read operations but requires external synchronization for modifications.

## Constructor

### NewRegistry

```go
func NewRegistry() *Registry
```

Creates a new empty registry.

**Example:**
```go
registry := cwe.NewRegistry()
```

## Core Operations

### Register

```go
func (r *Registry) Register(cwe *CWE) error
```

Adds a CWE to the registry.

**Parameters:**
- `cwe` - CWE instance to register

**Returns:**
- `error` - Error if CWE is nil, has no ID, or ID already exists

**Example:**
```go
// Create a new registry to store CWE instances
registry := cwe.NewRegistry()

// Create a CWE instance
xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")

// Add the CWE to the registry
// This allows for centralized management and querying of CWEs
err := registry.Register(xss)
if err != nil {
    log.Fatalf("Failed to register CWE: %v", err)
}

// Verify the registration
fmt.Printf("Successfully registered %s\n", xss.ID)
```

### GetByID

```go
func (r *Registry) GetByID(id string) (*CWE, bool)
```

Retrieves a CWE by its ID.

**Parameters:**
- `id` - CWE ID to look up

**Returns:**
- `*CWE` - The CWE instance if found
- `bool` - True if CWE was found

**Example:**
```go
// Retrieve a CWE from the registry by its ID
// The second return value indicates whether the CWE was found
cwe, exists := registry.GetByID("CWE-79")
if exists {
    // CWE was found, print its information
    fmt.Printf("Found: %s - %s\n", cwe.ID, cwe.Name)
    fmt.Printf("Description: %s\n", cwe.Description)
} else {
    // CWE was not found in the registry
    fmt.Println("CWE not found in registry")
}
```

### GetAll

```go
func (r *Registry) GetAll() map[string]*CWE
```

Returns all CWEs in the registry.

**Returns:**
- `map[string]*CWE` - Copy of the entries map

### Count

```go
func (r *Registry) Count() int
```

Returns the number of CWEs in the registry.

**Example:**
```go
// Get the total count of CWEs in the registry
count := registry.Count()
fmt.Printf("Registry contains %d CWEs\n", count)
```

## Hierarchy Operations

### BuildHierarchy

```go
func (r *Registry) BuildHierarchy() error
```

Builds parent-child relationships between CWEs in the registry and identifies the root node.

**Returns:**
- `error` - Error if hierarchy building fails

**Example:**
```go
// Add multiple CWEs to the registry
registry.Register(cwe.NewCWE("CWE-1000", "Research View"))
registry.Register(cwe.NewCWE("CWE-74", "Injection"))
registry.Register(cwe.NewCWE("CWE-79", "XSS"))

// Build the hierarchy to establish parent-child relationships
// This is necessary for tree traversal and analysis
err := registry.BuildHierarchy()
if err != nil {
    log.Fatalf("Failed to build hierarchy: %v", err)
}

// Access the root node of the hierarchy
if registry.Root != nil {
    fmt.Printf("Root: %s\n", registry.Root.ID)
    fmt.Printf("Root has %d children\n", len(registry.Root.Children))
}
```

### GetRoots

```go
func (r *Registry) GetRoots() []*CWE
```

Returns all CWEs that have no parent (potential root nodes).

**Returns:**
- `[]*CWE` - Slice of root CWEs

### GetLeaves

```go
func (r *Registry) GetLeaves() []*CWE
```

Returns all CWEs that have no children (leaf nodes).

**Returns:**
- `[]*CWE` - Slice of leaf CWEs

## Search Operations

### SearchByName

```go
func (r *Registry) SearchByName(query string) []*CWE
```

Searches for CWEs by name (case-insensitive substring match).

**Parameters:**
- `query` - Search query string

**Returns:**
- `[]*CWE` - Slice of matching CWEs

**Example:**
```go
// Search for CWEs containing "injection" in their name
// This performs a case-insensitive substring search
results := registry.SearchByName("injection")
fmt.Printf("Found %d CWEs matching 'injection':\n", len(results))
for _, cwe := range results {
    fmt.Printf("  %s: %s\n", cwe.ID, cwe.Name)
}
```

### SearchByDescription

```go
func (r *Registry) SearchByDescription(query string) []*CWE
```

Searches for CWEs by description (case-insensitive substring match).

### FilterBySeverity

```go
func (r *Registry) FilterBySeverity(severity string) []*CWE
```

Filters CWEs by severity level.

**Parameters:**
- `severity` - Severity level to filter by

**Returns:**
- `[]*CWE` - Slice of CWEs with matching severity

## Import/Export Operations

### ExportToJSON

```go
func (r *Registry) ExportToJSON() ([]byte, error)
```

Exports the registry to JSON format.

**Returns:**
- `[]byte` - JSON data
- `error` - Serialization error

**Example:**
```go
jsonData, err := registry.ExportToJSON()
if err != nil {
    log.Fatalf("Export failed: %v", err)
}

// Save to file
err = ioutil.WriteFile("cwe_data.json", jsonData, 0644)
if err != nil {
    log.Fatalf("Failed to save file: %v", err)
}
```

### ImportFromJSON

```go
func (r *Registry) ImportFromJSON(data []byte) error
```

Imports CWEs from JSON data.

**Parameters:**
- `data` - JSON data to import

**Returns:**
- `error` - Import or parsing error

**Example:**
```go
// Read from file
jsonData, err := ioutil.ReadFile("cwe_data.json")
if err != nil {
    log.Fatalf("Failed to read file: %v", err)
}

// Import into registry
registry := cwe.NewRegistry()
err = registry.ImportFromJSON(jsonData)
if err != nil {
    log.Fatalf("Import failed: %v", err)
}

fmt.Printf("Imported %d CWEs\n", registry.Count())
```

## Statistics and Analysis

### GetStatistics

```go
func (r *Registry) GetStatistics() map[string]interface{}
```

Returns statistical information about the registry.

**Returns:**
- `map[string]interface{}` - Statistics map

**Example:**
```go
stats := registry.GetStatistics()
fmt.Printf("Registry Statistics:\n")
fmt.Printf("  Total CWEs: %v\n", stats["total"])
fmt.Printf("  Root nodes: %v\n", stats["roots"])
fmt.Printf("  Leaf nodes: %v\n", stats["leaves"])
fmt.Printf("  Max depth: %v\n", stats["max_depth"])
```

## Usage Examples

### Basic Registry Operations

```go
// Create registry
registry := cwe.NewRegistry()

// Add CWEs
cweList := []*cwe.CWE{
    cwe.NewCWE("CWE-79", "Cross-site Scripting"),
    cwe.NewCWE("CWE-89", "SQL Injection"),
    cwe.NewCWE("CWE-287", "Improper Authentication"),
}

for _, c := range cweList {
    err := registry.Register(c)
    if err != nil {
        log.Printf("Failed to register %s: %v", c.ID, err)
    }
}

fmt.Printf("Registered %d CWEs\n", registry.Count())

// Retrieve CWE
if xss, exists := registry.GetByID("CWE-79"); exists {
    fmt.Printf("Found XSS: %s\n", xss.Name)
}
```

### Building and Exploring Hierarchies

```go
// Create a simple hierarchy
registry := cwe.NewRegistry()

root := cwe.NewCWE("CWE-1000", "Research View")
injection := cwe.NewCWE("CWE-74", "Injection")
xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
sqli := cwe.NewCWE("CWE-89", "SQL Injection")

// Register all CWEs
registry.Register(root)
registry.Register(injection)
registry.Register(xss)
registry.Register(sqli)

// Build relationships manually
root.AddChild(injection)
injection.AddChild(xss)
injection.AddChild(sqli)

// Build registry hierarchy
err := registry.BuildHierarchy()
if err != nil {
    log.Fatal(err)
}

// Explore hierarchy
fmt.Printf("Root: %s\n", registry.Root.ID)
fmt.Printf("Roots: %d\n", len(registry.GetRoots()))
fmt.Printf("Leaves: %d\n", len(registry.GetLeaves()))
```

### Search and Filter Operations

```go
// Search by name
injectionCWEs := registry.SearchByName("injection")
fmt.Printf("CWEs with 'injection' in name: %d\n", len(injectionCWEs))

// Search by description
scriptCWEs := registry.SearchByDescription("script")
fmt.Printf("CWEs with 'script' in description: %d\n", len(scriptCWEs))

// Filter by severity
highSeverityCWEs := registry.FilterBySeverity("High")
fmt.Printf("High severity CWEs: %d\n", len(highSeverityCWEs))
```

### Data Persistence

```go
// Export registry
jsonData, err := registry.ExportToJSON()
if err != nil {
    log.Fatal(err)
}

// Save to file
err = ioutil.WriteFile("my_cwe_collection.json", jsonData, 0644)
if err != nil {
    log.Fatal(err)
}

// Later, load from file
newRegistry := cwe.NewRegistry()
savedData, err := ioutil.ReadFile("my_cwe_collection.json")
if err != nil {
    log.Fatal(err)
}

err = newRegistry.ImportFromJSON(savedData)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Loaded %d CWEs from file\n", newRegistry.Count())
```

### Working with DataFetcher

```go
// Use DataFetcher to populate registry
fetcher := cwe.NewDataFetcher()

// Fetch multiple CWEs
ids := []string{"79", "89", "287", "22", "78"}
registry, err := fetcher.FetchMultiple(ids)
if err != nil {
    log.Fatal(err)
}

// Registry is now populated
fmt.Printf("Fetched %d CWEs\n", registry.Count())

// Search within fetched data
results := registry.SearchByName("injection")
fmt.Printf("Found %d injection-related CWEs\n", len(results))

// Export for later use
jsonData, _ := registry.ExportToJSON()
ioutil.WriteFile("fetched_cwes.json", jsonData, 0644)
```

## Thread Safety

- **Read Operations**: Thread-safe (GetByID, GetAll, Search methods)
- **Write Operations**: Not thread-safe (Register, BuildHierarchy)
- **Concurrent Access**: Use external synchronization for modifications

## Performance Considerations

- **Memory Usage**: Stores all CWEs in memory
- **Search Performance**: Linear search for name/description queries
- **Hierarchy Building**: O(n²) complexity for relationship building
- **Large Collections**: Consider pagination for very large datasets
