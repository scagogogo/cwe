# Search & Utils

This section covers search functionality and utility functions provided by the CWE library for working with CWE data, IDs, and collections.

## Search Functions

### SearchCWEsByName

```go
func SearchCWEsByName(cwes []*CWE, query string) []*CWE
```

Searches for CWEs by name using case-insensitive substring matching.

**Parameters:**
- `cwes` - Slice of CWE instances to search
- `query` - Search query string

**Returns:**
- `[]*CWE` - Slice of matching CWEs

**Example:**
```go
cwes := []*cwe.CWE{
    cwe.NewCWE("CWE-79", "Cross-site Scripting"),
    cwe.NewCWE("CWE-89", "SQL Injection"),
    cwe.NewCWE("CWE-287", "Improper Authentication"),
}

results := cwe.SearchCWEsByName(cwes, "injection")
fmt.Printf("Found %d CWEs with 'injection' in name\n", len(results))
for _, c := range results {
    fmt.Printf("  %s: %s\n", c.ID, c.Name)
}
```

### SearchCWEsByDescription

```go
func SearchCWEsByDescription(cwes []*CWE, query string) []*CWE
```

Searches for CWEs by description using case-insensitive substring matching.

**Parameters:**
- `cwes` - Slice of CWE instances to search
- `query` - Search query string

**Returns:**
- `[]*CWE` - Slice of matching CWEs

### FilterCWEsBySeverity

```go
func FilterCWEsBySeverity(cwes []*CWE, severity string) []*CWE
```

Filters CWEs by severity level.

**Parameters:**
- `cwes` - Slice of CWE instances to filter
- `severity` - Severity level to match

**Returns:**
- `[]*CWE` - Slice of CWEs with matching severity

**Example:**
```go
highSeverityCWEs := cwe.FilterCWEsBySeverity(allCWEs, "High")
fmt.Printf("Found %d high-severity CWEs\n", len(highSeverityCWEs))
```

## Utility Functions

### ParseCWEID

```go
func ParseCWEID(id string) (string, error)
```

Parses and normalizes a CWE ID to the standard format.

**Parameters:**
- `id` - CWE ID in various formats

**Returns:**
- `string` - Normalized CWE ID (e.g., "CWE-79")
- `error` - Error if ID format is invalid

**Supported Formats:**
- `"79"` → `"CWE-79"`
- `"CWE-79"` → `"CWE-79"`
- `"cwe-79"` → `"CWE-79"`

**Example:**
```go
// Various input formats
inputs := []string{"79", "CWE-79", "cwe-89", "287"}

for _, input := range inputs {
    normalized, err := cwe.ParseCWEID(input)
    if err != nil {
        log.Printf("Invalid ID %s: %v", input, err)
        continue
    }
    fmt.Printf("%s → %s\n", input, normalized)
}
```

### ValidateCWEID

```go
func ValidateCWEID(id string) bool
```

Validates whether a string is a valid CWE ID format.

**Parameters:**
- `id` - String to validate

**Returns:**
- `bool` - True if valid CWE ID format

**Example:**
```go
ids := []string{"CWE-79", "79", "invalid", "CWE-", "CWE-abc"}

for _, id := range ids {
    if cwe.ValidateCWEID(id) {
        fmt.Printf("%s is valid\n", id)
    } else {
        fmt.Printf("%s is invalid\n", id)
    }
}
```

### ExtractCWENumber

```go
func ExtractCWENumber(id string) (int, error)
```

Extracts the numeric part from a CWE ID.

**Parameters:**
- `id` - CWE ID string

**Returns:**
- `int` - Numeric CWE identifier
- `error` - Error if extraction fails

**Example:**
```go
number, err := cwe.ExtractCWENumber("CWE-79")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("CWE number: %d\n", number) // Output: 79
```

### FormatCWEID

```go
func FormatCWEID(number int) string
```

Formats a numeric CWE identifier to standard string format.

**Parameters:**
- `number` - Numeric CWE identifier

**Returns:**
- `string` - Formatted CWE ID

**Example:**
```go
formatted := cwe.FormatCWEID(79)
fmt.Println(formatted) // Output: "CWE-79"
```

## Collection Utilities

### SortCWEsByID

```go
func SortCWEsByID(cwes []*CWE)
```

Sorts a slice of CWEs by their ID in ascending order.

**Parameters:**
- `cwes` - Slice of CWEs to sort (modified in-place)

**Example:**
```go
cwes := []*cwe.CWE{
    cwe.NewCWE("CWE-287", "Authentication"),
    cwe.NewCWE("CWE-79", "XSS"),
    cwe.NewCWE("CWE-89", "SQL Injection"),
}

cwe.SortCWEsByID(cwes)

for _, c := range cwes {
    fmt.Printf("%s: %s\n", c.ID, c.Name)
}
// Output:
// CWE-79: XSS
// CWE-89: SQL Injection
// CWE-287: Authentication
```

### SortCWEsByName

```go
func SortCWEsByName(cwes []*CWE)
```

Sorts a slice of CWEs by their name in ascending order.

### SortCWEsBySeverity

```go
func SortCWEsBySeverity(cwes []*CWE)
```

Sorts a slice of CWEs by severity (High → Medium → Low).

### RemoveDuplicateCWEs

```go
func RemoveDuplicateCWEs(cwes []*CWE) []*CWE
```

Removes duplicate CWEs from a slice based on ID.

**Parameters:**
- `cwes` - Slice of CWEs that may contain duplicates

**Returns:**
- `[]*CWE` - New slice with duplicates removed

**Example:**
```go
cwes := []*cwe.CWE{
    cwe.NewCWE("CWE-79", "XSS"),
    cwe.NewCWE("CWE-89", "SQL Injection"),
    cwe.NewCWE("CWE-79", "Cross-site Scripting"), // Duplicate
}

unique := cwe.RemoveDuplicateCWEs(cwes)
fmt.Printf("Original: %d, Unique: %d\n", len(cwes), len(unique))
```

## Tree Utilities

### FindCWEInTree

```go
func FindCWEInTree(root *CWE, id string) *CWE
```

Searches for a CWE by ID within a tree structure.

**Parameters:**
- `root` - Root node of the tree to search
- `id` - CWE ID to find

**Returns:**
- `*CWE` - Found CWE instance, or nil if not found

**Example:**
```go
// Build a tree
root := cwe.NewCWE("CWE-1000", "Research View")
injection := cwe.NewCWE("CWE-74", "Injection")
xss := cwe.NewCWE("CWE-79", "XSS")

root.AddChild(injection)
injection.AddChild(xss)

// Search in tree
found := cwe.FindCWEInTree(root, "CWE-79")
if found != nil {
    fmt.Printf("Found: %s - %s\n", found.ID, found.Name)
}
```

### GetTreeDepth

```go
func GetTreeDepth(root *CWE) int
```

Calculates the maximum depth of a CWE tree.

**Parameters:**
- `root` - Root node of the tree

**Returns:**
- `int` - Maximum depth (root = 0)

### CountNodesInTree

```go
func CountNodesInTree(root *CWE) int
```

Counts the total number of nodes in a CWE tree.

**Parameters:**
- `root` - Root node of the tree

**Returns:**
- `int` - Total number of nodes

### GetLeafNodes

```go
func GetLeafNodes(root *CWE) []*CWE
```

Returns all leaf nodes (nodes with no children) in a tree.

**Parameters:**
- `root` - Root node of the tree

**Returns:**
- `[]*CWE` - Slice of leaf nodes

## String Utilities

### TruncateString

```go
func TruncateString(s string, maxLength int) string
```

Truncates a string to the specified maximum length.

**Parameters:**
- `s` - String to truncate
- `maxLength` - Maximum allowed length

**Returns:**
- `string` - Truncated string with "..." suffix if truncated

### NormalizeWhitespace

```go
func NormalizeWhitespace(s string) string
```

Normalizes whitespace in a string by collapsing multiple spaces and trimming.

**Parameters:**
- `s` - String to normalize

**Returns:**
- `string` - Normalized string

## Usage Examples

### Comprehensive Search

```go
// Load CWEs
registry := cwe.NewRegistry()
// ... populate registry ...

allCWEs := make([]*cwe.CWE, 0, len(registry.Entries))
for _, c := range registry.Entries {
    allCWEs = append(allCWEs, c)
}

// Search by name
nameResults := cwe.SearchCWEsByName(allCWEs, "injection")
fmt.Printf("Name search results: %d\n", len(nameResults))

// Search by description
descResults := cwe.SearchCWEsByDescription(allCWEs, "authentication")
fmt.Printf("Description search results: %d\n", len(descResults))

// Filter by severity
highSeverity := cwe.FilterCWEsBySeverity(allCWEs, "High")
fmt.Printf("High severity CWEs: %d\n", len(highSeverity))

// Sort results
cwe.SortCWEsByName(nameResults)
for _, c := range nameResults {
    fmt.Printf("  %s: %s\n", c.ID, c.Name)
}
```

### ID Processing

```go
// Process various ID formats
rawIDs := []string{"79", "CWE-89", "cwe-287", "22", "invalid"}

var validCWEs []*cwe.CWE
for _, rawID := range rawIDs {
    // Validate and normalize
    if !cwe.ValidateCWEID(rawID) {
        fmt.Printf("Skipping invalid ID: %s\n", rawID)
        continue
    }
    
    normalizedID, err := cwe.ParseCWEID(rawID)
    if err != nil {
        fmt.Printf("Failed to parse %s: %v\n", rawID, err)
        continue
    }
    
    // Extract number for processing
    number, err := cwe.ExtractCWENumber(normalizedID)
    if err != nil {
        fmt.Printf("Failed to extract number from %s: %v\n", normalizedID, err)
        continue
    }
    
    fmt.Printf("Processing CWE-%d\n", number)
    
    // Create CWE instance
    cweInstance := cwe.NewCWE(normalizedID, fmt.Sprintf("CWE %d", number))
    validCWEs = append(validCWEs, cweInstance)
}

// Remove duplicates and sort
uniqueCWEs := cwe.RemoveDuplicateCWEs(validCWEs)
cwe.SortCWEsByID(uniqueCWEs)

fmt.Printf("Processed %d unique CWEs\n", len(uniqueCWEs))
```

### Tree Analysis

```go
// Build tree
fetcher := cwe.NewDataFetcher()
registry, err := fetcher.BuildCWETreeWithView("1000")
if err != nil {
    log.Fatal(err)
}

if registry.Root != nil {
    // Analyze tree structure
    depth := cwe.GetTreeDepth(registry.Root)
    nodeCount := cwe.CountNodesInTree(registry.Root)
    leafNodes := cwe.GetLeafNodes(registry.Root)
    
    fmt.Printf("Tree Analysis:\n")
    fmt.Printf("  Max depth: %d\n", depth)
    fmt.Printf("  Total nodes: %d\n", nodeCount)
    fmt.Printf("  Leaf nodes: %d\n", len(leafNodes))
    
    // Find specific CWE in tree
    xss := cwe.FindCWEInTree(registry.Root, "CWE-79")
    if xss != nil {
        fmt.Printf("  Found XSS at depth: %d\n", xss.GetDepth())
    }
}
```
