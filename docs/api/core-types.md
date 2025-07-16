# Core Types

This section documents the core data structures and types used throughout the CWE Go library.

## CWE

The `CWE` struct represents a Common Weakness Enumeration entry and forms the foundation of the library.

```go
type CWE struct {
    Parent      *CWE     // Parent node in the hierarchy
    URL         string   // CWE details page URL
    ID          string   // Unique identifier (e.g., "CWE-79")
    Name        string   // CWE name/title
    Children    []*CWE   // Child nodes
    Description string   // Detailed description
    Severity    string   // Severity level (High, Medium, Low)
    Mitigations []string // Mitigation strategies
    Examples    []string // Example scenarios
}
```

### Constructor

#### NewCWE

```go
func NewCWE(id, name string) *CWE
```

Creates a new CWE instance with the specified ID and name.

**Parameters:**
- `id` - CWE identifier (format: "CWE-number")
- `name` - CWE name/title

**Returns:**
- `*CWE` - Initialized CWE instance

**Example:**
```go
cwe := cwe.NewCWE("CWE-79", "Cross-site Scripting")
cwe.Description = "Allows attackers to inject malicious scripts"
cwe.Severity = "High"
```

### Methods

#### AddChild

```go
func (c *CWE) AddChild(child *CWE)
```

Adds a child CWE to the current node and sets the parent relationship.

**Parameters:**
- `child` - The CWE to add as a child

**Example:**
```go
parent := cwe.NewCWE("CWE-1000", "Software Security")
child := cwe.NewCWE("CWE-79", "XSS")
parent.AddChild(child)
```

#### RemoveChild

```go
func (c *CWE) RemoveChild(childID string) bool
```

Removes a child CWE by ID.

**Parameters:**
- `childID` - ID of the child to remove

**Returns:**
- `bool` - True if child was found and removed

#### GetDepth

```go
func (c *CWE) GetDepth() int
```

Returns the depth of the current node in the tree (root = 0).

#### GetRoot

```go
func (c *CWE) GetRoot() *CWE
```

Returns the root node of the tree containing this CWE.

#### IsLeaf

```go
func (c *CWE) IsLeaf() bool
```

Returns true if the CWE has no children.

#### GetAllChildren

```go
func (c *CWE) GetAllChildren() []*CWE
```

Returns all descendant CWEs (children, grandchildren, etc.).

#### ToJSON

```go
func (c *CWE) ToJSON() ([]byte, error)
```

Serializes the CWE to JSON format.

#### ToXML

```go
func (c *CWE) ToXML() ([]byte, error)
```

Serializes the CWE to XML format.

## TreeNode

The `TreeNode` struct provides a wrapper around CWE for flexible tree representations.

```go
type TreeNode struct {
    CWE      *CWE        // The wrapped CWE instance
    Children []*TreeNode // Child nodes
}
```

### Constructor

#### NewTreeNode

```go
func NewTreeNode(cwe *CWE) *TreeNode
```

Creates a new tree node wrapping the specified CWE.

### Methods

#### AddChild

```go
func (n *TreeNode) AddChild(child *TreeNode)
```

Adds a child node to the current tree node.

## API Response Types

### APIResponse

Base response structure for API calls.

```go
type APIResponse struct {
    Status  int    `json:"status,omitempty"`
    Message string `json:"message,omitempty"`
    Error   string `json:"error,omitempty"`
}
```

### VersionResponse

Response structure for version information.

```go
type VersionResponse struct {
    Version     string `json:"version"`
    ReleaseDate string `json:"release_date"`
}
```

### CWEWeakness

API response structure for weakness data.

```go
type CWEWeakness struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description"`
    URL         string `json:"url"`
    Severity    string `json:"severity,omitempty"`
    // Additional fields...
}
```

### CWECategory

API response structure for category data.

```go
type CWECategory struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description"`
    URL         string `json:"url"`
    // Additional fields...
}
```

### CWEView

API response structure for view data.

```go
type CWEView struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description"`
    URL         string `json:"url"`
    // Additional fields...
}
```

## Usage Examples

### Creating and Building Trees

```go
// Create root CWE
root := cwe.NewCWE("CWE-1000", "Research View")
root.Description = "Top-level research view"

// Create child CWEs
injection := cwe.NewCWE("CWE-74", "Injection")
xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
sqli := cwe.NewCWE("CWE-89", "SQL Injection")

// Build hierarchy
root.AddChild(injection)
injection.AddChild(xss)
injection.AddChild(sqli)

// Navigate tree
fmt.Printf("Root depth: %d\n", root.GetDepth())           // 0
fmt.Printf("XSS depth: %d\n", xss.GetDepth())             // 2
fmt.Printf("XSS is leaf: %v\n", xss.IsLeaf())             // true
fmt.Printf("Root children: %d\n", len(root.GetAllChildren())) // 3
```

### Serialization

```go
// Convert to JSON
jsonData, err := root.ToJSON()
if err != nil {
    log.Fatalf("JSON serialization failed: %v", err)
}

// Convert to XML
xmlData, err := root.ToXML()
if err != nil {
    log.Fatalf("XML serialization failed: %v", err)
}
```

## Thread Safety

- **CWE**: Not thread-safe for modifications. Use external synchronization when modifying CWE structures concurrently.
- **TreeNode**: Not thread-safe for modifications.
- **API Response Types**: Immutable after creation, safe for concurrent read access.
