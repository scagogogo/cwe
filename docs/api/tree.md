# Tree Operations

The CWE library provides comprehensive support for building, traversing, and manipulating hierarchical CWE structures. This section covers tree-related operations and the `TreeNode` wrapper.

## TreeNode

The `TreeNode` provides a flexible wrapper around CWE instances for tree operations.

```go
type TreeNode struct {
    CWE      *CWE        // Wrapped CWE instance
    Children []*TreeNode // Child tree nodes
}
```

### Constructor

#### NewTreeNode

```go
func NewTreeNode(cwe *CWE) *TreeNode
```

Creates a new tree node wrapping the specified CWE.

**Parameters:**
- `cwe` - CWE instance to wrap

**Returns:**
- `*TreeNode` - New tree node

**Example:**
```go
cwe := cwe.NewCWE("CWE-79", "Cross-site Scripting")
node := cwe.NewTreeNode(cwe)
```

### Methods

#### AddChild

```go
func (n *TreeNode) AddChild(child *TreeNode)
```

Adds a child node to the current tree node.

**Parameters:**
- `child` - Child tree node to add

**Example:**
```go
root := cwe.NewTreeNode(cwe.NewCWE("CWE-1000", "Research View"))
child := cwe.NewTreeNode(cwe.NewCWE("CWE-79", "XSS"))
root.AddChild(child)
```

## Tree Building Functions

### BuildTreeFromRegistry

```go
func BuildTreeFromRegistry(registry *Registry) *TreeNode
```

Builds a tree structure from a registry with established relationships.

**Parameters:**
- `registry` - Registry with CWEs and relationships

**Returns:**
- `*TreeNode` - Root tree node, or nil if no root found

**Example:**
```go
registry := cwe.NewRegistry()
// ... populate registry and build hierarchy ...

tree := cwe.BuildTreeFromRegistry(registry)
if tree != nil {
    fmt.Printf("Tree root: %s\n", tree.CWE.ID)
}
```

### BuildSubTree

```go
func BuildSubTree(cwe *CWE) *TreeNode
```

Builds a tree starting from a specific CWE node.

**Parameters:**
- `cwe` - Root CWE for the subtree

**Returns:**
- `*TreeNode` - Tree representation of the CWE and its descendants

**Example:**
```go
// Get a CWE with children
injection := registry.GetByID("CWE-74")
if injection != nil {
    subTree := cwe.BuildSubTree(injection)
    fmt.Printf("Subtree has %d children\n", len(subTree.Children))
}
```

## Tree Traversal Functions

### TraverseTreeDepthFirst

```go
func TraverseTreeDepthFirst(root *TreeNode, visitor func(*TreeNode))
```

Traverses a tree in depth-first order, calling the visitor function for each node.

**Parameters:**
- `root` - Root tree node
- `visitor` - Function called for each visited node

**Example:**
```go
tree := cwe.BuildTreeFromRegistry(registry)

// Print all nodes in depth-first order
cwe.TraverseTreeDepthFirst(tree, func(node *cwe.TreeNode) {
    depth := node.CWE.GetDepth()
    indent := strings.Repeat("  ", depth)
    fmt.Printf("%s%s: %s\n", indent, node.CWE.ID, node.CWE.Name)
})
```

### TraverseTreeBreadthFirst

```go
func TraverseTreeBreadthFirst(root *TreeNode, visitor func(*TreeNode))
```

Traverses a tree in breadth-first order.

**Parameters:**
- `root` - Root tree node
- `visitor` - Function called for each visited node

**Example:**
```go
// Print nodes level by level
cwe.TraverseTreeBreadthFirst(tree, func(node *cwe.TreeNode) {
    fmt.Printf("Level %d: %s - %s\n", 
        node.CWE.GetDepth(), node.CWE.ID, node.CWE.Name)
})
```

### FindNodeInTree

```go
func FindNodeInTree(root *TreeNode, predicate func(*TreeNode) bool) *TreeNode
```

Finds the first node in a tree that matches the predicate.

**Parameters:**
- `root` - Root tree node to search
- `predicate` - Function that returns true for matching nodes

**Returns:**
- `*TreeNode` - First matching node, or nil if not found

**Example:**
```go
// Find node by ID
found := cwe.FindNodeInTree(tree, func(node *cwe.TreeNode) bool {
    return node.CWE.ID == "CWE-79"
})

if found != nil {
    fmt.Printf("Found: %s\n", found.CWE.Name)
}

// Find node by name pattern
sqlNode := cwe.FindNodeInTree(tree, func(node *cwe.TreeNode) bool {
    return strings.Contains(strings.ToLower(node.CWE.Name), "sql")
})
```

### CollectNodes

```go
func CollectNodes(root *TreeNode, predicate func(*TreeNode) bool) []*TreeNode
```

Collects all nodes in a tree that match the predicate.

**Parameters:**
- `root` - Root tree node to search
- `predicate` - Function that returns true for nodes to collect

**Returns:**
- `[]*TreeNode` - Slice of matching nodes

**Example:**
```go
// Collect all leaf nodes
leaves := cwe.CollectNodes(tree, func(node *cwe.TreeNode) bool {
    return len(node.Children) == 0
})

fmt.Printf("Found %d leaf nodes:\n", len(leaves))
for _, leaf := range leaves {
    fmt.Printf("  %s: %s\n", leaf.CWE.ID, leaf.CWE.Name)
}
```

## Tree Analysis Functions

### GetTreeHeight

```go
func GetTreeHeight(root *TreeNode) int
```

Calculates the height of a tree (maximum depth from root to leaf).

**Parameters:**
- `root` - Root tree node

**Returns:**
- `int` - Tree height (single node = 0)

### CountTreeNodes

```go
func CountTreeNodes(root *TreeNode) int
```

Counts the total number of nodes in a tree.

**Parameters:**
- `root` - Root tree node

**Returns:**
- `int` - Total node count

### GetTreeStatistics

```go
func GetTreeStatistics(root *TreeNode) map[string]int
```

Returns comprehensive statistics about a tree.

**Parameters:**
- `root` - Root tree node

**Returns:**
- `map[string]int` - Statistics map with keys: "total", "height", "leaves", "internal"

**Example:**
```go
stats := cwe.GetTreeStatistics(tree)
fmt.Printf("Tree Statistics:\n")
fmt.Printf("  Total nodes: %d\n", stats["total"])
fmt.Printf("  Height: %d\n", stats["height"])
fmt.Printf("  Leaf nodes: %d\n", stats["leaves"])
fmt.Printf("  Internal nodes: %d\n", stats["internal"])
```

## Tree Manipulation Functions

### PruneTree

```go
func PruneTree(root *TreeNode, predicate func(*TreeNode) bool) *TreeNode
```

Removes nodes from a tree that don't match the predicate.

**Parameters:**
- `root` - Root tree node
- `predicate` - Function that returns true for nodes to keep

**Returns:**
- `*TreeNode` - New tree with pruned nodes, or nil if root is pruned

**Example:**
```go
// Keep only high-severity CWEs
prunedTree := cwe.PruneTree(tree, func(node *cwe.TreeNode) bool {
    return node.CWE.Severity == "High" || node.CWE.Severity == ""
})
```

### FilterTreeByDepth

```go
func FilterTreeByDepth(root *TreeNode, maxDepth int) *TreeNode
```

Creates a new tree containing only nodes up to the specified depth.

**Parameters:**
- `root` - Root tree node
- `maxDepth` - Maximum depth to include

**Returns:**
- `*TreeNode` - New tree limited to specified depth

### CloneTree

```go
func CloneTree(root *TreeNode) *TreeNode
```

Creates a deep copy of a tree structure.

**Parameters:**
- `root` - Root tree node to clone

**Returns:**
- `*TreeNode` - Cloned tree

## Tree Serialization

### TreeToJSON

```go
func TreeToJSON(root *TreeNode) ([]byte, error)
```

Serializes a tree to JSON format.

**Parameters:**
- `root` - Root tree node

**Returns:**
- `[]byte` - JSON data
- `error` - Serialization error

### TreeFromJSON

```go
func TreeFromJSON(data []byte) (*TreeNode, error)
```

Deserializes a tree from JSON format.

**Parameters:**
- `data` - JSON data

**Returns:**
- `*TreeNode` - Reconstructed tree
- `error` - Deserialization error

## Usage Examples

### Building and Analyzing Trees

```go
// Build tree from fetched data
fetcher := cwe.NewDataFetcher()
registry, err := fetcher.BuildCWETreeWithView("1000")
if err != nil {
    log.Fatal(err)
}

// Convert to TreeNode structure
tree := cwe.BuildTreeFromRegistry(registry)
if tree == nil {
    log.Fatal("No tree root found")
}

// Analyze tree structure
stats := cwe.GetTreeStatistics(tree)
fmt.Printf("Tree Analysis:\n")
fmt.Printf("  Root: %s - %s\n", tree.CWE.ID, tree.CWE.Name)
fmt.Printf("  Total nodes: %d\n", stats["total"])
fmt.Printf("  Height: %d\n", stats["height"])
fmt.Printf("  Leaf nodes: %d\n", stats["leaves"])
```

### Tree Traversal and Search

```go
// Depth-first traversal with indentation
fmt.Println("Tree Structure (Depth-First):")
cwe.TraverseTreeDepthFirst(tree, func(node *cwe.TreeNode) {
    depth := node.CWE.GetDepth()
    indent := strings.Repeat("  ", depth)
    fmt.Printf("%s%s: %s\n", indent, node.CWE.ID, node.CWE.Name)
})

// Find specific nodes
injectionNodes := cwe.CollectNodes(tree, func(node *cwe.TreeNode) bool {
    return strings.Contains(strings.ToLower(node.CWE.Name), "injection")
})

fmt.Printf("\nFound %d injection-related CWEs:\n", len(injectionNodes))
for _, node := range injectionNodes {
    fmt.Printf("  %s: %s (depth %d)\n", 
        node.CWE.ID, node.CWE.Name, node.CWE.GetDepth())
}
```

### Tree Manipulation

```go
// Create a filtered view of high-severity issues
highSeverityTree := cwe.PruneTree(tree, func(node *cwe.TreeNode) bool {
    // Keep nodes that are high severity or have high-severity descendants
    if node.CWE.Severity == "High" {
        return true
    }
    
    // Check if any descendants are high severity
    hasHighSeverityChild := false
    cwe.TraverseTreeDepthFirst(node, func(child *cwe.TreeNode) {
        if child.CWE.Severity == "High" {
            hasHighSeverityChild = true
        }
    })
    
    return hasHighSeverityChild
})

if highSeverityTree != nil {
    fmt.Printf("High-severity tree has %d nodes\n", 
        cwe.CountTreeNodes(highSeverityTree))
}

// Create a shallow view (first 3 levels only)
shallowTree := cwe.FilterTreeByDepth(tree, 2)
fmt.Printf("Shallow tree (depth ≤ 2) has %d nodes\n", 
    cwe.CountTreeNodes(shallowTree))
```

### Tree Persistence

```go
// Save tree to JSON
jsonData, err := cwe.TreeToJSON(tree)
if err != nil {
    log.Fatal(err)
}

err = ioutil.WriteFile("cwe_tree.json", jsonData, 0644)
if err != nil {
    log.Fatal(err)
}

// Load tree from JSON
savedData, err := ioutil.ReadFile("cwe_tree.json")
if err != nil {
    log.Fatal(err)
}

loadedTree, err := cwe.TreeFromJSON(savedData)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Loaded tree with %d nodes\n", cwe.CountTreeNodes(loadedTree))
```

### Custom Tree Operations

```go
// Find all paths from root to leaves
func findAllPaths(root *cwe.TreeNode) [][]string {
    var paths [][]string
    var currentPath []string
    
    var traverse func(*cwe.TreeNode)
    traverse = func(node *cwe.TreeNode) {
        currentPath = append(currentPath, node.CWE.ID)
        
        if len(node.Children) == 0 {
            // Leaf node - save path
            path := make([]string, len(currentPath))
            copy(path, currentPath)
            paths = append(paths, path)
        } else {
            // Internal node - continue traversal
            for _, child := range node.Children {
                traverse(child)
            }
        }
        
        currentPath = currentPath[:len(currentPath)-1]
    }
    
    traverse(root)
    return paths
}

// Usage
paths := findAllPaths(tree)
fmt.Printf("Found %d paths from root to leaves:\n", len(paths))
for i, path := range paths[:5] { // Show first 5 paths
    fmt.Printf("  Path %d: %s\n", i+1, strings.Join(path, " → "))
}
```

## Performance Considerations

- **Memory Usage**: TreeNode structures use additional memory compared to direct CWE relationships
- **Traversal Speed**: Depth-first traversal is generally faster than breadth-first
- **Large Trees**: Consider using iterative approaches for very deep trees to avoid stack overflow
- **Cloning**: Tree cloning creates complete copies, which can be memory-intensive

## Thread Safety

- **TreeNode**: Not thread-safe for modifications
- **Traversal Functions**: Safe for concurrent read-only operations
- **Tree Building**: Should be done in a single thread
- **Analysis Functions**: Thread-safe for read-only analysis
