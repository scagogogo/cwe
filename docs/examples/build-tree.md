# Building Trees

This example demonstrates how to build and work with CWE hierarchical tree structures, including recursive fetching and tree traversal.

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
    fmt.Println("==== CWE Tree Building Example ====")
    
    fetcher := cwe.NewDataFetcher()
    
    // 1. Build tree from view
    fmt.Println("\n1. Building CWE Tree from Research View")
    fmt.Println("This may take a while due to API rate limiting...")
    
    registry, err := fetcher.BuildCWETreeWithView("1000")
    if err != nil {
        log.Fatalf("Failed to build tree: %v", err)
    }
    
    fmt.Printf("Built tree with %d nodes\n", len(registry.Entries))
    
    // 2. Analyze tree structure
    if registry.Root != nil {
        fmt.Printf("Root: %s - %s\n", registry.Root.ID, registry.Root.Name)
        fmt.Printf("Root has %d direct children\n", len(registry.Root.Children))
        
        // Print tree statistics
        depth := registry.Root.GetDepth()
        fmt.Printf("Root depth: %d\n", depth)
        
        allChildren := registry.Root.GetAllChildren()
        fmt.Printf("Total descendants: %d\n", len(allChildren))
    }
    
    // 3. Traverse tree structure
    fmt.Println("\n2. Tree Traversal (First 3 levels)")
    if registry.Root != nil {
        printTreeLimited(registry.Root, 0, 3)
    }
    
    // 4. Find specific nodes
    fmt.Println("\n3. Finding Specific Nodes")
    
    // Find injection-related CWEs
    injectionCWEs := findCWEsByName(registry.Root, "injection")
    fmt.Printf("Found %d injection-related CWEs:\n", len(injectionCWEs))
    for _, cwe := range injectionCWEs {
        fmt.Printf("  %s: %s (depth %d)\n", cwe.ID, cwe.Name, cwe.GetDepth())
    }
    
    // 5. Build subtree
    fmt.Println("\n4. Building Subtree")
    if injection := findCWEByID(registry.Root, "CWE-74"); injection != nil {
        fmt.Printf("Injection subtree:\n")
        printTreeLimited(injection, 0, 2)
    }
    
    // 6. Tree statistics
    fmt.Println("\n5. Tree Statistics")
    stats := analyzeTree(registry.Root)
    for key, value := range stats {
        fmt.Printf("  %s: %d\n", key, value)
    }
    
    fmt.Println("\n==== Tree Building Example Complete ====")
}

// Helper function to print tree with depth limit
func printTreeLimited(cwe *cwe.CWE, currentDepth, maxDepth int) {
    if currentDepth > maxDepth {
        return
    }
    
    indent := strings.Repeat("  ", currentDepth)
    fmt.Printf("%s%s: %s\n", indent, cwe.ID, cwe.Name)
    
    for _, child := range cwe.Children {
        printTreeLimited(child, currentDepth+1, maxDepth)
    }
}

// Find CWEs by name pattern
func findCWEsByName(root *cwe.CWE, pattern string) []*cwe.CWE {
    var results []*cwe.CWE
    
    var traverse func(*cwe.CWE)
    traverse = func(node *cwe.CWE) {
        if strings.Contains(strings.ToLower(node.Name), strings.ToLower(pattern)) {
            results = append(results, node)
        }
        
        for _, child := range node.Children {
            traverse(child)
        }
    }
    
    if root != nil {
        traverse(root)
    }
    
    return results
}

// Find CWE by ID
func findCWEByID(root *cwe.CWE, id string) *cwe.CWE {
    if root == nil {
        return nil
    }
    
    if root.ID == id {
        return root
    }
    
    for _, child := range root.Children {
        if found := findCWEByID(child, id); found != nil {
            return found
        }
    }
    
    return nil
}

// Analyze tree structure
func analyzeTree(root *cwe.CWE) map[string]int {
    stats := map[string]int{
        "total_nodes": 0,
        "leaf_nodes":  0,
        "max_depth":   0,
    }
    
    if root == nil {
        return stats
    }
    
    var traverse func(*cwe.CWE, int)
    traverse = func(node *cwe.CWE, depth int) {
        stats["total_nodes"]++
        
        if depth > stats["max_depth"] {
            stats["max_depth"] = depth
        }
        
        if len(node.Children) == 0 {
            stats["leaf_nodes"]++
        }
        
        for _, child := range node.Children {
            traverse(child, depth+1)
        }
    }
    
    traverse(root, 0)
    return stats
}
```

## Key Concepts

### 1. Building Trees from Views

```go
// Build complete tree from a view
registry, err := fetcher.BuildCWETreeWithView("1000")
if err != nil {
    log.Fatal(err)
}

// The registry contains all nodes with relationships established
fmt.Printf("Tree has %d nodes\n", len(registry.Entries))
```

### 2. Working with Tree Relationships

```go
// Access tree structure
root := registry.Root
if root != nil {
    fmt.Printf("Root: %s\n", root.ID)
    fmt.Printf("Children: %d\n", len(root.Children))
    
    // Navigate tree
    for _, child := range root.Children {
        fmt.Printf("  Child: %s\n", child.ID)
        fmt.Printf("  Parent: %s\n", child.Parent.ID)
    }
}
```

### 3. Tree Traversal Patterns

```go
// Depth-first traversal
func traverseDepthFirst(node *cwe.CWE, visitor func(*cwe.CWE)) {
    if node == nil {
        return
    }
    
    visitor(node)
    
    for _, child := range node.Children {
        traverseDepthFirst(child, visitor)
    }
}

// Breadth-first traversal
func traverseBreadthFirst(root *cwe.CWE, visitor func(*cwe.CWE)) {
    if root == nil {
        return
    }
    
    queue := []*cwe.CWE{root}
    
    for len(queue) > 0 {
        node := queue[0]
        queue = queue[1:]
        
        visitor(node)
        
        queue = append(queue, node.Children...)
    }
}
```

## Advanced Tree Operations

### Building Custom Trees

```go
func buildCustomTree() *cwe.CWE {
    // Create root
    root := cwe.NewCWE("CWE-1000", "Software Security")
    
    // Create categories
    injection := cwe.NewCWE("CWE-74", "Injection")
    crypto := cwe.NewCWE("CWE-310", "Cryptographic Issues")
    
    // Create specific weaknesses
    xss := cwe.NewCWE("CWE-79", "Cross-site Scripting")
    sqli := cwe.NewCWE("CWE-89", "SQL Injection")
    
    // Build hierarchy
    root.AddChild(injection)
    root.AddChild(crypto)
    injection.AddChild(xss)
    injection.AddChild(sqli)
    
    return root
}
```

### Tree Analysis Functions

```go
func getTreePaths(root *cwe.CWE) [][]string {
    var paths [][]string
    var currentPath []string
    
    var traverse func(*cwe.CWE)
    traverse = func(node *cwe.CWE) {
        currentPath = append(currentPath, node.ID)
        
        if len(node.Children) == 0 {
            // Leaf node - save path
            path := make([]string, len(currentPath))
            copy(path, currentPath)
            paths = append(paths, path)
        } else {
            // Continue traversal
            for _, child := range node.Children {
                traverse(child)
            }
        }
        
        currentPath = currentPath[:len(currentPath)-1]
    }
    
    traverse(root)
    return paths
}
```

### Tree Filtering

```go
func filterTreeBySeverity(root *cwe.CWE, severity string) *cwe.CWE {
    if root == nil {
        return nil
    }
    
    // Create new node if current node matches or has matching descendants
    if root.Severity == severity || hasDescendantWithSeverity(root, severity) {
        newNode := cwe.NewCWE(root.ID, root.Name)
        newNode.Description = root.Description
        newNode.Severity = root.Severity
        
        // Recursively filter children
        for _, child := range root.Children {
            if filteredChild := filterTreeBySeverity(child, severity); filteredChild != nil {
                newNode.AddChild(filteredChild)
            }
        }
        
        return newNode
    }
    
    return nil
}

func hasDescendantWithSeverity(node *cwe.CWE, severity string) bool {
    for _, child := range node.Children {
        if child.Severity == severity || hasDescendantWithSeverity(child, severity) {
            return true
        }
    }
    return false
}
```

## Working with TreeNode

```go
// Convert CWE tree to TreeNode structure
func convertToTreeNode(cwe *cwe.CWE) *cwe.TreeNode {
    if cwe == nil {
        return nil
    }
    
    node := cwe.NewTreeNode(cwe)
    
    for _, child := range cwe.Children {
        if childNode := convertToTreeNode(child); childNode != nil {
            node.AddChild(childNode)
        }
    }
    
    return node
}

// Use TreeNode for flexible tree operations
treeNode := convertToTreeNode(registry.Root)
if treeNode != nil {
    // TreeNode provides additional flexibility for tree operations
    fmt.Printf("TreeNode root: %s\n", treeNode.CWE.ID)
}
```

## Performance Considerations

### Incremental Tree Building

```go
func buildTreeIncremental(fetcher *cwe.DataFetcher, rootID string, maxDepth int) (*cwe.CWE, error) {
    root, err := fetcher.FetchWeakness(rootID)
    if err != nil {
        return nil, err
    }
    
    err = populateChildrenToDepth(fetcher, root, 0, maxDepth)
    if err != nil {
        return nil, err
    }
    
    return root, nil
}

func populateChildrenToDepth(fetcher *cwe.DataFetcher, node *cwe.CWE, currentDepth, maxDepth int) error {
    if currentDepth >= maxDepth {
        return nil
    }
    
    // Get children IDs (this would need to be implemented)
    // childIDs := getChildrenIDs(node.ID)
    
    // for _, childID := range childIDs {
    //     child, err := fetcher.FetchWeakness(childID)
    //     if err != nil {
    //         continue // Skip failed fetches
    //     }
    //     
    //     node.AddChild(child)
    //     
    //     err = populateChildrenToDepth(fetcher, child, currentDepth+1, maxDepth)
    //     if err != nil {
    //         // Log error but continue
    //         log.Printf("Failed to populate children for %s: %v", child.ID, err)
    //     }
    // }
    
    return nil
}
```

## Running the Example

```bash
go run main.go
```

**Note:** Building complete trees can take significant time due to API rate limiting. Consider using smaller subsets for testing.

## Next Steps

- Explore [Search & Filter](./search-filter) for finding specific nodes in trees
- Learn about [Export & Import](./export-import) for persisting tree structures
- Check [Rate Limited Client](./rate-limited) for optimizing API usage
