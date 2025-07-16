# 树操作

树操作模块提供了构建、遍历和操作CWE层次结构的功能。

## 概述

树操作功能包括：

- 构建CWE层次树
- 树的遍历和搜索
- 节点操作和修改
- 树的序列化和反序列化

## 树节点结构

### TreeNode

```go
type TreeNode struct {
    CWE      interface{}   `json:"cwe"`
    Children []*TreeNode   `json:"children,omitempty"`
    Parent   *TreeNode     `json:"-"`
    Depth    int          `json:"depth"`
}
```

字段说明：
- **CWE**: 可以是 `*CWEWeakness`、`*CWECategory` 或 `*CWEView`
- **Children**: 子节点列表
- **Parent**: 父节点（不序列化）
- **Depth**: 在树中的深度

## 创建树

### 手动创建

```go
// 创建根节点
root := &cwe.TreeNode{
    CWE: &cwe.CWEView{
        ID:   "1000",
        Name: "研究概念",
    },
    Depth: 0,
}

// 创建子节点
child1 := &cwe.TreeNode{
    CWE: &cwe.CWECategory{
        ID:   "20",
        Name: "输入验证不当",
    },
    Depth: 1,
}

child2 := &cwe.TreeNode{
    CWE: &cwe.CWEWeakness{
        ID:   "79",
        Name: "跨站脚本",
    },
    Depth: 2,
}

// 建立父子关系
root.AddChild(child1)
child1.AddChild(child2)
```

### 从API构建

```go
func buildTreeFromAPI(client *cwe.APIClient, viewID string) (*cwe.TreeNode, error) {
    // 获取视图信息
    view, err := client.GetView(viewID)
    if err != nil {
        return nil, err
    }
    
    // 创建根节点
    root := &cwe.TreeNode{
        CWE:   view,
        Depth: 0,
    }
    
    // 递归构建子树
    err = buildSubTree(client, root)
    if err != nil {
        return nil, err
    }
    
    return root, nil
}

func buildSubTree(client *cwe.APIClient, parent *cwe.TreeNode) error {
    // 根据父节点类型获取子节点
    children, err := getChildren(client, parent.CWE)
    if err != nil {
        return err
    }
    
    for _, childData := range children {
        child := &cwe.TreeNode{
            CWE:    childData,
            Parent: parent,
            Depth:  parent.Depth + 1,
        }
        
        parent.AddChild(child)
        
        // 递归构建子树
        err = buildSubTree(client, child)
        if err != nil {
            return err
        }
    }
    
    return nil
}
```

## 树的遍历

### 深度优先遍历

```go
// 遍历整个树
func (n *TreeNode) Walk(fn func(*TreeNode)) {
    fn(n)
    
    for _, child := range n.Children {
        child.Walk(fn)
    }
}

// 使用示例
root.Walk(func(node *cwe.TreeNode) {
    switch cweData := node.CWE.(type) {
    case *cwe.CWEWeakness:
        fmt.Printf("%s弱点: CWE-%s - %s\n", 
            strings.Repeat("  ", node.Depth), cweData.ID, cweData.Name)
    case *cwe.CWECategory:
        fmt.Printf("%s类别: CWE-%s - %s\n", 
            strings.Repeat("  ", node.Depth), cweData.ID, cweData.Name)
    case *cwe.CWEView:
        fmt.Printf("%s视图: CWE-%s - %s\n", 
            strings.Repeat("  ", node.Depth), cweData.ID, cweData.Name)
    }
})
```

### 广度优先遍历

```go
func (n *TreeNode) BreadthFirstWalk(fn func(*TreeNode)) {
    queue := []*TreeNode{n}
    
    for len(queue) > 0 {
        current := queue[0]
        queue = queue[1:]
        
        fn(current)
        
        queue = append(queue, current.Children...)
    }
}
```

### 条件遍历

```go
func (n *TreeNode) WalkIf(fn func(*TreeNode), condition func(*TreeNode) bool) {
    if condition(n) {
        fn(n)
    }
    
    for _, child := range n.Children {
        child.WalkIf(fn, condition)
    }
}

// 使用示例：只遍历弱点节点
root.WalkIf(
    func(node *cwe.TreeNode) {
        if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
            fmt.Printf("弱点: %s\n", weakness.Name)
        }
    },
    func(node *cwe.TreeNode) bool {
        _, isWeakness := node.CWE.(*cwe.CWEWeakness)
        return isWeakness
    },
)
```

## 树的搜索

### 按ID查找

```go
func (n *TreeNode) FindByID(id string) *TreeNode {
    if getCWEID(n.CWE) == id {
        return n
    }
    
    for _, child := range n.Children {
        if found := child.FindByID(id); found != nil {
            return found
        }
    }
    
    return nil
}

func getCWEID(cweData interface{}) string {
    switch data := cweData.(type) {
    case *cwe.CWEWeakness:
        return data.ID
    case *cwe.CWECategory:
        return data.ID
    case *cwe.CWEView:
        return data.ID
    default:
        return ""
    }
}
```

### 按条件查找

```go
func (n *TreeNode) FindAll(condition func(*TreeNode) bool) []*TreeNode {
    var results []*TreeNode
    
    n.Walk(func(node *TreeNode) {
        if condition(node) {
            results = append(results, node)
        }
    })
    
    return results
}

// 使用示例：查找所有高严重程度的弱点
highSeverityNodes := root.FindAll(func(node *cwe.TreeNode) bool {
    if weakness, ok := node.CWE.(*cwe.CWEWeakness); ok {
        return weakness.Severity == "High"
    }
    return false
})
```

## 树的操作

### 添加和删除节点

```go
func (n *TreeNode) AddChild(child *TreeNode) {
    child.Parent = n
    child.Depth = n.Depth + 1
    n.Children = append(n.Children, child)
}

func (n *TreeNode) RemoveChild(child *TreeNode) bool {
    for i, c := range n.Children {
        if c == child {
            // 移除子节点
            n.Children = append(n.Children[:i], n.Children[i+1:]...)
            child.Parent = nil
            return true
        }
    }
    return false
}

func (n *TreeNode) RemoveByID(id string) bool {
    for i, child := range n.Children {
        if getCWEID(child.CWE) == id {
            n.Children = append(n.Children[:i], n.Children[i+1:]...)
            child.Parent = nil
            return true
        }
        
        if child.RemoveByID(id) {
            return true
        }
    }
    return false
}
```

### 移动节点

```go
func (n *TreeNode) MoveTo(newParent *TreeNode) {
    if n.Parent != nil {
        n.Parent.RemoveChild(n)
    }
    
    newParent.AddChild(n)
    
    // 更新深度
    n.updateDepth()
}

func (n *TreeNode) updateDepth() {
    if n.Parent != nil {
        n.Depth = n.Parent.Depth + 1
    } else {
        n.Depth = 0
    }
    
    for _, child := range n.Children {
        child.updateDepth()
    }
}
```

## 树的分析

### 获取统计信息

```go
func (n *TreeNode) GetStats() map[string]int {
    stats := make(map[string]int)
    
    n.Walk(func(node *TreeNode) {
        stats["total"]++
        
        switch node.CWE.(type) {
        case *cwe.CWEWeakness:
            stats["weaknesses"]++
        case *cwe.CWECategory:
            stats["categories"]++
        case *cwe.CWEView:
            stats["views"]++
        }
        
        if len(node.Children) == 0 {
            stats["leaves"]++
        }
    })
    
    return stats
}
```

### 获取路径

```go
func (n *TreeNode) GetPath() []*TreeNode {
    var path []*TreeNode
    
    current := n
    for current != nil {
        path = append([]*TreeNode{current}, path...)
        current = current.Parent
    }
    
    return path
}

func (n *TreeNode) GetPathString() string {
    path := n.GetPath()
    var parts []string
    
    for _, node := range path {
        id := getCWEID(node.CWE)
        parts = append(parts, "CWE-"+id)
    }
    
    return strings.Join(parts, " -> ")
}
```

### 获取叶子节点

```go
func (n *TreeNode) GetLeaves() []*TreeNode {
    var leaves []*TreeNode
    
    n.Walk(func(node *TreeNode) {
        if len(node.Children) == 0 {
            leaves = append(leaves, node)
        }
    })
    
    return leaves
}
```

## 树的序列化

### JSON序列化

```go
func (n *TreeNode) ToJSON() ([]byte, error) {
    return json.MarshalIndent(n, "", "  ")
}

func TreeFromJSON(data []byte) (*TreeNode, error) {
    var node TreeNode
    err := json.Unmarshal(data, &node)
    if err != nil {
        return nil, err
    }
    
    // 重建父子关系
    node.rebuildParentLinks()
    
    return &node, nil
}

func (n *TreeNode) rebuildParentLinks() {
    for _, child := range n.Children {
        child.Parent = n
        child.rebuildParentLinks()
    }
}
```

### 保存和加载

```go
func (n *TreeNode) SaveToFile(filename string) error {
    data, err := n.ToJSON()
    if err != nil {
        return err
    }
    
    return ioutil.WriteFile(filename, data, 0644)
}

func LoadTreeFromFile(filename string) (*TreeNode, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    
    return TreeFromJSON(data)
}
```

## 树的可视化

### 文本格式输出

```go
func (n *TreeNode) PrintTree() {
    n.printNode("", true)
}

func (n *TreeNode) printNode(prefix string, isLast bool) {
    // 打印当前节点
    connector := "├── "
    if isLast {
        connector = "└── "
    }
    
    id := getCWEID(n.CWE)
    name := getCWEName(n.CWE)
    fmt.Printf("%s%sCWE-%s: %s\n", prefix, connector, id, name)
    
    // 打印子节点
    childPrefix := prefix
    if isLast {
        childPrefix += "    "
    } else {
        childPrefix += "│   "
    }
    
    for i, child := range n.Children {
        isLastChild := i == len(n.Children)-1
        child.printNode(childPrefix, isLastChild)
    }
}

func getCWEName(cweData interface{}) string {
    switch data := cweData.(type) {
    case *cwe.CWEWeakness:
        return data.Name
    case *cwe.CWECategory:
        return data.Name
    case *cwe.CWEView:
        return data.Name
    default:
        return "Unknown"
    }
}
```

## 最佳实践

1. **内存管理** - 注意循环引用，及时清理不需要的节点
2. **深度控制** - 对于深层树结构，注意栈溢出风险
3. **并发安全** - 在多goroutine环境中使用锁保护
4. **性能优化** - 对于大型树，考虑使用索引加速查找
5. **数据一致性** - 确保父子关系的一致性

## 下一步

- 了解[API客户端](./api-client)的树构建功能
- 学习[注册表](./registry)的数据管理
- 查看[示例](/zh/examples/)中的实际应用
