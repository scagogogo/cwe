# 核心类型

CWE Go库定义了几个核心类型来表示CWE数据结构。这些类型提供了处理CWE弱点、类别、视图和相关数据的基础。

## CWE数据结构

### CWEWeakness

`CWEWeakness` 表示一个CWE弱点条目。

```go
type CWEWeakness struct {
    ID          string `json:"id" xml:"id,attr"`
    Name        string `json:"name" xml:"name,attr"`
    Description string `json:"description" xml:"description"`
    Severity    string `json:"severity,omitempty" xml:"severity,attr,omitempty"`
    URL         string `json:"url,omitempty" xml:"url,attr,omitempty"`
}
```

#### 字段说明

- **ID**: CWE标识符（例如："79", "89"）
- **Name**: 弱点名称
- **Description**: 详细描述
- **Severity**: 严重程度（可选）
- **URL**: 相关URL（可选）

#### 示例

```go
weakness := &cwe.CWEWeakness{
    ID:          "79",
    Name:        "跨站脚本",
    Description: "应用程序在生成网页时未正确验证输入",
    Severity:    "Medium",
    URL:         "https://cwe.mitre.org/data/definitions/79.html",
}
```

### CWECategory

`CWECategory` 表示一个CWE类别。

```go
type CWECategory struct {
    ID          string `json:"id" xml:"id,attr"`
    Name        string `json:"name" xml:"name,attr"`
    Description string `json:"description" xml:"description"`
    URL         string `json:"url,omitempty" xml:"url,attr,omitempty"`
}
```

#### 示例

```go
category := &cwe.CWECategory{
    ID:          "20",
    Name:        "输入验证不当",
    Description: "产品未正确验证输入",
    URL:         "https://cwe.mitre.org/data/definitions/20.html",
}
```

### CWEView

`CWEView` 表示一个CWE视图。

```go
type CWEView struct {
    ID          string `json:"id" xml:"id,attr"`
    Name        string `json:"name" xml:"name,attr"`
    Description string `json:"description" xml:"description"`
    URL         string `json:"url,omitempty" xml:"url,attr,omitempty"`
}
```

#### 示例

```go
view := &cwe.CWEView{
    ID:          "1000",
    Name:        "研究概念",
    Description: "用于研究的CWE视图",
    URL:         "https://cwe.mitre.org/data/definitions/1000.html",
}
```

## 响应类型

### WeaknessResponse

API响应的包装类型，用于弱点查询。

```go
type WeaknessResponse struct {
    Weaknesses []*CWEWeakness `json:"weaknesses"`
}
```

### CategoryResponse

API响应的包装类型，用于类别查询。

```go
type CategoryResponse struct {
    Categories []*CWECategory `json:"categories"`
}
```

### ViewResponse

API响应的包装类型，用于视图查询。

```go
type ViewResponse struct {
    Views []*CWEView `json:"views"`
}
```

## 树结构类型

### TreeNode

`TreeNode` 表示CWE层次结构中的一个节点。

```go
type TreeNode struct {
    CWE      interface{}   `json:"cwe"`
    Children []*TreeNode   `json:"children,omitempty"`
    Parent   *TreeNode     `json:"-"`
    Depth    int          `json:"depth"`
}
```

#### 字段说明

- **CWE**: 可以是 `*CWEWeakness`、`*CWECategory` 或 `*CWEView`
- **Children**: 子节点列表
- **Parent**: 父节点（不序列化）
- **Depth**: 在树中的深度

#### 方法

```go
// 添加子节点
func (n *TreeNode) AddChild(child *TreeNode)

// 遍历树
func (n *TreeNode) Walk(fn func(*TreeNode))

// 查找节点
func (n *TreeNode) FindByID(id string) *TreeNode

// 获取所有叶子节点
func (n *TreeNode) GetLeaves() []*TreeNode
```

#### 示例

```go
// 创建根节点
root := &cwe.TreeNode{
    CWE: &cwe.CWEView{
        ID:   "1000",
        Name: "研究概念",
    },
    Depth: 0,
}

// 添加子节点
child := &cwe.TreeNode{
    CWE: &cwe.CWEWeakness{
        ID:   "79",
        Name: "跨站脚本",
    },
    Depth: 1,
}

root.AddChild(child)

// 遍历树
root.Walk(func(node *cwe.TreeNode) {
    switch cweData := node.CWE.(type) {
    case *cwe.CWEWeakness:
        fmt.Printf("弱点: CWE-%s\n", cweData.ID)
    case *cwe.CWECategory:
        fmt.Printf("类别: CWE-%s\n", cweData.ID)
    case *cwe.CWEView:
        fmt.Printf("视图: CWE-%s\n", cweData.ID)
    }
})
```

## 版本信息类型

### VersionInfo

表示CWE数据库的版本信息。

```go
type VersionInfo struct {
    Version     string `json:"version"`
    ReleaseDate string `json:"release_date"`
}
```

#### 示例

```go
version := &cwe.VersionInfo{
    Version:     "4.7",
    ReleaseDate: "2023-06-29",
}

fmt.Printf("CWE版本: %s，发布于: %s\n", 
    version.Version, version.ReleaseDate)
```

## 类型转换和验证

### 类型断言

在处理 `TreeNode.CWE` 字段时，需要进行类型断言：

```go
switch cweData := node.CWE.(type) {
case *cwe.CWEWeakness:
    // 处理弱点
    fmt.Printf("弱点ID: %s\n", cweData.ID)
case *cwe.CWECategory:
    // 处理类别
    fmt.Printf("类别ID: %s\n", cweData.ID)
case *cwe.CWEView:
    // 处理视图
    fmt.Printf("视图ID: %s\n", cweData.ID)
default:
    fmt.Println("未知类型")
}
```

### 验证方法

```go
// 验证CWE ID格式
func IsValidCWEID(id string) bool {
    // 实现验证逻辑
    return len(id) > 0 && id != ""
}

// 获取CWE的显示名称
func GetDisplayName(cweData interface{}) string {
    switch data := cweData.(type) {
    case *cwe.CWEWeakness:
        return data.Name
    case *cwe.CWECategory:
        return data.Name
    case *cwe.CWEView:
        return data.Name
    default:
        return "未知"
    }
}
```

## 最佳实践

1. **类型安全**: 使用类型断言时始终检查类型
2. **错误处理**: 验证数据完整性
3. **内存管理**: 注意循环引用（TreeNode.Parent）
4. **序列化**: 使用适当的JSON/XML标签

## 下一步

- 了解[API客户端](./api-client)如何使用这些类型
- 查看[示例](/zh/examples/)中的实际用法
- 学习[树操作](./tree)的高级功能
