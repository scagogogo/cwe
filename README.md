# CWE 工具库

这个Go语言库封装了Common Weakness Enumeration (CWE) 相关的功能，可以作为工具类引入到其他应用中。它提供了处理CWE数据的基本结构和方法，并包含了对[MITRE CWE REST API](https://cwe.mitre.org/api/)的完整封装。

[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cwe)](https://goreportcard.com/report/github.com/scagogogo/cwe)
[![GoDoc](https://godoc.org/github.com/scagogogo/cwe?status.svg)](https://godoc.org/github.com/scagogogo/cwe)

## 📋 目录

- [功能特点](#功能特点)
- [安装](#安装)
- [基本用法](#基本用法)
- [示例](#示例)
- [API文档](#api文档)
- [CWE Top 25](#cwe-top-25)
- [相关资源](#相关资源)
- [贡献](#贡献)
- [许可证](#许可证)

## 🚀 功能特点

- CWE数据结构的管理（ID、名称、描述、URL等）
- CWE层次结构的表示和操作（父子关系）
- 从MITRE官方REST API获取CWE数据
- 支持获取弱点(weakness)、类别(category)和视图(view)
- 支持查询CWE之间的关系（父项、子项、祖先、后代）
- 支持构建和导出完整的CWE树结构
- 支持树形结构的遍历和搜索
- 支持关键字和自定义条件的搜索和筛选
- JSON/XML格式的导入导出
- 支持特定CWE或子树的导出

## 📥 安装

```bash
go get github.com/scagogogo/cwe
```

## 🔰 基本用法

### 创建和操作CWE实例

```go
// 创建新的CWE实例
sqlInjection := cwe.NewCWE("CWE-89", "SQL注入")
sqlInjection.Description = "SQL注入是当用户控制的输入被不安全地包含在SQL查询中时发生的..."
sqlInjection.URL = "https://cwe.mitre.org/data/definitions/89.html"
sqlInjection.Severity = "高"

// 添加缓解措施
sqlInjection.Mitigations = append(sqlInjection.Mitigations, 
    "使用参数化查询", 
    "输入验证", 
    "最小权限原则")

// 建立层次关系
inputValidation := cwe.NewCWE("CWE-20", "输入验证不当")
inputValidation.AddChild(sqlInjection) // 自动设置父子关系

// 检查节点类型
fmt.Printf("是根节点吗? %t\n", inputValidation.IsRoot())
fmt.Printf("是叶子节点吗? %t\n", sqlInjection.IsLeaf())

// 获取路径
path := sqlInjection.GetPath()
for i, node := range path {
    fmt.Printf("%d. %s\n", i, node.ID)
}
```

### 使用注册表管理多个CWE

```go
// 创建新的注册表
registry := cwe.NewRegistry()

// 注册CWE实例
registry.Register(inputValidation)
registry.Register(sqlInjection)

// 设置根节点
registry.Root = inputValidation

// 根据ID获取CWE
xss, err := registry.GetByID("CWE-79")
if err != nil {
    fmt.Printf("未找到CWE-79: %v\n", err)
}
```

### 从MITRE API获取CWE数据

```go
// 创建数据获取器
fetcher := cwe.NewDataFetcher()

// 获取当前CWE版本
version, err := fetcher.GetCurrentVersion()
if err != nil {
    fmt.Printf("获取版本失败: %v\n", err)
} else {
    fmt.Printf("当前CWE版本: %s\n", version)
}

// 获取特定CWE
sqlInjection, err := fetcher.FetchWeakness("89")
if err != nil {
    fmt.Printf("获取CWE-89失败: %v\n", err)
} else {
    fmt.Printf("CWE ID: %s\n", sqlInjection.ID)
    fmt.Printf("名称: %s\n", sqlInjection.Name)
    fmt.Printf("描述: %s\n", sqlInjection.Description)
}

// 构建完整CWE树
registry, err := fetcher.BuildCWETreeWithView("1000")
if err != nil {
    fmt.Printf("构建CWE树失败: %v\n", err)
} else {
    fmt.Printf("注册表中CWE条目数量: %d\n", len(registry.Entries))
}
```

## 📚 示例

在 `examples` 目录中提供了一系列完整的使用示例，展示了库的主要功能:

1. **基本用法** (`examples/01_basic_usage/main.go`): 演示CWE库的基本使用，包括创建CWE对象、建立层次关系、访问对象属性等基础功能。

2. **数据获取** (`examples/02_fetch_cwe/main.go`): 演示如何使用CWE库从API获取CWE数据，包括获取当前版本、获取特定CWE、类别和视图等。

3. **树结构构建** (`examples/03_build_tree/main.go`): 演示如何使用CWE库构建完整的CWE树结构，包括通过视图构建树、遍历树结构、查找节点等功能。

4. **搜索和筛选** (`examples/04_search_and_filter/main.go`): 演示如何使用CWE库搜索和筛选CWE条目，包括按关键字搜索、按ID查找、自定义筛选等。

5. **导出和导入** (`examples/05_export_import/main.go`): 演示如何导出和导入CWE数据，包括将CWE数据保存为JSON/XML格式以及从这些格式导入。

## 📖 API文档

### 核心类型

#### `CWE` 结构体

表示一个CWE实体，包含其基本信息和关系。

```go
type CWE struct {
    ID          string   // CWE ID，例如 "CWE-89"
    Name        string   // CWE名称
    Description string   // 描述信息
    URL         string   // 官方链接
    Severity    string   // 严重程度
    Mitigations []string // 缓解措施列表
    Parent      *CWE     // 父节点引用
    Children    []*CWE   // 子节点切片
}
```

**主要方法:**

- `NewCWE(id, name string) *CWE`: 创建新的CWE实例
- `AddChild(child *CWE)`: 添加子节点，自动设置父子关系
- `IsRoot() bool`: 检查是否为根节点（无父节点）
- `IsLeaf() bool`: 检查是否为叶子节点（无子节点）
- `GetNumericID() (int, error)`: 获取数字形式的ID
- `GetPath() []*CWE`: 获取从根到此节点的路径

#### `Registry` 结构体

管理多个CWE实例的容器。

```go
type Registry struct {
    Entries map[string]*CWE // 所有CWE条目的映射 (ID -> CWE)
    Root    *CWE            // 根节点
}
```

**主要方法:**

- `NewRegistry() *Registry`: 创建新的注册表
- `Register(cwe *CWE)`: 注册一个CWE实例
- `GetByID(id string) (*CWE, error)`: 根据ID获取CWE
- `ExportToJSON() ([]byte, error)`: 导出为JSON格式
- `ExportToXML() ([]byte, error)`: 导出为XML格式
- `ImportFromJSON(data []byte) error`: 从JSON导入
- `ImportFromXML(data []byte) error`: 从XML导入

#### `APIClient` 结构体

用于访问MITRE CWE REST API的客户端。

```go
type APIClient struct {
    BaseURL    string
    HTTPClient *http.Client
}
```

**主要方法:**

- `NewAPIClient() *APIClient`: 创建新的API客户端
- `GetCurrentVersion() (string, error)`: 获取当前CWE版本
- `GetWeakness(id string) (*CWE, error)`: 获取弱点
- `GetCategory(id string) (*CWE, error)`: 获取类别
- `GetView(id string) (*CWE, error)`: 获取视图
- `GetParents(id, viewID string) ([]string, error)`: 获取父节点
- `GetChildren(id, viewID string) ([]string, error)`: 获取子节点

#### `DataFetcher` 结构体

用于获取和组织CWE数据的高级工具。

```go
type DataFetcher struct {
    Client *APIClient
}
```

**主要方法:**

- `NewDataFetcher() *DataFetcher`: 创建新的数据获取器
- `FetchWeakness(id string) (*CWE, error)`: 获取弱点
- `FetchCategory(id string) (*CWE, error)`: 获取类别
- `FetchView(id string) (*CWE, error)`: 获取视图
- `FetchMultiple(ids []string) (*Registry, error)`: 获取多个CWE
- `FetchCWEByIDWithRelations(id, viewID string) (*CWE, error)`: 获取CWE及其关系
- `BuildCWETreeWithView(viewID string) (*Registry, error)`: 构建CWE树

### 辅助函数

- `FindByID(root *CWE, id string) *CWE`: 在树中查找特定ID的CWE
- `FindByKeyword(root *CWE, keyword string) []*CWE`: 在树中查找包含特定关键字的CWE
- `WalkTree(root *CWE, callback func(*CWE) bool)`: 遍历CWE树并对每个节点执行回调函数

## 📊 CWE Top 25

[CWE Top 25 最危险软件弱点列表](https://cwe.mitre.org/top25/) 是由MITRE和SANS机构联合发布的安全弱点排名，反映了当前最常见和最关键的软件安全漏洞。

这个列表对于安全研究人员、开发人员和安全专业人员来说是非常有价值的资源，可以帮助他们优先处理最危险的安全问题。

使用本库，你可以方便地获取这些高风险CWE的详细信息：

```go
// 获取CWE Top 25中的条目
fetcher := cwe.NewDataFetcher()
top25IDs := []string{"119", "79", "89", "20", "125", "78", "416"} // 示例，实际Top 25列表请参考官方网站
top25Registry, err := fetcher.FetchMultiple(top25IDs)
if err != nil {
    fmt.Printf("获取Top 25失败: %v\n", err)
}
```

## 🔗 相关资源

- [MITRE CWE官方网站](https://cwe.mitre.org/)
- [CWE Top 25 最危险软件弱点](https://cwe.mitre.org/top25/)
- [CWE REST API文档](https://cwe.mitre.org/api/)

## 👥 贡献

欢迎贡献！如果您有任何改进意见或发现错误，请提交Issue或Pull Request。

## 📄 许可证

MIT 