# 示例

本节提供了CWE Go库的实用示例，展示如何在实际项目中使用各种功能。

## 概述

我们提供了以下示例：

- **[基本用法](./basic-usage)** - 开始使用库的基础知识
- **[获取CWE数据](./fetch-cwe)** - 从API获取CWE数据
- **[构建树](./build-tree)** - 创建和操作CWE层次结构
- **[搜索和过滤](./search-filter)** - 查找特定的CWE条目
- **[导出和导入](./export-import)** - 数据序列化和持久化
- **[速率限制客户端](./rate-limited)** - 高级HTTP客户端使用

## 快速开始示例

### 获取CWE版本信息

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("获取版本失败: %v", err)
    }
    
    fmt.Printf("CWE版本: %s\n", version.Version)
    fmt.Printf("发布日期: %s\n", version.ReleaseDate)
}
```

### 获取特定弱点

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    client := cwe.NewAPIClient()
    
    // 获取SQL注入弱点
    weakness, err := client.GetWeakness("89")
    if err != nil {
        log.Fatalf("获取弱点失败: %v", err)
    }
    
    fmt.Printf("ID: %s\n", weakness.ID)
    fmt.Printf("名称: %s\n", weakness.Name)
    fmt.Printf("描述: %s\n", weakness.Description)
}
```

### 搜索CWE

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // 创建注册表
    registry := cwe.NewCWERegistry()
    
    // 添加一些CWE数据
    registry.AddCWE(&cwe.CWEWeakness{
        ID:   "79",
        Name: "跨站脚本",
        Description: "应用程序在生成网页时未正确验证输入",
    })
    
    registry.AddCWE(&cwe.CWEWeakness{
        ID:   "89",
        Name: "SQL注入",
        Description: "应用程序在构造SQL命令时未正确验证输入",
    })
    
    // 搜索包含"注入"的CWE
    results := registry.SearchByKeyword("注入")
    
    fmt.Printf("找到 %d 个结果:\n", len(results))
    for _, result := range results {
        fmt.Printf("- CWE-%s: %s\n", result.ID, result.Name)
    }
}
```

## 运行示例

### 本地运行

```bash
# 克隆仓库
git clone https://github.com/scagogogo/cwe.git
cd cwe

# 运行基本示例
go run examples/01_basic_usage/main.go

# 运行数据获取示例
go run examples/02_fetch_cwe/main.go

# 运行树构建示例
go run examples/03_build_tree/main.go
```

### 使用示例运行器

```bash
# 运行特定示例
go run examples/run_examples.go basic_usage

# 运行所有示例
go run examples/run_examples.go all
```

## 常见用例

### 1. 批量获取CWE数据

```go
// 获取多个CWE
ids := []string{"79", "89", "20"}
cwes, err := client.GetCWEs(ids)
if err != nil {
    log.Fatal(err)
}

for id, cwe := range cwes {
    fmt.Printf("CWE-%s: %s\n", id, cwe.Name)
}
```

### 2. 构建CWE层次树

```go
// 从视图构建树
tree, err := cwe.BuildCWETreeWithView(client, "1000")
if err != nil {
    log.Fatal(err)
}

// 遍历树
tree.Walk(func(node *cwe.TreeNode) {
    fmt.Printf("CWE-%s: %s (深度: %d)\n", 
        node.CWE.ID, node.CWE.Name, node.Depth)
})
```

### 3. 自定义速率限制

```go
// 创建自定义速率限制器
limiter := cwe.NewHTTPRateLimiter(5 * time.Second)

// 创建客户端
client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)

// 使用客户端
weakness, err := client.GetWeakness("79")
```

## 最佳实践

1. **错误处理**: 始终检查和处理错误
2. **速率限制**: 使用适当的速率限制避免API限制
3. **资源管理**: 在适当的时候重用客户端实例
4. **并发**: 利用库的线程安全特性进行并发操作

## 下一步

- 查看[API参考](/zh/api/)了解详细的API文档
- 浏览具体的示例页面了解更多用例
- 访问[GitHub仓库](https://github.com/scagogogo/cwe)获取完整的源代码
