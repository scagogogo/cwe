# CWE Go 库

[![Go Reference](https://pkg.go.dev/badge/github.com/scagogogo/cwe.svg)](https://pkg.go.dev/github.com/scagogogo/cwe)
[![Documentation](https://img.shields.io/badge/docs-online-blue.svg)](https://scagogogo.github.io/cwe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cwe)](https://goreportcard.com/report/github.com/scagogogo/cwe)
[![Build Status](https://github.com/scagogogo/cwe/workflows/Go/badge.svg)](https://github.com/scagogogo/cwe/actions)

**语言:** [English](README.md) | [简体中文](README.zh.md)

一个用于处理CWE（通用弱点枚举）数据的综合Go语言库，具有API客户端、速率限制、树操作等功能。

## 📚 文档

**[📖 完整文档和API参考](https://scagogogo.github.io/cwe/zh/)**

完整文档包括：
- [API参考](https://scagogogo.github.io/cwe/zh/api/) - 所有类型、函数和方法的详细文档
- [示例](https://scagogogo.github.io/cwe/zh/examples/) - 实用的使用示例和教程
- [入门指南](https://scagogogo.github.io/cwe/zh/api/) - 快速开始和基本用法

## 🚀 快速开始

```bash
go get github.com/scagogogo/cwe
```

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cwe"
)

func main() {
    // 创建API客户端
    client := cwe.NewAPIClient()

    // 获取CWE版本
    version, err := client.GetVersion()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CWE版本: %s\n", version.Version)
    // 输出: CWE版本: 4.12

    // 获取弱点信息
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CWE-79: %s\n", weakness.Name)
    // 输出: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
}
```

## ✨ 功能特性

- **完整的CWE API客户端** - 用于CWE数据访问的完整REST API客户端
- **速率限制** - 内置速率限制以防止API过载
- **树操作** - 构建和遍历CWE层次结构
- **搜索和过滤** - 强大的搜索功能，用于查找特定的CWE
- **数据管理** - 用于管理CWE集合的注册表系统
- **导出/导入** - JSON和XML序列化支持
- **线程安全** - 所有组件都设计为并发使用
- **全面测试** - 92.6%的测试覆盖率

## 🏗️ 架构

代码库组织为专注的模块，以提高可维护性：

### 核心组件
- **`cwe.go`** - 包文档和导出接口
- **`cwe_model.go`** - CWE数据结构和方法
- **`cwe_registry.go`** - CWE注册表管理
- **`cwe_search.go`** - 搜索功能
- **`cwe_utils.go`** - 工具函数

### API客户端
- **`api_client.go`** - 基础API客户端结构
- **`api_client_version.go`** - 版本相关API
- **`api_client_cwe.go`** - CWE数据检索API
- **`api_client_relations.go`** - 关系查询API
- **`api_integration.go`** - 集成功能

### HTTP和速率限制
- **`http_client.go`** - 速率限制HTTP客户端
- **`rate_limiter.go`** - 速率限制实现
- **`data_fetcher_utils.go`** - 数据获取工具

## 🧪 测试

具有92.6%覆盖率的综合测试套件：

### 核心模型测试
- **`cwe_test.go`** - CWE模型基本功能
- **`cwe_registry_test.go`** - 注册表功能
- **`cwe_search_test.go`** - 搜索功能
- **`cwe_utils_test.go`** - 工具函数

### API客户端测试
- **`api_client_test.go`** - API客户端基本功能
- **`api_client_cwe_test.go`** - CWE数据API
- **`api_client_relations_test.go`** - 关系查询API
- **`api_client_version_test.go`** - 版本API
- **`api_integration_test.go`** - 集成功能

### 其他测试
- **`build_tree_test.go`** - 树构建
- **`fetch_category_test.go`** - 类别获取
- **`fetch_multiple_test.go`** - 批量操作
- **`xml_json_test.go`** - 序列化

## 📖 文档和示例

有关全面的文档和示例，请访问我们的**[文档网站](https://scagogogo.github.io/cwe/zh/)**：

- **[API参考](https://scagogogo.github.io/cwe/zh/api/)** - 完整的API文档
- **[示例](https://scagogogo.github.io/cwe/zh/examples/)** - 实用的使用示例：
  - [基本用法](https://scagogogo.github.io/cwe/zh/examples/basic-usage) - 入门指南
  - [获取CWE数据](https://scagogogo.github.io/cwe/zh/examples/fetch-cwe) - 数据检索
  - [构建树](https://scagogogo.github.io/cwe/zh/examples/build-tree) - 层次结构
  - [搜索和过滤](https://scagogogo.github.io/cwe/zh/examples/search-filter) - 查找CWE
  - [导出和导入](https://scagogogo.github.io/cwe/zh/examples/export-import) - 数据持久化
  - [速率限制客户端](https://scagogogo.github.io/cwe/zh/examples/rate-limited) - 高级HTTP用法
  - [支持代理的HTTP客户端](https://scagogogo.github.io/cwe/zh/examples/http-client-proxy) - 代理配置

### 本地运行示例

```
# 克隆仓库
git clone https://github.com/scagogogo/cwe.git
cd cwe

# 运行示例
go run examples/01_basic_usage/main.go
go run examples/02_fetch_cwe/main.go
go run examples/03_build_tree/main.go
go run examples/http_client_example/main.go

# 或使用示例运行器
go run examples/run_examples.go basic_usage
```

## ⚡ 速率限制

该库包含一个复杂的速率限制HTTP客户端，以防止API过载并确保可靠的请求。

### 默认配置

默认情况下，API客户端使用：
- 每10秒1个请求
- 失败时重试3次
- 1秒重试间隔
- 30秒HTTP超时

### 自定义速率限制

```
import (
    "time"
    "net/http"
    "github.com/scagogogo/cwe"
)

// 创建自定义速率限制器（每2秒1个请求）
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// 创建具有自定义速率限制的客户端
client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)

// 所有API请求将自动遵守速率限制
version, err := client.GetVersion()
// 输出: 版本响应将根据需要延迟以遵守速率限制

weakness, err := client.GetWeakness("79")
// 输出: CWE-79数据将在应用速率限制的情况下检索
```

### 动态速率限制调整

```
// 获取当前速率限制器
limiter := client.GetRateLimiter()

// 将速率限制调整为每个请求5秒
limiter.SetInterval(5 * time.Second)
// 输出: 未来的请求现在将在每次调用之间至少等待5秒

// 或设置全新的速率限制器
newLimiter := cwe.NewHTTPRateLimiter(1 * time.Second)
client.SetRateLimiter(newLimiter)
// 输出: 未来的请求现在将在每次调用之间至少等待1秒
```

### 支持代理的HTTP客户端

``go
import (
    "net/http"
    "net/url"
    "time"
    "github.com/scagogogo/cwe"
)

// 创建支持代理的自定义HTTP传输
proxyURL, _ := url.Parse("http://proxy.example.com:8080")
transport := &http.Transport{
    Proxy: http.ProxyURL(proxyURL),
}

// 创建带代理的HTTP客户端
httpClient := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}

// 创建支持代理的CWE HTTP客户端
cweClient := cwe.NewHttpClient(
    cwe.WithMaxRetries(3),
    cwe.WithRetryInterval(time.Second),
    cwe.WithRateLimit(1), // 每秒1个请求
)

// 设置带代理的自定义HTTP客户端
cweClient.SetClient(httpClient)

// 使用客户端通过代理发出请求
resp, err := cweClient.Get(context.Background(), "https://cwe-api.mitre.org/api/v1/version")
if err != nil {
    // 输出: 如果代理连接失败的错误消息
    log.Printf("请求失败: %v", err)
    return
}

// 输出: 通过代理从MITRE API返回的响应状态码和正文
fmt.Printf("响应状态: %d\n", resp.StatusCode)
```

## 🔧 高级用法

### 构建CWE树

```
// 从CWE视图构建层次树
tree, err := cwe.BuildCWETreeWithView(client, "1000")
if err != nil {
    log.Fatal(err)
}

// 遍历树
tree.Walk(func(node *cwe.TreeNode) {
    fmt.Printf("CWE-%s: %s\n", node.CWE.ID, node.CWE.Name)
})
```

### 搜索和过滤

```
// 创建注册表并添加CWE
registry := cwe.NewCWERegistry()
registry.AddCWE(&cwe.CWEWeakness{ID: "79", Name: "跨站脚本"})

// 按关键字搜索
results := registry.SearchByKeyword("脚本")
for _, result := range results {
    fmt.Printf("找到: %s\n", result.Name)
}
```

## 🚀 运行测试

```
# 运行所有测试
go test -v ./...

# 运行带覆盖率的测试
go test -v -cover ./...

# 运行特定测试
go test -v -run TestAPIClient
```

## 🤝 贡献

欢迎贡献！请随时提交Pull Request。对于重大更改，请先打开issue讨论您想要更改的内容。

### 开发设置

```
# 克隆仓库
git clone https://github.com/scagogogo/cwe.git
cd cwe

# 安装依赖
go mod download

# 运行测试
go test -v ./...

# 运行示例
go run examples/01_basic_usage/main.go
```

## 📄 许可证

该项目根据MIT许可证授权 - 有关详细信息，请参阅[LICENSE](LICENSE)文件。

## 🙏 致谢

- [MITRE CWE](https://cwe.mitre.org/) 提供CWE数据和API
- Go社区提供优秀的库和工具

## 📞 支持

- 📖 [文档](https://scagogogo.github.io/cwe/zh/)
- 🐛 [问题跟踪器](https://github.com/scagogogo/cwe/issues)
- 💬 [讨论](https://github.com/scagogogo/cwe/discussions)
