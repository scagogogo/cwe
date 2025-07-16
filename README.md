# CWE Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/scagogogo/cwe.svg)](https://pkg.go.dev/github.com/scagogogo/cwe)
[![Documentation](https://img.shields.io/badge/docs-online-blue.svg)](https://scagogogo.github.io/cwe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Go library for working with CWE (Common Weakness Enumeration) data, featuring API clients, rate limiting, tree operations, and more.

## 📚 Documentation

**[📖 Complete Documentation & API Reference](https://scagogogo.github.io/cwe/)**

The complete documentation includes:
- [API Reference](https://scagogogo.github.io/cwe/api/) - Detailed documentation for all types, functions, and methods
- [Examples](https://scagogogo.github.io/cwe/examples/) - Practical usage examples and tutorials
- [Getting Started Guide](https://scagogogo.github.io/cwe/api/) - Quick start and basic usage

## 🚀 Quick Start

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
    // Create API client
    client := cwe.NewAPIClient()

    // Get CWE version
    version, err := client.GetVersion()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CWE Version: %s\n", version.Version)

    // Fetch a weakness
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CWE-79: %s\n", weakness.Name)
}
```

这个库提供了用于操作CWE (Common Weakness Enumeration) 数据的Go语言工具。

## 代码组织

代码已根据功能模块重构为更小的文件，提高了可维护性：

1. **核心模型和数据结构**
   - `cwe.go` (14行): 包文档和导出接口
   - `cwe_model.go` (151行): CWE数据结构和方法
   - `cwe_registry.go` (117行): CWE注册表管理
   - `cwe_search.go` (45行): 搜索功能
   - `cwe_utils.go` (68行): 工具函数

2. **API客户端**
   - `api_client.go` (54行): 基础API客户端结构
   - `api_client_version.go` (40行): 版本相关API
   - `api_client_cwe.go` (138行): CWE数据检索API
   - `api_client_relations.go` (129行): 关系查询API
   - `api_integration.go` (377行): 集成功能

## 测试组织

测试文件与功能文件对应，测试覆盖率为92.6%：

1. **核心模型测试**
   - `cwe_test.go`: 测试CWE模型基本功能
   - `cwe_registry_test.go`: 测试注册表功能
   - `cwe_search_test.go`: 测试搜索功能
   - `cwe_utils_test.go`: 测试工具函数

2. **API客户端测试**
   - `api_client_test.go`: 测试API客户端基础功能
   - `api_client_cwe_test.go`: 测试CWE数据API
   - `api_client_relations_test.go`: 测试关系查询API
   - `api_client_version_test.go`: 测试版本API
   - `api_integration_test.go`: 测试集成功能

3. **其他测试文件**
   - `build_tree_test.go`: 测试树构建
   - `fetch_category_test.go`: 测试分类获取
   - `fetch_multiple_test.go`: 测试批量获取
   - `xml_json_test.go`: 测试序列化

## 📖 Documentation & Examples

For comprehensive documentation and examples, visit our **[Documentation Website](https://scagogogo.github.io/cwe/)**:

- **[API Reference](https://scagogogo.github.io/cwe/api/)** - Complete API documentation
- **[Examples](https://scagogogo.github.io/cwe/examples/)** - Practical usage examples:
  - [Basic Usage](https://scagogogo.github.io/cwe/examples/basic-usage) - Getting started
  - [Fetching CWE Data](https://scagogogo.github.io/cwe/examples/fetch-cwe) - Data retrieval
  - [Building Trees](https://scagogogo.github.io/cwe/examples/build-tree) - Hierarchical structures
  - [Search & Filter](https://scagogogo.github.io/cwe/examples/search-filter) - Finding CWEs
  - [Export & Import](https://scagogogo.github.io/cwe/examples/export-import) - Data persistence
  - [Rate Limited Client](https://scagogogo.github.io/cwe/examples/rate-limited) - Advanced HTTP usage

### Running Examples Locally

```bash
# Clone the repository
git clone https://github.com/scagogogo/cwe.git
cd cwe

# Run examples
go run examples/01_basic_usage/main.go
go run examples/02_fetch_cwe/main.go
go run examples/03_build_tree/main.go

# Or use the example runner
go run examples/run_examples.go basic_usage
```

## 许可证

MIT License

# 速率限制HTTP客户端

这个库提供了一个带速率限制功能的HTTP客户端，可以控制向服务器发送请求的频率，避免因请求过于频繁而被目标服务器限流或封禁。

## 主要功能

- 对HTTP请求进行速率限制，控制请求发送频率
- 支持自定义请求间隔时间
- 支持动态调整速率限制
- 完全兼容标准库的`http.Client`接口

## 安装

```bash
go get github.com/scagogogo/cwe
```

## 快速开始

### 使用默认客户端

默认客户端的速率限制为每10秒1个请求：

```go
import "github.com/scagogogo/cwe"

// 使用默认的速率限制客户端
resp, err := cwe.DefaultRateLimitedClient.Get("https://api.example.com/data")
if err != nil {
    // 处理错误
}
defer resp.Body.Close()
// 处理响应...
```

### 自定义速率限制

创建自定义速率限制的客户端：

```go
import (
    "github.com/scagogogo/cwe"
    "time"
    "net/http"
)

// 创建一个2秒1个请求的速率限制器
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// 创建带有自定义速率限制器的客户端
client := cwe.NewRateLimitedHTTPClient(http.DefaultClient, limiter)

// 发送请求
resp, err := client.Get("https://api.example.com/data")
if err != nil {
    // 处理错误
}
defer resp.Body.Close()
// 处理响应...
```

### 动态调整速率限制

在程序运行期间可以动态调整速率限制：

```go
// 获取当前速率限制器
limiter := client.GetRateLimiter()

// 调整速率限制为5秒1个请求
limiter.SetInterval(5 * time.Second)

// 或者直接设置新的速率限制器
newLimiter := cwe.NewHTTPRateLimiter(1 * time.Second)
client.SetRateLimiter(newLimiter)
```

## 示例

查看 [examples/rate_limited_http_client_example.go](examples/rate_limited_http_client_example.go) 获取完整的使用示例。

运行示例：

```bash
go run examples/run_examples.go rate_limited_http_client
```

## 测试

运行单元测试：

```bash
go test -v
```

## 许可证

MIT 

## 功能特性

- 提供完整的CWE数据访问和查询功能
- 支持通过ID、关键字和其他属性进行搜索
- 支持构建和遍历CWE层次结构
- 提供数据导入和导出功能
- 包含速率限制的HTTP客户端，可防止请求过于频繁导致API限流

## 组件

### 速率限制HTTP客户端

包含一个带有速率限制功能的HTTP客户端，可以控制向服务器发送请求的频率，避免因请求过于频繁而被目标服务器限流或封禁。

```go
// 创建一个2秒1个请求的速率限制器
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// 创建带有自定义速率限制器的客户端
client := cwe.NewRateLimitedHTTPClient(http.DefaultClient, limiter)

// 发送请求（会自动遵循速率限制）
resp, err := client.Get("https://api.example.com/data")
```

更多示例请参考 [examples/06_rate_limited_client](examples/06_rate_limited_client/main.go)。

## 速率限制的API客户端

从版本X.X.X开始，`APIClient`已集成`RateLimitedHTTPClient`，为所有API请求提供自动速率限制功能。这可以有效防止因请求过于频繁而被CWE API服务器限流或封禁。

### 默认设置

默认情况下，`APIClient`内部使用一个配置为每10秒1个请求的`RateLimitedHTTPClient`：

```go
// 创建默认配置的APIClient
client := cwe.NewAPIClient()

// 该客户端的所有API请求都会自动限速
version, err := client.GetVersion()
weakness, err := client.GetWeakness("79")
```

### 自定义速率限制

可以通过以下方法自定义API客户端的速率限制：

```go
// 方法1：创建时指定速率限制器
customLimiter := cwe.NewHTTPRateLimiter(5 * time.Second) // 每5秒1个请求
client := cwe.NewAPIClientWithOptions("", 30*time.Second, customLimiter)

// 方法2：动态获取并修改速率限制器
client := cwe.NewAPIClient()
limiter := client.GetRateLimiter()
limiter.SetInterval(2 * time.Second) // 修改为每2秒1个请求

// 方法3：直接设置新的速率限制器
newLimiter := cwe.NewHTTPRateLimiter(3 * time.Second)
client.SetRateLimiter(newLimiter)
```

### 示例

请查看 [examples/rate_limited_api_client_example.go](examples/rate_limited_api_client_example.go) 获取更多关于如何使用带速率限制的API客户端的示例。

运行示例：

```bash
go run examples/rate_limited_api_client_example.go
``` 

# CWE REST API Go客户端

这是一个用于访问CWE（Common Weakness Enumeration）REST API的Go客户端库。它提供了一个简单、可靠且线程安全的方式来查询CWE数据。

## 特性

- 支持所有CWE REST API端点
- 内置速率限制，防止API请求过载
- 自动重试机制，提高请求可靠性
- 完整的类型定义和文档
- 线程安全设计
- 可自定义的HTTP客户端配置

## 安装

```bash
go get github.com/yourusername/cwe
```

## 快速开始

### 基本用法

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/yourusername/cwe"
)

func main() {
    // 创建默认客户端
    client := cwe.NewAPIClient()
    
    // 获取CWE版本信息
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("获取CWE版本失败: %v", err)
    }
    
    fmt.Printf("当前CWE版本: %s，发布日期: %s\n", version.Version, version.ReleaseDate)
}
```

### 自定义配置

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/yourusername/cwe"
)

func main() {
    // 创建自定义HTTP客户端
    httpClient := cwe.NewHTTPClient(
        &http.Client{Timeout: 30 * time.Second},
        cwe.NewHTTPRateLimiter(5 * time.Second), // 每5秒一个请求
        3,                                       // 最多重试3次
        1 * time.Second,                         // 重试间隔1秒
    )
    
    // 使用自定义配置创建API客户端
    client := cwe.NewAPIClientWithOptionsV2(
        "https://custom-cwe-api.example.com/api/v1",
        httpClient,
    )
    
    // 获取CWE版本信息
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("获取CWE版本失败: %v", err)
    }
    
    fmt.Printf("当前CWE版本: %s，发布日期: %s\n", version.Version, version.ReleaseDate)
}
```

## 速率限制

从版本X.X.X开始，`APIClient`已集成速率限制和自动重试功能，为所有API请求提供可靠性保障。这可以有效防止因请求过于频繁而被CWE API服务器限流或封禁。

### 默认配置

默认情况下，`APIClient`使用以下配置：

- 每10秒限制1个请求
- 请求失败时最多重试3次
- 重试间隔为1秒
- HTTP请求超时时间为30秒

### 自定义速率限制

你可以根据需要调整速率限制和重试策略：

```go
// 创建自定义速率限制器
limiter := cwe.NewHTTPRateLimiter(5 * time.Second) // 每5秒一个请求

// 创建自定义HTTP客户端
client := cwe.NewHTTPClient(
    &http.Client{Timeout: 30 * time.Second},
    limiter,
    5,                // 最多重试5次
    2 * time.Second,  // 重试间隔2秒
)

// 使用自定义客户端
apiClient := cwe.NewAPIClientWithOptionsV2("", client)
```

## 错误处理

该库使用标准的Go错误处理方式。所有的错误都会包含详细的错误信息，包括：

- HTTP请求错误
- API响应错误
- 重试次数和原因
- 速率限制状态

示例：

```go
version, err := client.GetVersion()
if err != nil {
    switch {
    case strings.Contains(err.Error(), "达到最大重试次数"):
        log.Printf("请求失败，已重试最大次数: %v", err)
    case strings.Contains(err.Error(), "请求超时"):
        log.Printf("请求超时: %v", err)
    default:
        log.Printf("未知错误: %v", err)
    }
    return
}
```

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License 