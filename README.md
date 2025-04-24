# CWE 库

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

## 使用示例

请参阅`examples`目录中的示例程序：

1. `01_basic_usage`: 基本使用
2. `02_fetch_cwe`: 获取CWE数据
3. `03_build_tree`: 构建CWE树
4. `04_search_and_filter`: 搜索和过滤
5. `05_export_import`: 导出和导入

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