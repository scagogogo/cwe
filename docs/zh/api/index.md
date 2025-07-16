# API 参考

CWE Go 库提供了一个全面的API，用于处理CWE（通用弱点枚举）数据。本文档涵盖了所有可用的类型、函数和方法。

## 概述

该库的核心组件包括：

- **[核心类型](./core-types)** - 基本的CWE数据结构
- **[API客户端](./api-client)** - 用于访问CWE REST API的客户端
- **[数据获取器](./data-fetcher)** - 高级数据获取工具
- **[注册表](./registry)** - CWE数据的集合管理
- **[HTTP客户端](./http-client)** - 速率限制的HTTP客户端
- **[速率限制器](./rate-limiter)** - 请求速率控制
- **[搜索和工具](./search-utils)** - 搜索和实用功能
- **[树操作](./tree)** - 层次结构操作

## 快速开始

### 安装

```bash
go get github.com/scagogogo/cwe
```

### 基本用法

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
    
    // 获取弱点信息
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("CWE-79: %s\n", weakness.Name)
}
```

## 主要功能

### API客户端

API客户端提供了访问CWE REST API的完整功能：

```go
// 创建默认客户端
client := cwe.NewAPIClient()

// 创建自定义客户端
client := cwe.NewAPIClientWithOptions(
    "https://custom-api.example.com",
    30*time.Second,
    cwe.NewHTTPRateLimiter(5*time.Second),
)
```

### 速率限制

内置速率限制确保API请求的可靠性：

```go
// 创建速率限制器
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// 动态调整速率限制
limiter.SetInterval(5 * time.Second)
```

### 数据管理

使用注册表管理CWE数据集合：

```go
// 创建注册表
registry := cwe.NewCWERegistry()

// 添加CWE
registry.AddCWE(&cwe.CWEWeakness{
    ID:   "79",
    Name: "跨站脚本",
})

// 搜索
results := registry.SearchByKeyword("脚本")
```

## 错误处理

该库使用标准的Go错误处理模式：

```go
weakness, err := client.GetWeakness("79")
if err != nil {
    // 处理错误
    log.Printf("获取弱点失败: %v", err)
    return
}

// 使用数据
fmt.Printf("弱点名称: %s\n", weakness.Name)
```

## 并发使用

所有组件都设计为线程安全：

```go
// 可以在多个goroutine中安全使用
go func() {
    weakness, _ := client.GetWeakness("79")
    // 处理数据...
}()

go func() {
    category, _ := client.GetCategory("20")
    // 处理数据...
}()
```

## 下一步

- 查看[示例](/zh/examples/)了解实际使用案例
- 浏览[核心类型](./core-types)了解数据结构
- 学习[API客户端](./api-client)的详细用法
