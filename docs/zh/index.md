---
layout: home

hero:
  name: "CWE Go 库"
  text: "通用弱点枚举 Go 语言库"
  tagline: 一个用于处理CWE数据的综合Go语言库，具有API客户端、速率限制和树操作功能
  actions:
    - theme: brand
      text: 开始使用
      link: /zh/api/
    - theme: alt
      text: 查看示例
      link: /zh/examples/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cwe
  image:
    src: /logo.svg
    alt: CWE Go Library

features:
  - icon: 🚀
    title: 易于使用
    details: 简单直观的API，用于从官方MITRE API获取和处理CWE数据。

  - icon: ⚡
    title: 速率限制
    details: 内置速率限制和重试机制，防止API过载并确保可靠的请求。

  - icon: 🌳
    title: 树操作
    details: 全面支持构建和遍历CWE层次结构。

  - icon: 🔍
    title: 搜索和过滤
    details: 强大的搜索和过滤功能，快速找到特定的CWE条目。

  - icon: 📊
    title: 数据管理
    details: 用于管理CWE集合的注册表系统，具有导入/导出功能。

  - icon: 🛡️
    title: 线程安全
    details: 所有组件都设计为线程安全，适用于并发应用程序。
---

## 快速开始 {#quick-start}

安装库：

```bash
go get github.com/scagogogo/cwe
```

基本用法：

```go
package main

import (
    "fmt"
    "log"

    "github.com/scagogogo/cwe"
)

func main() {
    // 创建新的API客户端
    client := cwe.NewAPIClient()

    // 获取CWE版本信息
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("获取CWE版本失败: %v", err)
    }

    fmt.Printf("当前CWE版本: %s，发布日期: %s\n", 
        version.Version, version.ReleaseDate)

    // 获取特定弱点
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("获取弱点失败: %v", err)
    }

    fmt.Printf("CWE-79: %s\n", weakness.Name)
}
```

## 功能特性 {#features}

### 🎯 核心组件 {#core-components}

- **API客户端**: 用于CWE数据的完整REST API客户端
- **数据获取器**: 用于获取和转换CWE数据的高级接口
- **注册表**: CWE条目的集合管理
- **HTTP客户端**: 具有重试逻辑的速率限制HTTP客户端
- **树操作**: 构建和遍历CWE层次结构

### 📈 高级功能 {#advanced-features}

- **速率限制**: 可配置的请求速率限制
- **自动重试**: 失败请求的自动重试
- **并发安全**: 为并发使用设计的线程安全
- **导出/导入**: JSON和XML序列化支持
- **搜索**: 灵活的搜索和过滤功能

## 文档 {#documentation}

- [API 参考](/zh/api/) - 完整的API文档
- [示例](/zh/examples/) - 实用的使用示例
- [GitHub 仓库](https://github.com/scagogogo/cwe) - 源代码和问题

## 许可证 {#license}

该项目基于MIT许可证授权。
