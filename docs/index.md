---
layout: home

hero:
  name: "CWE Go Library"
  text: "Common Weakness Enumeration for Go"
  tagline: "A comprehensive Go library for working with CWE data, featuring API clients, rate limiting, and tree operations"
  image:
    src: /logo.svg
    alt: CWE Go Library
  actions:
    - theme: brand
      text: Get Started
      link: /api/
    - theme: alt
      text: View Examples
      link: /examples/
    - theme: alt
      text: 简体中文
      link: /zh/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cwe

features:
  - icon: 🚀
    title: Easy to Use
    details: Simple and intuitive API for fetching and working with CWE data from the official MITRE API.
  
  - icon: ⚡
    title: Rate Limited
    details: Built-in rate limiting and retry mechanisms to prevent API overload and ensure reliable requests.
  
  - icon: 🌳
    title: Tree Operations
    details: Comprehensive support for building and traversing CWE hierarchical structures.
  
  - icon: 🔍
    title: Search & Filter
    details: Powerful search and filtering capabilities to find specific CWE entries quickly.
  
  - icon: 📊
    title: Data Management
    details: Registry system for managing CWE collections with import/export functionality.
  
  - icon: 🛡️
    title: Thread Safe
    details: All components are designed to be thread-safe for use in concurrent applications.
---

## Quick Start

Install the library:

```bash
go get github.com/scagogogo/cwe
```

Basic usage:

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cwe"
)

func main() {
    // Create a new API client
    client := cwe.NewAPIClient()
    
    // Get CWE version information
    version, err := client.GetVersion()
    if err != nil {
        log.Fatalf("Failed to get CWE version: %v", err)
    }
    
    fmt.Printf("Current CWE version: %s, Release date: %s\n", 
        version.Version, version.ReleaseDate)
    
    // Fetch a specific weakness
    weakness, err := client.GetWeakness("79")
    if err != nil {
        log.Fatalf("Failed to get weakness: %v", err)
    }
    
    fmt.Printf("CWE-79: %s\n", weakness.Name)
}
```

## Features

### 🎯 Core Components

- **API Client**: Complete REST API client for CWE data
- **Data Fetcher**: High-level interface for fetching and converting CWE data
- **Registry**: Collection management for CWE entries
- **HTTP Client**: Rate-limited HTTP client with retry logic
- **Tree Operations**: Build and traverse CWE hierarchies

### 📈 Advanced Features

- **Rate Limiting**: Configurable request rate limiting
- **Auto Retry**: Automatic retry on failed requests
- **Concurrent Safe**: Thread-safe design for concurrent usage
- **Export/Import**: JSON and XML serialization support
- **Search**: Flexible search and filtering capabilities

## Documentation

- [API Reference](/api/) - Complete API documentation
- [Examples](/examples/) - Practical usage examples
- [GitHub Repository](https://github.com/scagogogo/cwe) - Source code and issues

## License

This project is licensed under the MIT License.
