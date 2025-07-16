# CWE Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/scagogogo/cwe.svg)](https://pkg.go.dev/github.com/scagogogo/cwe)
[![Documentation](https://img.shields.io/badge/docs-online-blue.svg)](https://scagogogo.github.io/cwe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/scagogogo/cwe)](https://goreportcard.com/report/github.com/scagogogo/cwe)
[![Build Status](https://github.com/scagogogo/cwe/workflows/Go/badge.svg)](https://github.com/scagogogo/cwe/actions)

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

## ✨ Features

- **Complete CWE API Client** - Full REST API client for CWE data access
- **Rate Limiting** - Built-in rate limiting to prevent API overload
- **Tree Operations** - Build and traverse CWE hierarchical structures
- **Search & Filter** - Powerful search capabilities for finding specific CWEs
- **Data Management** - Registry system for managing CWE collections
- **Export/Import** - JSON and XML serialization support
- **Thread Safe** - All components designed for concurrent usage
- **Comprehensive Testing** - 92.6% test coverage

## 🏗️ Architecture

The codebase is organized into focused modules for better maintainability:

### Core Components
- **`cwe.go`** - Package documentation and exported interfaces
- **`cwe_model.go`** - CWE data structures and methods
- **`cwe_registry.go`** - CWE registry management
- **`cwe_search.go`** - Search functionality
- **`cwe_utils.go`** - Utility functions

### API Client
- **`api_client.go`** - Base API client structure
- **`api_client_version.go`** - Version-related APIs
- **`api_client_cwe.go`** - CWE data retrieval APIs
- **`api_client_relations.go`** - Relationship query APIs
- **`api_integration.go`** - Integration features

### HTTP & Rate Limiting
- **`http_client.go`** - Rate-limited HTTP client
- **`rate_limiter.go`** - Rate limiting implementation
- **`data_fetcher_utils.go`** - Data fetching utilities

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

## 🧪 Testing

Comprehensive test suite with 92.6% coverage:

### Core Model Tests
- **`cwe_test.go`** - CWE model basic functionality
- **`cwe_registry_test.go`** - Registry functionality
- **`cwe_search_test.go`** - Search functionality
- **`cwe_utils_test.go`** - Utility functions

### API Client Tests
- **`api_client_test.go`** - API client basic functionality
- **`api_client_cwe_test.go`** - CWE data APIs
- **`api_client_relations_test.go`** - Relationship query APIs
- **`api_client_version_test.go`** - Version APIs
- **`api_integration_test.go`** - Integration features

### Additional Tests
- **`build_tree_test.go`** - Tree building
- **`fetch_category_test.go`** - Category fetching
- **`fetch_multiple_test.go`** - Batch operations
- **`xml_json_test.go`** - Serialization

## ⚡ Rate Limiting

The library includes a sophisticated rate-limited HTTP client to prevent API overload and ensure reliable requests.

### Default Configuration

By default, the API client uses:
- 1 request per 10 seconds
- 3 retry attempts on failure
- 1 second retry interval
- 30 second HTTP timeout

### Custom Rate Limiting

```go
import (
    "time"
    "net/http"
    "github.com/scagogogo/cwe"
)

// Create a custom rate limiter (1 request per 2 seconds)
limiter := cwe.NewHTTPRateLimiter(2 * time.Second)

// Create client with custom rate limiting
client := cwe.NewAPIClientWithOptions("", 30*time.Second, limiter)

// All API requests will automatically respect rate limits
version, err := client.GetVersion()
weakness, err := client.GetWeakness("79")
```

### Dynamic Rate Limit Adjustment

```go
// Get current rate limiter
limiter := client.GetRateLimiter()

// Adjust rate limit to 5 seconds per request
limiter.SetInterval(5 * time.Second)

// Or set a completely new rate limiter
newLimiter := cwe.NewHTTPRateLimiter(1 * time.Second)
client.SetRateLimiter(newLimiter)
```

## 🔧 Advanced Usage

### Building CWE Trees

```go
// Build a hierarchical tree from a CWE view
tree, err := cwe.BuildCWETreeWithView(client, "1000")
if err != nil {
    log.Fatal(err)
}

// Traverse the tree
tree.Walk(func(node *cwe.TreeNode) {
    fmt.Printf("CWE-%s: %s\n", node.CWE.ID, node.CWE.Name)
})
```

### Search and Filter

```go
// Create a registry and add CWEs
registry := cwe.NewCWERegistry()
registry.AddCWE(&cwe.CWEWeakness{ID: "79", Name: "Cross-site Scripting"})

// Search by keyword
results := registry.SearchByKeyword("script")
for _, result := range results {
    fmt.Printf("Found: %s\n", result.Name)
}
```

## 🚀 Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -v -cover ./...

# Run specific test
go test -v -run TestAPIClient
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/scagogogo/cwe.git
cd cwe

# Install dependencies
go mod download

# Run tests
go test -v ./...

# Run examples
go run examples/01_basic_usage/main.go
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [MITRE CWE](https://cwe.mitre.org/) for providing the CWE data and API
- The Go community for excellent libraries and tools

## 📞 Support

- 📖 [Documentation](https://scagogogo.github.io/cwe/)
- 🐛 [Issue Tracker](https://github.com/scagogogo/cwe/issues)
- 💬 [Discussions](https://github.com/scagogogo/cwe/discussions)