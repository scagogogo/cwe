package examples

import (
	"fmt"
	"os"
)

// RunExample 运行指定的示例
func RunExample(exampleName string) {
	switch exampleName {
	case "rate_limited_http_client":
		fmt.Println("=== 运行速率限制HTTP客户端示例 ===")
		RateLimitedHTTPClientExample()
	default:
		fmt.Printf("未知的示例: %s\n", exampleName)
		fmt.Println("可用的示例:")
		fmt.Println("  rate_limited_http_client - 速率限制HTTP客户端示例")
	}
}

// main 函数是示例运行的入口点
func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run examples/run_examples.go <示例名称>")
		fmt.Println("可用的示例:")
		fmt.Println("  rate_limited_http_client - 速率限制HTTP客户端示例")
		os.Exit(1)
	}

	RunExample(os.Args[1])
}
