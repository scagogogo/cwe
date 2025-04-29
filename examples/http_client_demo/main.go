package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/scagogogo/cwe"
)

func main() {
	// 创建一个新的HTTP客户端
	client := cwe.NewHttpClient(
		cwe.WithMaxRetries(3),
		cwe.WithRetryInterval(time.Second),
		cwe.WithRateLimit(1),
	)
	defer client.Close()

	// 发送GET请求示例
	ctx := context.Background()
	resp, err := client.Get(ctx, "https://api.example.com/data")
	if err != nil {
		log.Printf("GET请求失败: %v\n", err)
		return
	}
	fmt.Printf("GET响应状态码: %d\n", resp.StatusCode)

	// 发送POST请求示例
	postData := []byte(`{"key": "value"}`)
	resp, err = client.Post(ctx, "https://api.example.com/data", postData)
	if err != nil {
		log.Printf("POST请求失败: %v\n", err)
		return
	}
	fmt.Printf("POST响应状态码: %d\n", resp.StatusCode)
}
