package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/scagogogo/cwe" // 修正导入路径
)

// 简单的HTTP服务器，用于测试HTTP客户端
func startTestServer() *http.Server {
	mux := http.NewServeMux()

	// 模拟正常响应
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "成功响应",
		})
	})

	// 模拟服务器错误，第三次请求才会成功
	var errorCount int
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		errorCount++
		if errorCount >= 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "ok",
				"message": "在第3次尝试后成功",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": fmt.Sprintf("第%d次尝试失败", errorCount),
		})
	})

	// 模拟速率限制
	mux.HandleFunc("/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "ok",
			"timestamp": fmt.Sprintf("%d", time.Now().UnixNano()),
		})
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// 等待服务器启动
	time.Sleep(100 * time.Millisecond)
	fmt.Println("测试服务器已启动在 http://localhost:8080")

	return server
}

func main() {
	// 启动测试服务器
	server := startTestServer()
	defer func() {
		// 关闭服务器
		if err := server.Close(); err != nil {
			log.Printf("关闭服务器时出错: %v", err)
		}
	}()

	// 1. 创建一个自定义的HTTP客户端
	client := cwe.NewHTTPClient(
		&http.Client{Timeout: 5 * time.Second},
		cwe.NewHTTPRateLimiter(500*time.Millisecond), // 速率限制：每500ms一个请求
		3,                    // 最多重试3次
		200*time.Millisecond, // 重试间隔200ms
	)

	// 2. 测试正常请求
	fmt.Println("\n=== 测试正常请求 ===")
	resp, err := client.Get("http://localhost:8080/ok")
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("读取响应体失败: %v", err)
	}

	fmt.Printf("状态码: %d\n", resp.StatusCode)
	fmt.Printf("响应: %s\n", string(body))

	// 3. 测试自动重试
	fmt.Println("\n=== 测试自动重试 ===")
	fmt.Println("请求会重试到成功为止，或者达到最大重试次数")

	retryResp, err := client.Get("http://localhost:8080/error")
	if err != nil {
		log.Fatalf("重试后请求仍然失败: %v", err)
	}
	defer retryResp.Body.Close()

	retryBody, err := io.ReadAll(retryResp.Body)
	if err != nil {
		log.Fatalf("读取响应体失败: %v", err)
	}

	fmt.Printf("重试后状态码: %d\n", retryResp.StatusCode)
	fmt.Printf("重试后响应: %s\n", string(retryBody))

	// 4. 测试速率限制
	fmt.Println("\n=== 测试速率限制 ===")
	fmt.Println("发送3个连续请求，应该会看到请求之间有延迟")

	for i := 0; i < 3; i++ {
		start := time.Now()

		limitResp, err := client.Get("http://localhost:8080/ratelimit")
		if err != nil {
			log.Fatalf("请求失败: %v", err)
		}

		limitBody, err := io.ReadAll(limitResp.Body)
		limitResp.Body.Close()
		if err != nil {
			log.Fatalf("读取响应体失败: %v", err)
		}

		duration := time.Since(start)
		fmt.Printf("请求 #%d 耗时: %v, 响应: %s\n", i+1, duration, string(limitBody))
	}

	fmt.Println("\n所有测试完成")
}
