package cwe

import (
	"sync"
	"time"
)

// HTTPRateLimiter 用于控制HTTP请求的发送频率
// 主要目的是防止对目标服务器发送过于频繁的请求，避免被限流或封禁
//
// 线程安全性：
// 该结构体是线程安全的，可以在多个goroutine中并发使用
// 内部使用互斥锁保护共享状态的访问
//
// 性能考虑：
// - 每次请求都需要获取锁，在高并发场景下可能成为性能瓶颈
// - 建议根据实际需求调整interval参数，避免过于频繁的请求
//
// 使用示例：
// ```go
// // 创建一个每5秒允许1个请求的限流器
// limiter := NewHTTPRateLimiter(5 * time.Second)
//
// // 在发送请求前等待
// limiter.WaitForRequest()
//
// // 发送HTTP请求
// resp, err := http.Get("https://api.example.com/data")
// ```
type HTTPRateLimiter struct {
	// interval 表示两次请求之间的最小时间间隔
	// 单位：time.Duration（纳秒）
	// 示例：5 * time.Second 表示每5秒允许1个请求
	interval time.Duration

	// lastRequest 记录上一次请求的时间
	// 用于计算是否需要等待才能发送下一个请求
	lastRequest time.Time

	// mutex 用于在并发环境下保护lastRequest的访问
	// 确保在多个goroutine中使用时的线程安全
	mutex sync.Mutex
}

// NewHTTPRateLimiter 创建一个新的HTTP请求速率限制器
//
// 方法功能：
// 创建并初始化一个新的HTTPRateLimiter实例，用于控制HTTP请求的发送频率
//
// 参数：
// - interval time.Duration: 两次请求之间的最小时间间隔
//   - 取值范围：>0，如果<=0会导致不进行速率限制
//   - 单位：time.Duration（纳秒）
//   - 示例值：5 * time.Second, 100 * time.Millisecond
//
// 返回值：
// - *HTTPRateLimiter: 配置完成的速率限制器实例
//   - 如果interval > 0，返回正常配置的限流器
//   - 如果interval <= 0，返回的限流器不会进行实际的速率限制
//
// 使用示例：
// ```go
// // 创建一个每5秒允许1个请求的限流器
// limiter := NewHTTPRateLimiter(5 * time.Second)
//
// // 创建一个每100毫秒允许1个请求的限流器
// fastLimiter := NewHTTPRateLimiter(100 * time.Millisecond)
//
// // 创建一个不进行速率限制的限流器（不推荐）
// noLimiter := NewHTTPRateLimiter(0)
// ```
//
// 相关方法：
// - WaitForRequest(): 等待直到允许发送下一个请求
// - GetInterval(): 获取当前的时间间隔设置
// - SetInterval(): 修改时间间隔设置
// - ResetLastRequest(): 重置上次请求时间
func NewHTTPRateLimiter(interval time.Duration) *HTTPRateLimiter {
	return &HTTPRateLimiter{
		interval:    interval,
		lastRequest: time.Now().Add(-interval), // 初始化为可以立即发送第一个请求
	}
}

// WaitForRequest 根据速率限制等待，确保距离上次请求至少间隔指定时间
//
// 方法功能：
// 在发送新的HTTP请求前调用此方法，它会在必要时阻塞等待，
// 以确保两次请求之间的间隔不小于指定值。这是实现速率限制的核心方法。
//
// 线程安全性：
// 该方法是线程安全的，可以在多个goroutine中并发调用
//
// 阻塞行为：
// - 如果距离上次请求的时间小于指定间隔，会阻塞等待
// - 如果已经超过间隔时间，则立即返回
// - 如果interval<=0，则不会进行等待
//
// 使用示例：
// ```go
// limiter := NewHTTPRateLimiter(time.Second)
//
// // 在循环中发送请求
//
//	for i := 0; i < 5; i++ {
//	    limiter.WaitForRequest()
//	    resp, err := http.Get("https://api.example.com/data")
//	    // 处理响应...
//	}
//
// // 在并发环境中使用
// var wg sync.WaitGroup
//
//	for i := 0; i < 3; i++ {
//	    wg.Add(1)
//	    go func() {
//	        defer wg.Done()
//	        limiter.WaitForRequest()
//	        // 发送请求...
//	    }()
//	}
//
// wg.Wait()
// ```
//
// 性能考虑：
// - 每次调用都会获取锁，在高并发场景下可能影响性能
// - 如果多个goroutine同时等待，它们会按照调用顺序依次获得发送请求的机会
func (r *HTTPRateLimiter) WaitForRequest() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRequest)

	// 如果距离上次请求的时间小于指定间隔，则等待
	if elapsed < r.interval {
		waitTime := r.interval - elapsed
		time.Sleep(waitTime)
		now = time.Now()
	}

	// 更新上次请求时间
	r.lastRequest = now
}

// ResetLastRequest 重置上次请求时间，使得下一次请求可以立即发送
//
// 方法功能：
// 将上次请求时间重置为当前时间减去间隔时间，这样下一次调用WaitForRequest时可以立即发送请求。
// 主要用于在特殊情况下（如重置限流器状态、错误恢复等）手动干预速率限制行为。
//
// 线程安全性：
// 该方法是线程安全的，可以在多个goroutine中并发调用
//
// 使用场景：
// 1. 在发生错误后重置限流器状态
// 2. 在限流器配置变更后重置状态
// 3. 在需要立即发送请求的特殊情况下
//
// 使用示例：
// ```go
// limiter := NewHTTPRateLimiter(5 * time.Second)
//
// // 正常发送请求
// limiter.WaitForRequest()
// resp1, err := http.Get("https://api.example.com/data")
//
// // 发生错误，需要重置状态
//
//	if err != nil {
//	    limiter.ResetLastRequest()
//	    // 立即重试请求
//	    resp2, err := http.Get("https://api.example.com/data")
//	}
//
// // 配置变更后重置
// limiter.SetInterval(2 * time.Second)
// limiter.ResetLastRequest()
// ```
//
// 注意事项：
// - 不要过于频繁地调用此方法，这可能导致速率限制失效
// - 仅在确实需要立即发送请求时使用
func (r *HTTPRateLimiter) ResetLastRequest() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.lastRequest = time.Now().Add(-r.interval)
}

// GetInterval 获取当前设置的请求间隔
//
// 方法功能：
// 返回当前限流器配置的请求间隔时间。这个方法通常用于检查或调试限流器的配置。
//
// 返回值：
// - time.Duration: 当前设置的请求间隔时间
//   - 单位：time.Duration（纳秒）
//   - 特殊值：<=0 表示没有速率限制
//
// 线程安全性：
// 该方法是线程安全的，可以在多个goroutine中并发调用
//
// 使用示例：
// ```go
// limiter := NewHTTPRateLimiter(5 * time.Second)
//
// // 获取并检查间隔设置
// interval := limiter.GetInterval()
// fmt.Printf("当前限流器配置为每 %v 允许一个请求\n", interval)
//
// // 在运行时检查配置
//
//	if limiter.GetInterval() > time.Second {
//	    log.Println("警告：当前速率限制可能过于保守")
//	}
//
// ```
func (r *HTTPRateLimiter) GetInterval() time.Duration {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.interval
}

// SetInterval 设置请求间隔
//
// 方法功能：
// 动态修改限流器的请求间隔时间。这允许在程序运行期间根据需要调整速率限制策略。
//
// 参数：
// - interval time.Duration: 新的请求间隔时间
//   - 取值范围：>0，如果<=0会导致不进行速率限制
//   - 单位：time.Duration（纳秒）
//   - 示例值：5 * time.Second, 100 * time.Millisecond
//
// 线程安全性：
// 该方法是线程安全的，可以在多个goroutine中并发调用
//
// 使用场景：
// 1. 根据服务器响应动态调整请求频率
// 2. 实现自适应限流策略
// 3. 在不同时段使用不同的限流策略
//
// 使用示例：
// ```go
// limiter := NewHTTPRateLimiter(5 * time.Second)
//
// // 基本使用
// limiter.SetInterval(2 * time.Second) // 修改为每2秒一个请求
//
// // 动态调整示例
//
//	for {
//	    resp, err := http.Get("https://api.example.com/data")
//	    if err != nil {
//	        // 发生错误时降低请求频率
//	        currentInterval := limiter.GetInterval()
//	        limiter.SetInterval(currentInterval * 2)
//	        continue
//	    }
//
//	    if resp.StatusCode == 429 { // Too Many Requests
//	        // 收到限流响应时降低请求频率
//	        limiter.SetInterval(limiter.GetInterval() * 2)
//	    } else if resp.StatusCode == 200 {
//	        // 请求成功时可以适当提高频率
//	        currentInterval := limiter.GetInterval()
//	        if currentInterval > time.Second {
//	            limiter.SetInterval(currentInterval / 2)
//	        }
//	    }
//	}
//
// // 在特定时段调整限流策略
//
//	if time.Now().Hour() >= 22 || time.Now().Hour() < 6 {
//	    // 夜间降低请求频率
//	    limiter.SetInterval(10 * time.Second)
//	} else {
//
//	    // 日间使用正常频率
//	    limiter.SetInterval(2 * time.Second)
//	}
//
// ```
//
// 注意事项：
// - 调整间隔不会影响当前正在等待的请求
// - 建议在修改间隔后调用ResetLastRequest()以立即使新设置生效
func (r *HTTPRateLimiter) SetInterval(interval time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.interval = interval
}

// DefaultRateLimiter 是默认的速率限制器，每10秒允许1个请求
// 这个相对保守的默认值适用于大多数API调用场景，可以有效防止被目标服务器限流
var DefaultRateLimiter = NewHTTPRateLimiter(10 * time.Second)
