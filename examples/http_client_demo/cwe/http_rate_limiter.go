package cwe

import (
	"sync"
	"time"
)

// HTTPRateLimiter 用于控制HTTP请求的发送频率
// 主要目的是防止对目标服务器发送过于频繁的请求，避免被限流或封禁
type HTTPRateLimiter struct {
	interval    time.Duration // 请求间隔时间
	lastRequest time.Time     // 上次请求的时间
	mutex       sync.Mutex    // 互斥锁，用于在并发环境下保护lastRequest
}

// NewHTTPRateLimiter 创建一个新的HTTP请求速率限制器
// interval: 两次请求之间的最小时间间隔
func NewHTTPRateLimiter(interval time.Duration) *HTTPRateLimiter {
	return &HTTPRateLimiter{
		interval:    interval,
		lastRequest: time.Now().Add(-interval), // 初始化为可以立即发送第一个请求
	}
}

// WaitForRequest 根据速率限制等待，确保距离上次请求至少间隔指定时间
// 该函数会阻塞直到允许发送下一个请求
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
func (r *HTTPRateLimiter) ResetLastRequest() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.lastRequest = time.Now().Add(-r.interval)
}

// GetInterval 获取当前设置的请求间隔
func (r *HTTPRateLimiter) GetInterval() time.Duration {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.interval
}

// SetInterval 设置请求间隔
func (r *HTTPRateLimiter) SetInterval(interval time.Duration) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.interval = interval
}

// DefaultRateLimiter 是默认的速率限制器，每10秒允许1个请求
var DefaultRateLimiter = NewHTTPRateLimiter(10 * time.Second)
