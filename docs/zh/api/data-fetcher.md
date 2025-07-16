# 数据获取器

数据获取器提供了高级的数据获取和转换功能，简化了CWE数据的处理过程。

## 概述

数据获取器包含以下主要功能：

- 数据类型转换和验证
- 批量数据处理
- 错误处理和重试
- 数据缓存和优化

## 主要函数

### convertToCWE

将原始数据转换为CWE结构：

```go
// 转换弱点数据
weakness := &cwe.CWEWeakness{
    ID:   "79",
    Name: "跨站脚本",
}

converted := cwe.ConvertToCWE(weakness)
```

### 数据验证

验证CWE数据的完整性：

```go
func validateCWEData(data interface{}) error {
    switch cweData := data.(type) {
    case *cwe.CWEWeakness:
        if cweData.ID == "" {
            return errors.New("弱点ID不能为空")
        }
        if cweData.Name == "" {
            return errors.New("弱点名称不能为空")
        }
    case *cwe.CWECategory:
        if cweData.ID == "" {
            return errors.New("类别ID不能为空")
        }
    case *cwe.CWEView:
        if cweData.ID == "" {
            return errors.New("视图ID不能为空")
        }
    default:
        return errors.New("未知的CWE数据类型")
    }
    return nil
}
```

## 批量处理

### 批量获取和转换

```go
func fetchMultipleCWEs(client *cwe.APIClient, ids []string) ([]*cwe.CWEWeakness, error) {
    var results []*cwe.CWEWeakness
    
    for _, id := range ids {
        weakness, err := client.GetWeakness(id)
        if err != nil {
            log.Printf("获取CWE-%s失败: %v", id, err)
            continue
        }
        
        // 验证数据
        if err := validateCWEData(weakness); err != nil {
            log.Printf("CWE-%s数据无效: %v", id, err)
            continue
        }
        
        results = append(results, weakness)
    }
    
    return results, nil
}
```

### 并发获取

```go
func fetchConcurrently(client *cwe.APIClient, ids []string) map[string]*cwe.CWEWeakness {
    results := make(map[string]*cwe.CWEWeakness)
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    for _, id := range ids {
        wg.Add(1)
        go func(cweID string) {
            defer wg.Done()
            
            weakness, err := client.GetWeakness(cweID)
            if err != nil {
                log.Printf("获取CWE-%s失败: %v", cweID, err)
                return
            }
            
            mu.Lock()
            results[cweID] = weakness
            mu.Unlock()
        }(id)
    }
    
    wg.Wait()
    return results
}
```

## 数据转换工具

### JSON序列化

```go
func serializeToJSON(data interface{}) ([]byte, error) {
    return json.MarshalIndent(data, "", "  ")
}

func deserializeFromJSON(data []byte, target interface{}) error {
    return json.Unmarshal(data, target)
}
```

### XML序列化

```go
func serializeToXML(data interface{}) ([]byte, error) {
    return xml.MarshalIndent(data, "", "  ")
}

func deserializeFromXML(data []byte, target interface{}) error {
    return xml.Unmarshal(data, target)
}
```

## 缓存机制

### 简单内存缓存

```go
type CWECache struct {
    data map[string]interface{}
    mu   sync.RWMutex
}

func NewCWECache() *CWECache {
    return &CWECache{
        data: make(map[string]interface{}),
    }
}

func (c *CWECache) Get(key string) (interface{}, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    value, exists := c.data[key]
    return value, exists
}

func (c *CWECache) Set(key string, value interface{}) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.data[key] = value
}
```

### 带过期时间的缓存

```go
type CacheItem struct {
    Data      interface{}
    ExpiresAt time.Time
}

type TTLCache struct {
    items map[string]*CacheItem
    mu    sync.RWMutex
}

func NewTTLCache() *TTLCache {
    cache := &TTLCache{
        items: make(map[string]*CacheItem),
    }
    
    // 启动清理goroutine
    go cache.cleanup()
    
    return cache
}

func (c *TTLCache) Set(key string, value interface{}, ttl time.Duration) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.items[key] = &CacheItem{
        Data:      value,
        ExpiresAt: time.Now().Add(ttl),
    }
}

func (c *TTLCache) Get(key string) (interface{}, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    item, exists := c.items[key]
    if !exists {
        return nil, false
    }
    
    if time.Now().After(item.ExpiresAt) {
        return nil, false
    }
    
    return item.Data, true
}

func (c *TTLCache) cleanup() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        c.mu.Lock()
        now := time.Now()
        for key, item := range c.items {
            if now.After(item.ExpiresAt) {
                delete(c.items, key)
            }
        }
        c.mu.Unlock()
    }
}
```

## 错误处理

### 重试机制

```go
func fetchWithRetry(client *cwe.APIClient, id string, maxRetries int) (*cwe.CWEWeakness, error) {
    var lastErr error
    
    for i := 0; i <= maxRetries; i++ {
        weakness, err := client.GetWeakness(id)
        if err == nil {
            return weakness, nil
        }
        
        lastErr = err
        
        // 如果是客户端错误（4xx），不重试
        if strings.Contains(err.Error(), "404") {
            break
        }
        
        // 等待后重试
        if i < maxRetries {
            time.Sleep(time.Duration(i+1) * time.Second)
        }
    }
    
    return nil, fmt.Errorf("重试%d次后仍然失败: %v", maxRetries, lastErr)
}
```

## 实用工具

### ID规范化

```go
func normalizeID(id string) string {
    // 移除CWE-前缀（如果存在）
    if strings.HasPrefix(strings.ToUpper(id), "CWE-") {
        return strings.TrimPrefix(strings.ToUpper(id), "CWE-")
    }
    return id
}

func addCWEPrefix(id string) string {
    if !strings.HasPrefix(strings.ToUpper(id), "CWE-") {
        return "CWE-" + id
    }
    return strings.ToUpper(id)
}
```

### 数据统计

```go
func analyzeData(weaknesses []*cwe.CWEWeakness) map[string]int {
    stats := make(map[string]int)
    
    for _, weakness := range weaknesses {
        // 按严重程度统计
        if weakness.Severity != "" {
            stats["severity_"+weakness.Severity]++
        }
        
        // 按名称长度统计
        nameLength := len(weakness.Name)
        switch {
        case nameLength < 20:
            stats["name_short"]++
        case nameLength < 50:
            stats["name_medium"]++
        default:
            stats["name_long"]++
        }
    }
    
    return stats
}
```

## 最佳实践

1. **数据验证** - 始终验证从API获取的数据
2. **错误处理** - 实现适当的重试和错误处理机制
3. **缓存使用** - 合理使用缓存减少API调用
4. **并发控制** - 在并发环境中注意线程安全
5. **资源管理** - 及时清理缓存和释放资源

## 下一步

- 了解[注册表](./registry)的数据管理功能
- 学习[搜索和工具](./search-utils)的使用
- 查看[示例](/zh/examples/)中的实际应用
