# Search & Filter

This example demonstrates various search and filtering capabilities for finding specific CWE entries based on different criteria.

## Complete Example

```go
package main

import (
    "fmt"
    "log"
    "strings"
    
    "github.com/scagogogo/cwe"
)

func main() {
    fmt.Println("==== CWE Search & Filter Example ====")
    
    // 1. Build sample dataset
    registry := buildSampleRegistry()
    fmt.Printf("Created registry with %d CWEs\n", registry.Count())
    
    // 2. Search by name
    fmt.Println("\n1. Search by Name")
    nameResults := registry.SearchByName("injection")
    fmt.Printf("Found %d CWEs with 'injection' in name:\n", len(nameResults))
    for _, cwe := range nameResults {
        fmt.Printf("  %s: %s\n", cwe.ID, cwe.Name)
    }
    
    // 3. Search by description
    fmt.Println("\n2. Search by Description")
    descResults := registry.SearchByDescription("authentication")
    fmt.Printf("Found %d CWEs with 'authentication' in description:\n", len(descResults))
    for _, cwe := range descResults {
        fmt.Printf("  %s: %s\n", cwe.ID, cwe.Name)
    }
    
    // 4. Filter by severity
    fmt.Println("\n3. Filter by Severity")
    highSeverity := registry.FilterBySeverity("High")
    fmt.Printf("Found %d high-severity CWEs:\n", len(highSeverity))
    for _, cwe := range highSeverity {
        fmt.Printf("  %s: %s (Severity: %s)\n", cwe.ID, cwe.Name, cwe.Severity)
    }
    
    // 5. Custom search functions
    fmt.Println("\n4. Custom Search Functions")
    
    // Find CWEs with specific keywords
    webVulns := findCWEsWithKeywords(registry, []string{"web", "script", "html"})
    fmt.Printf("Found %d web-related vulnerabilities:\n", len(webVulns))
    for _, cwe := range webVulns {
        fmt.Printf("  %s: %s\n", cwe.ID, cwe.Name)
    }
    
    // 6. Advanced filtering
    fmt.Println("\n5. Advanced Filtering")
    
    // Complex filter: High severity AND contains "injection"
    complexResults := advancedFilter(registry, func(cwe *cwe.CWE) bool {
        return cwe.Severity == "High" && 
               strings.Contains(strings.ToLower(cwe.Name), "injection")
    })
    
    fmt.Printf("High-severity injection CWEs: %d\n", len(complexResults))
    for _, cwe := range complexResults {
        fmt.Printf("  %s: %s\n", cwe.ID, cwe.Name)
    }
    
    // 7. Search with ranking
    fmt.Println("\n6. Search with Ranking")
    rankedResults := searchWithRanking(registry, "script")
    fmt.Printf("Top 3 results for 'script':\n")
    for i, result := range rankedResults[:min(3, len(rankedResults))] {
        fmt.Printf("  %d. %s: %s (Score: %.2f)\n", 
            i+1, result.CWE.ID, result.CWE.Name, result.Score)
    }
    
    fmt.Println("\n==== Search & Filter Example Complete ====")
}

// Build sample registry with test data
func buildSampleRegistry() *cwe.Registry {
    registry := cwe.NewRegistry()
    
    // Create sample CWEs with various attributes
    cwes := []*cwe.CWE{
        createCWE("CWE-79", "Cross-site Scripting", "High", 
            "Improper neutralization of input during web page generation"),
        createCWE("CWE-89", "SQL Injection", "High", 
            "Improper neutralization of special elements used in SQL commands"),
        createCWE("CWE-287", "Improper Authentication", "Medium", 
            "Occurs when an actor claims to have a given identity"),
        createCWE("CWE-22", "Path Traversal", "High", 
            "Improper limitation of a pathname to a restricted directory"),
        createCWE("CWE-78", "OS Command Injection", "High", 
            "Improper neutralization of special elements used in OS commands"),
        createCWE("CWE-352", "Cross-Site Request Forgery", "Medium", 
            "Web application does not verify that a request was intentionally provided"),
        createCWE("CWE-434", "Unrestricted Upload", "High", 
            "Software allows the attacker to upload dangerous file types"),
        createCWE("CWE-862", "Missing Authorization", "Medium", 
            "Software does not perform an authorization check"),
    }
    
    for _, cwe := range cwes {
        registry.Register(cwe)
    }
    
    return registry
}

func createCWE(id, name, severity, description string) *cwe.CWE {
    c := cwe.NewCWE(id, name)
    c.Severity = severity
    c.Description = description
    return c
}

// Find CWEs containing any of the specified keywords
func findCWEsWithKeywords(registry *cwe.Registry, keywords []string) []*cwe.CWE {
    var results []*cwe.CWE
    
    for _, cwe := range registry.GetAll() {
        nameText := strings.ToLower(cwe.Name)
        descText := strings.ToLower(cwe.Description)
        
        for _, keyword := range keywords {
            if strings.Contains(nameText, strings.ToLower(keyword)) ||
               strings.Contains(descText, strings.ToLower(keyword)) {
                results = append(results, cwe)
                break // Found match, no need to check other keywords
            }
        }
    }
    
    return results
}

// Advanced filter with custom predicate
func advancedFilter(registry *cwe.Registry, predicate func(*cwe.CWE) bool) []*cwe.CWE {
    var results []*cwe.CWE
    
    for _, cwe := range registry.GetAll() {
        if predicate(cwe) {
            results = append(results, cwe)
        }
    }
    
    return results
}

// Search result with relevance score
type SearchResult struct {
    CWE   *cwe.CWE
    Score float64
}

// Search with ranking based on relevance
func searchWithRanking(registry *cwe.Registry, query string) []SearchResult {
    var results []SearchResult
    queryLower := strings.ToLower(query)
    
    for _, cwe := range registry.GetAll() {
        score := calculateRelevanceScore(cwe, queryLower)
        if score > 0 {
            results = append(results, SearchResult{
                CWE:   cwe,
                Score: score,
            })
        }
    }
    
    // Sort by score (highest first)
    for i := 0; i < len(results)-1; i++ {
        for j := i + 1; j < len(results); j++ {
            if results[i].Score < results[j].Score {
                results[i], results[j] = results[j], results[i]
            }
        }
    }
    
    return results
}

// Calculate relevance score for search query
func calculateRelevanceScore(cwe *cwe.CWE, query string) float64 {
    score := 0.0
    
    nameLower := strings.ToLower(cwe.Name)
    descLower := strings.ToLower(cwe.Description)
    
    // Exact match in name gets highest score
    if strings.Contains(nameLower, query) {
        score += 10.0
        
        // Bonus for exact word match
        if strings.Contains(" "+nameLower+" ", " "+query+" ") {
            score += 5.0
        }
    }
    
    // Match in description gets medium score
    if strings.Contains(descLower, query) {
        score += 3.0
    }
    
    // Bonus for high severity
    if cwe.Severity == "High" {
        score += 1.0
    }
    
    return score
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

## Advanced Search Patterns

### Multi-Criteria Search

```go
type SearchCriteria struct {
    NamePattern        string
    DescriptionPattern string
    Severity          string
    MinSeverityLevel  int
    HasMitigations    bool
}

func searchByCriteria(registry *cwe.Registry, criteria SearchCriteria) []*cwe.CWE {
    var results []*cwe.CWE
    
    for _, cwe := range registry.GetAll() {
        if matchesCriteria(cwe, criteria) {
            results = append(results, cwe)
        }
    }
    
    return results
}

func matchesCriteria(cwe *cwe.CWE, criteria SearchCriteria) bool {
    // Check name pattern
    if criteria.NamePattern != "" {
        if !strings.Contains(strings.ToLower(cwe.Name), 
                           strings.ToLower(criteria.NamePattern)) {
            return false
        }
    }
    
    // Check description pattern
    if criteria.DescriptionPattern != "" {
        if !strings.Contains(strings.ToLower(cwe.Description), 
                           strings.ToLower(criteria.DescriptionPattern)) {
            return false
        }
    }
    
    // Check exact severity
    if criteria.Severity != "" && cwe.Severity != criteria.Severity {
        return false
    }
    
    // Check minimum severity level
    if criteria.MinSeverityLevel > 0 {
        severityLevel := getSeverityLevel(cwe.Severity)
        if severityLevel < criteria.MinSeverityLevel {
            return false
        }
    }
    
    // Check for mitigations
    if criteria.HasMitigations && len(cwe.Mitigations) == 0 {
        return false
    }
    
    return true
}

func getSeverityLevel(severity string) int {
    switch severity {
    case "High":
        return 3
    case "Medium":
        return 2
    case "Low":
        return 1
    default:
        return 0
    }
}
```

### Fuzzy Search

```go
func fuzzySearch(registry *cwe.Registry, query string, threshold float64) []*cwe.CWE {
    var results []*cwe.CWE
    
    for _, cwe := range registry.GetAll() {
        similarity := calculateSimilarity(cwe.Name, query)
        if similarity >= threshold {
            results = append(results, cwe)
        }
    }
    
    return results
}

// Simple similarity calculation (Levenshtein-like)
func calculateSimilarity(text, query string) float64 {
    textLower := strings.ToLower(text)
    queryLower := strings.ToLower(query)
    
    // Simple substring matching for demonstration
    if strings.Contains(textLower, queryLower) {
        return float64(len(queryLower)) / float64(len(textLower))
    }
    
    // Count common words
    textWords := strings.Fields(textLower)
    queryWords := strings.Fields(queryLower)
    
    commonWords := 0
    for _, qWord := range queryWords {
        for _, tWord := range textWords {
            if qWord == tWord {
                commonWords++
                break
            }
        }
    }
    
    if len(queryWords) == 0 {
        return 0
    }
    
    return float64(commonWords) / float64(len(queryWords))
}
```

### Category-Based Search

```go
func searchByCategory(registry *cwe.Registry, categoryPattern string) []*cwe.CWE {
    var results []*cwe.CWE
    
    // Define category keywords
    categories := map[string][]string{
        "injection": {"injection", "sql", "command", "code"},
        "xss":       {"script", "cross-site", "xss"},
        "auth":      {"authentication", "authorization", "access"},
        "crypto":    {"cryptographic", "encryption", "hash"},
        "input":     {"input", "validation", "sanitization"},
    }
    
    keywords, exists := categories[strings.ToLower(categoryPattern)]
    if !exists {
        // Fallback to direct pattern matching
        keywords = []string{categoryPattern}
    }
    
    for _, cwe := range registry.GetAll() {
        if matchesAnyKeyword(cwe, keywords) {
            results = append(results, cwe)
        }
    }
    
    return results
}

func matchesAnyKeyword(cwe *cwe.CWE, keywords []string) bool {
    text := strings.ToLower(cwe.Name + " " + cwe.Description)
    
    for _, keyword := range keywords {
        if strings.Contains(text, strings.ToLower(keyword)) {
            return true
        }
    }
    
    return false
}
```

## Search Utilities

### Search Result Pagination

```go
type PaginatedResults struct {
    Results    []*cwe.CWE
    Page       int
    PageSize   int
    TotalCount int
    TotalPages int
}

func paginateResults(results []*cwe.CWE, page, pageSize int) PaginatedResults {
    totalCount := len(results)
    totalPages := (totalCount + pageSize - 1) / pageSize
    
    start := (page - 1) * pageSize
    end := start + pageSize
    
    if start >= totalCount {
        return PaginatedResults{
            Results:    []*cwe.CWE{},
            Page:       page,
            PageSize:   pageSize,
            TotalCount: totalCount,
            TotalPages: totalPages,
        }
    }
    
    if end > totalCount {
        end = totalCount
    }
    
    return PaginatedResults{
        Results:    results[start:end],
        Page:       page,
        PageSize:   pageSize,
        TotalCount: totalCount,
        TotalPages: totalPages,
    }
}
```

### Search History and Caching

```go
type SearchCache struct {
    cache map[string][]*cwe.CWE
    mutex sync.RWMutex
}

func NewSearchCache() *SearchCache {
    return &SearchCache{
        cache: make(map[string][]*cwe.CWE),
    }
}

func (sc *SearchCache) Search(registry *cwe.Registry, query string) []*cwe.CWE {
    sc.mutex.RLock()
    if cached, exists := sc.cache[query]; exists {
        sc.mutex.RUnlock()
        return cached
    }
    sc.mutex.RUnlock()
    
    // Perform search
    results := registry.SearchByName(query)
    
    // Cache results
    sc.mutex.Lock()
    sc.cache[query] = results
    sc.mutex.Unlock()
    
    return results
}
```

## Running the Example

```bash
go run main.go
```

Expected output shows various search and filtering results with different criteria and ranking scores.

## Next Steps

- Learn about [Export & Import](./export-import) for persisting search results
- Explore [Rate Limited Client](./rate-limited) for optimizing API searches
- Check the [API Reference](/api/) for complete search function documentation
