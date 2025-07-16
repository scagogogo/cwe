# Export & Import

This example demonstrates data persistence and serialization capabilities, including JSON/XML export, import operations, and data backup/restore functionality.

## Complete Example

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    
    "github.com/scagogogo/cwe"
)

func main() {
    fmt.Println("==== CWE Export & Import Example ====")
    
    // 1. Create and populate registry
    registry := createSampleRegistry()
    fmt.Printf("Created registry with %d CWEs\n", registry.Count())
    
    // 2. Export to JSON
    fmt.Println("\n1. Exporting to JSON")
    jsonData, err := registry.ExportToJSON()
    if err != nil {
        log.Fatalf("Failed to export to JSON: %v", err)
    }
    
    // Save to file
    err = ioutil.WriteFile("cwe_export.json", jsonData, 0644)
    if err != nil {
        log.Fatalf("Failed to save JSON file: %v", err)
    }
    fmt.Printf("Exported %d bytes to cwe_export.json\n", len(jsonData))
    
    // 3. Import from JSON
    fmt.Println("\n2. Importing from JSON")
    newRegistry := cwe.NewRegistry()
    
    savedData, err := ioutil.ReadFile("cwe_export.json")
    if err != nil {
        log.Fatalf("Failed to read JSON file: %v", err)
    }
    
    err = newRegistry.ImportFromJSON(savedData)
    if err != nil {
        log.Fatalf("Failed to import from JSON: %v", err)
    }
    
    fmt.Printf("Imported %d CWEs from JSON\n", newRegistry.Count())
    
    // 4. Export individual CWE to XML
    fmt.Println("\n3. Exporting Individual CWE to XML")
    if xss, exists := registry.GetByID("CWE-79"); exists {
        xmlData, err := xss.ToXML()
        if err != nil {
            log.Printf("Failed to export CWE to XML: %v", err)
        } else {
            err = ioutil.WriteFile("cwe-79.xml", xmlData, 0644)
            if err != nil {
                log.Printf("Failed to save XML file: %v", err)
            } else {
                fmt.Printf("Exported CWE-79 to XML (%d bytes)\n", len(xmlData))
            }
        }
    }
    
    // 5. Export individual CWE to JSON
    fmt.Println("\n4. Exporting Individual CWE to JSON")
    if sqli, exists := registry.GetByID("CWE-89"); exists {
        cweJsonData, err := sqli.ToJSON()
        if err != nil {
            log.Printf("Failed to export CWE to JSON: %v", err)
        } else {
            err = ioutil.WriteFile("cwe-89.json", cweJsonData, 0644)
            if err != nil {
                log.Printf("Failed to save CWE JSON file: %v", err)
            } else {
                fmt.Printf("Exported CWE-89 to JSON (%d bytes)\n", len(cweJsonData))
            }
        }
    }
    
    // 6. Backup and restore operations
    fmt.Println("\n5. Backup and Restore Operations")
    
    // Create backup
    backupData := createBackup(registry)
    err = ioutil.WriteFile("cwe_backup.json", backupData, 0644)
    if err != nil {
        log.Printf("Failed to create backup: %v", err)
    } else {
        fmt.Printf("Created backup file (%d bytes)\n", len(backupData))
    }
    
    // Restore from backup
    restoredRegistry, err := restoreFromBackup("cwe_backup.json")
    if err != nil {
        log.Printf("Failed to restore from backup: %v", err)
    } else {
        fmt.Printf("Restored %d CWEs from backup\n", restoredRegistry.Count())
    }
    
    // 7. Export filtered data
    fmt.Println("\n6. Exporting Filtered Data")
    highSeverityCWEs := registry.FilterBySeverity("High")
    filteredRegistry := cwe.NewRegistry()
    
    for _, cweItem := range highSeverityCWEs {
        filteredRegistry.Register(cweItem)
    }
    
    filteredData, err := filteredRegistry.ExportToJSON()
    if err != nil {
        log.Printf("Failed to export filtered data: %v", err)
    } else {
        err = ioutil.WriteFile("high_severity_cwes.json", filteredData, 0644)
        if err != nil {
            log.Printf("Failed to save filtered data: %v", err)
        } else {
            fmt.Printf("Exported %d high-severity CWEs\n", len(highSeverityCWEs))
        }
    }
    
    // 8. Cleanup
    fmt.Println("\n7. Cleaning up temporary files")
    cleanupFiles()
    
    fmt.Println("\n==== Export & Import Example Complete ====")
}

// Create sample registry with test data
func createSampleRegistry() *cwe.Registry {
    registry := cwe.NewRegistry()
    
    // Create sample CWEs
    cwes := []*cwe.CWE{
        createDetailedCWE("CWE-79", "Cross-site Scripting", "High",
            "Improper neutralization of input during web page generation",
            []string{"Input validation", "Output encoding", "CSP headers"},
            []string{"Stored XSS in comment fields", "Reflected XSS in search"}),
        
        createDetailedCWE("CWE-89", "SQL Injection", "High",
            "Improper neutralization of special elements used in SQL commands",
            []string{"Parameterized queries", "Input validation", "Least privilege"},
            []string{"Union-based injection", "Blind SQL injection"}),
        
        createDetailedCWE("CWE-287", "Improper Authentication", "Medium",
            "Occurs when an actor claims to have a given identity",
            []string{"Strong authentication", "Multi-factor auth", "Session management"},
            []string{"Weak password policies", "Missing authentication checks"}),
        
        createDetailedCWE("CWE-22", "Path Traversal", "High",
            "Improper limitation of a pathname to a restricted directory",
            []string{"Input validation", "Canonicalization", "Sandboxing"},
            []string{"Directory traversal with ../", "Absolute path injection"}),
        
        createDetailedCWE("CWE-352", "Cross-Site Request Forgery", "Medium",
            "Web application does not verify that a request was intentionally provided",
            []string{"CSRF tokens", "SameSite cookies", "Referer validation"},
            []string{"State-changing GET requests", "Missing CSRF protection"}),
    }
    
    for _, cweItem := range cwes {
        err := registry.Register(cweItem)
        if err != nil {
            log.Printf("Failed to register %s: %v", cweItem.ID, err)
        }
    }
    
    return registry
}

func createDetailedCWE(id, name, severity, description string, mitigations, examples []string) *cwe.CWE {
    c := cwe.NewCWE(id, name)
    c.Severity = severity
    c.Description = description
    c.Mitigations = mitigations
    c.Examples = examples
    c.URL = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", 
        strings.TrimPrefix(id, "CWE-"))
    return c
}

// Backup structure with metadata
type BackupData struct {
    Timestamp   string                 `json:"timestamp"`
    Version     string                 `json:"version"`
    Count       int                    `json:"count"`
    CWEs        map[string]*cwe.CWE    `json:"cwes"`
    Metadata    map[string]interface{} `json:"metadata"`
}

func createBackup(registry *cwe.Registry) []byte {
    backup := BackupData{
        Timestamp: time.Now().Format(time.RFC3339),
        Version:   "1.0",
        Count:     registry.Count(),
        CWEs:      registry.GetAll(),
        Metadata: map[string]interface{}{
            "source":      "cwe-go-library",
            "description": "CWE registry backup",
        },
    }
    
    data, err := json.MarshalIndent(backup, "", "  ")
    if err != nil {
        log.Printf("Failed to marshal backup data: %v", err)
        return nil
    }
    
    return data
}

func restoreFromBackup(filename string) (*cwe.Registry, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read backup file: %w", err)
    }
    
    var backup BackupData
    err = json.Unmarshal(data, &backup)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal backup data: %w", err)
    }
    
    registry := cwe.NewRegistry()
    for _, cweItem := range backup.CWEs {
        err = registry.Register(cweItem)
        if err != nil {
            log.Printf("Failed to register CWE %s during restore: %v", cweItem.ID, err)
        }
    }
    
    fmt.Printf("Restored backup from %s (version %s)\n", backup.Timestamp, backup.Version)
    return registry, nil
}

func cleanupFiles() {
    files := []string{
        "cwe_export.json",
        "cwe-79.xml",
        "cwe-89.json",
        "cwe_backup.json",
        "high_severity_cwes.json",
    }
    
    for _, file := range files {
        err := os.Remove(file)
        if err != nil {
            log.Printf("Failed to remove %s: %v", file, err)
        } else {
            fmt.Printf("Removed %s\n", file)
        }
    }
}
```

## Key Export/Import Operations

### 1. Registry JSON Export/Import

```go
// Export entire registry
jsonData, err := registry.ExportToJSON()
if err != nil {
    log.Fatal(err)
}

// Save to file
err = ioutil.WriteFile("registry.json", jsonData, 0644)

// Import to new registry
newRegistry := cwe.NewRegistry()
savedData, err := ioutil.ReadFile("registry.json")
if err != nil {
    log.Fatal(err)
}

err = newRegistry.ImportFromJSON(savedData)
```

### 2. Individual CWE Serialization

```go
// Export single CWE to JSON
cweInstance := cwe.NewCWE("CWE-79", "XSS")
jsonData, err := cweInstance.ToJSON()

// Export single CWE to XML
xmlData, err := cweInstance.ToXML()
```

### 3. Custom Backup Format

```go
type CustomBackup struct {
    CreatedAt   time.Time          `json:"created_at"`
    LibVersion  string             `json:"lib_version"`
    CWECount    int                `json:"cwe_count"`
    Data        map[string]*cwe.CWE `json:"data"`
    Checksums   map[string]string  `json:"checksums"`
}

func createCustomBackup(registry *cwe.Registry) (*CustomBackup, error) {
    backup := &CustomBackup{
        CreatedAt:  time.Now(),
        LibVersion: "1.0.0",
        CWECount:   registry.Count(),
        Data:       registry.GetAll(),
        Checksums:  make(map[string]string),
    }
    
    // Calculate checksums for integrity
    for id, cweItem := range backup.Data {
        data, err := json.Marshal(cweItem)
        if err != nil {
            return nil, err
        }
        
        hash := sha256.Sum256(data)
        backup.Checksums[id] = hex.EncodeToString(hash[:])
    }
    
    return backup, nil
}
```

## Advanced Export/Import Patterns

### Incremental Backup

```go
type IncrementalBackup struct {
    BaseBackup   string                 `json:"base_backup"`
    Changes      map[string]*cwe.CWE    `json:"changes"`
    Deletions    []string               `json:"deletions"`
    Timestamp    time.Time              `json:"timestamp"`
}

func createIncrementalBackup(current, previous *cwe.Registry) *IncrementalBackup {
    backup := &IncrementalBackup{
        Changes:   make(map[string]*cwe.CWE),
        Deletions: make([]string, 0),
        Timestamp: time.Now(),
    }
    
    currentCWEs := current.GetAll()
    previousCWEs := previous.GetAll()
    
    // Find changes and additions
    for id, currentCWE := range currentCWEs {
        if previousCWE, exists := previousCWEs[id]; !exists {
            // New CWE
            backup.Changes[id] = currentCWE
        } else if !cweEqual(currentCWE, previousCWE) {
            // Modified CWE
            backup.Changes[id] = currentCWE
        }
    }
    
    // Find deletions
    for id := range previousCWEs {
        if _, exists := currentCWEs[id]; !exists {
            backup.Deletions = append(backup.Deletions, id)
        }
    }
    
    return backup
}

func cweEqual(a, b *cwe.CWE) bool {
    return a.ID == b.ID &&
           a.Name == b.Name &&
           a.Description == b.Description &&
           a.Severity == b.Severity
}
```

### Filtered Export

```go
func exportByFilter(registry *cwe.Registry, filter func(*cwe.CWE) bool) ([]byte, error) {
    filteredRegistry := cwe.NewRegistry()
    
    for _, cweItem := range registry.GetAll() {
        if filter(cweItem) {
            err := filteredRegistry.Register(cweItem)
            if err != nil {
                return nil, err
            }
        }
    }
    
    return filteredRegistry.ExportToJSON()
}

// Usage examples
highSeverityData, err := exportByFilter(registry, func(c *cwe.CWE) bool {
    return c.Severity == "High"
})

injectionData, err := exportByFilter(registry, func(c *cwe.CWE) bool {
    return strings.Contains(strings.ToLower(c.Name), "injection")
})
```

### Compressed Export

```go
import (
    "compress/gzip"
    "bytes"
)

func exportCompressed(registry *cwe.Registry) ([]byte, error) {
    // Get JSON data
    jsonData, err := registry.ExportToJSON()
    if err != nil {
        return nil, err
    }
    
    // Compress with gzip
    var buf bytes.Buffer
    gzWriter := gzip.NewWriter(&buf)
    
    _, err = gzWriter.Write(jsonData)
    if err != nil {
        return nil, err
    }
    
    err = gzWriter.Close()
    if err != nil {
        return nil, err
    }
    
    return buf.Bytes(), nil
}

func importCompressed(data []byte) (*cwe.Registry, error) {
    // Decompress
    reader, err := gzip.NewReader(bytes.NewReader(data))
    if err != nil {
        return nil, err
    }
    defer reader.Close()
    
    jsonData, err := ioutil.ReadAll(reader)
    if err != nil {
        return nil, err
    }
    
    // Import JSON
    registry := cwe.NewRegistry()
    err = registry.ImportFromJSON(jsonData)
    if err != nil {
        return nil, err
    }
    
    return registry, nil
}
```

## Data Migration

### Version Migration

```go
type MigrationFunc func(map[string]interface{}) (map[string]interface{}, error)

var migrations = map[string]MigrationFunc{
    "1.0_to_1.1": migrateV1ToV1_1,
    "1.1_to_1.2": migrateV1_1ToV1_2,
}

func migrateData(data map[string]interface{}, fromVersion, toVersion string) (map[string]interface{}, error) {
    migrationKey := fromVersion + "_to_" + toVersion
    migration, exists := migrations[migrationKey]
    if !exists {
        return nil, fmt.Errorf("no migration available from %s to %s", fromVersion, toVersion)
    }
    
    return migration(data)
}

func migrateV1ToV1_1(data map[string]interface{}) (map[string]interface{}, error) {
    // Example migration: add new fields, rename existing ones
    if cwes, ok := data["cwes"].(map[string]interface{}); ok {
        for id, cweData := range cwes {
            if cweMap, ok := cweData.(map[string]interface{}); ok {
                // Add new field
                if _, exists := cweMap["created_at"]; !exists {
                    cweMap["created_at"] = time.Now().Format(time.RFC3339)
                }
                
                // Rename field
                if oldField, exists := cweMap["old_field"]; exists {
                    cweMap["new_field"] = oldField
                    delete(cweMap, "old_field")
                }
            }
        }
    }
    
    // Update version
    data["version"] = "1.1"
    return data, nil
}
```

## File Format Support

### CSV Export

```go
import (
    "encoding/csv"
    "strings"
)

func exportToCSV(registry *cwe.Registry) ([]byte, error) {
    var buf bytes.Buffer
    writer := csv.NewWriter(&buf)
    
    // Write header
    header := []string{"ID", "Name", "Severity", "Description", "URL"}
    err := writer.Write(header)
    if err != nil {
        return nil, err
    }
    
    // Write data
    for _, cweItem := range registry.GetAll() {
        record := []string{
            cweItem.ID,
            cweItem.Name,
            cweItem.Severity,
            strings.ReplaceAll(cweItem.Description, "\n", " "),
            cweItem.URL,
        }
        
        err := writer.Write(record)
        if err != nil {
            return nil, err
        }
    }
    
    writer.Flush()
    return buf.Bytes(), writer.Error()
}
```

### YAML Export

```go
import "gopkg.in/yaml.v2"

func exportToYAML(registry *cwe.Registry) ([]byte, error) {
    data := map[string]interface{}{
        "cwes":      registry.GetAll(),
        "count":     registry.Count(),
        "exported":  time.Now().Format(time.RFC3339),
    }
    
    return yaml.Marshal(data)
}

func importFromYAML(data []byte) (*cwe.Registry, error) {
    var yamlData map[string]interface{}
    err := yaml.Unmarshal(data, &yamlData)
    if err != nil {
        return nil, err
    }
    
    // Convert back to JSON for standard import
    jsonData, err := json.Marshal(yamlData["cwes"])
    if err != nil {
        return nil, err
    }
    
    registry := cwe.NewRegistry()
    err = registry.ImportFromJSON(jsonData)
    return registry, err
}
```

## Running the Example

```bash
go run main.go
```

This will create several export files, import them back, and demonstrate various serialization formats.

## Next Steps

- Explore [Rate Limited Client](./rate-limited) for optimizing data fetching
- Check the [API Reference](/api/) for complete serialization documentation
- Learn about [Building Trees](./build-tree) for exporting hierarchical structures
