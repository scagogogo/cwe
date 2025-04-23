# CWE 库

这个库提供了用于操作CWE (Common Weakness Enumeration) 数据的Go语言工具。

## 代码组织

代码已根据功能模块重构为更小的文件，提高了可维护性：

1. **核心模型和数据结构**
   - `cwe.go` (14行): 包文档和导出接口
   - `cwe_model.go` (151行): CWE数据结构和方法
   - `cwe_registry.go` (117行): CWE注册表管理
   - `cwe_search.go` (45行): 搜索功能
   - `cwe_utils.go` (68行): 工具函数

2. **API客户端**
   - `api_client.go` (54行): 基础API客户端结构
   - `api_client_version.go` (40行): 版本相关API
   - `api_client_cwe.go` (138行): CWE数据检索API
   - `api_client_relations.go` (129行): 关系查询API
   - `api_integration.go` (377行): 集成功能

## 测试组织

测试文件与功能文件对应，测试覆盖率为92.6%：

1. **核心模型测试**
   - `cwe_test.go`: 测试CWE模型基本功能
   - `cwe_registry_test.go`: 测试注册表功能
   - `cwe_search_test.go`: 测试搜索功能
   - `cwe_utils_test.go`: 测试工具函数

2. **API客户端测试**
   - `api_client_test.go`: 测试API客户端基础功能
   - `api_client_cwe_test.go`: 测试CWE数据API
   - `api_client_relations_test.go`: 测试关系查询API
   - `api_client_version_test.go`: 测试版本API
   - `api_integration_test.go`: 测试集成功能

3. **其他测试文件**
   - `build_tree_test.go`: 测试树构建
   - `fetch_category_test.go`: 测试分类获取
   - `fetch_multiple_test.go`: 测试批量获取
   - `xml_json_test.go`: 测试序列化

## 使用示例

请参阅`examples`目录中的示例程序：

1. `01_basic_usage`: 基本使用
2. `02_fetch_cwe`: 获取CWE数据
3. `03_build_tree`: 构建CWE树
4. `04_search_and_filter`: 搜索和过滤
5. `05_export_import`: 导出和导入

## 许可证

MIT License 