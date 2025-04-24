package cwe

// DataFetcher 提供从API获取CWE数据并转换为本地数据结构的功能
type DataFetcher struct {
	client *APIClient
}

// NewDataFetcher 创建新的数据获取器
func NewDataFetcher() *DataFetcher {
	return &DataFetcher{
		client: NewAPIClient(),
	}
}

// NewDataFetcherWithClient 使用自定义API客户端创建数据获取器
func NewDataFetcherWithClient(client *APIClient) *DataFetcher {
	return &DataFetcher{
		client: client,
	}
}

// GetCurrentVersion 获取当前CWE版本
func (f *DataFetcher) GetCurrentVersion() (string, error) {
	versionResp, err := f.client.GetVersion()
	if err != nil {
		return "", err
	}
	return versionResp.Version, nil
}
