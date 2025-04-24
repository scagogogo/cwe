package cwe

// APIResponse 通用API响应结构
// 这个结构体为所有API响应提供基础字段
type APIResponse struct {
	// Status API响应状态
	Status int `json:"status,omitempty"`

	// Message 响应消息
	Message string `json:"message,omitempty"`

	// Error 错误信息
	Error string `json:"error,omitempty"`
}

// CWEWeakness 表示CWE弱点条目的结构体
type CWEWeakness struct {
	// ID CWE的唯一标识符，格式为"CWE-数字"，例如"CWE-79"
	ID string `json:"id"`

	// Name CWE的名称
	Name string `json:"name"`

	// Description CWE的详细描述信息
	Description string `json:"description,omitempty"`

	// ExtendedDescription 扩展描述信息
	ExtendedDescription string `json:"extended_description,omitempty"`

	// Abstraction 抽象级别（Base, Class, Variant等）
	Abstraction string `json:"abstraction,omitempty"`

	// Structure 结构类型（Simple, Chain, Composite等）
	Structure string `json:"structure,omitempty"`

	// Status 状态（Stable, Draft, Incomplete等）
	Status string `json:"status,omitempty"`

	// URL CWE对应的详情页的网址
	URL string `json:"url,omitempty"`

	// Severity CWE的严重性级别（High, Medium, Low等）
	Severity string `json:"severity,omitempty"`

	// LikelihoodOfExploit 利用可能性
	LikelihoodOfExploit string `json:"likelihood_of_exploit,omitempty"`

	// RelatedWeaknesses 相关弱点关系列表
	RelatedWeaknesses []CWERelation `json:"related_weaknesses,omitempty"`

	// CommonConsequences 常见影响
	CommonConsequences []CWEConsequence `json:"common_consequences,omitempty"`

	// DetectionMethods 检测方法
	DetectionMethods []CWEDetectionMethod `json:"detection_methods,omitempty"`

	// Mitigations 缓解措施
	Mitigations []CWEMitigation `json:"mitigations,omitempty"`

	// AlternateTerms 替代术语
	AlternateTerms []CWEAlternateTerm `json:"alternate_terms,omitempty"`

	// ApplicablePlatforms 适用平台
	ApplicablePlatforms []CWEApplicablePlatform `json:"applicable_platforms,omitempty"`

	// DemonstrativeExamples 示例代码
	DemonstrativeExamples []interface{} `json:"demonstrative_examples,omitempty"`

	// ObservedExamples 已观察到的实例
	ObservedExamples []CWEObservedExample `json:"observed_examples,omitempty"`

	// ContentHistory 内容历史
	ContentHistory []CWEContentHistoryEntry `json:"content_history,omitempty"`

	// 原始数据，保存未明确映射的字段
	RawData map[string]interface{} `json:"-"`
}

// CWECategory 表示CWE分类条目的结构体
type CWECategory struct {
	// ID 分类的唯一标识符
	ID string `json:"id"`

	// Name 分类名称
	Name string `json:"name"`

	// Description 分类描述
	Description string `json:"description,omitempty"`

	// URL 分类对应的详情页的网址
	URL string `json:"url,omitempty"`

	// Status 状态
	Status string `json:"status,omitempty"`

	// Members 该分类包含的成员ID列表
	Members []string `json:"members,omitempty"`

	// MappingNotes 映射注释
	MappingNotes *CWEMappingNotes `json:"mapping_notes,omitempty"`

	// ContentHistory 内容历史
	ContentHistory []CWEContentHistoryEntry `json:"content_history,omitempty"`

	// 原始数据，保存未明确映射的字段
	RawData map[string]interface{} `json:"-"`
}

// CWEView 表示CWE视图条目的结构体
type CWEView struct {
	// ID 视图的唯一标识符
	ID string `json:"id"`

	// Name 视图名称
	Name string `json:"name"`

	// Type 视图类型
	Type string `json:"type,omitempty"`

	// Description 视图描述
	Description string `json:"description,omitempty"`

	// URL 视图对应的详情页的网址
	URL string `json:"url,omitempty"`

	// Status 状态
	Status string `json:"status,omitempty"`

	// Objective 目标
	Objective string `json:"objective,omitempty"`

	// Audience 受众
	Audience []CWEAudience `json:"audience,omitempty"`

	// Members 该视图包含的成员列表
	Members []CWEViewMember `json:"members,omitempty"`

	// MappingNotes 映射注释
	MappingNotes *CWEMappingNotes `json:"mapping_notes,omitempty"`

	// Notes 备注
	Notes []CWENote `json:"notes,omitempty"`

	// ContentHistory 内容历史
	ContentHistory []CWEContentHistoryEntry `json:"content_history,omitempty"`

	// 原始数据，保存未明确映射的字段
	RawData map[string]interface{} `json:"-"`
}

// CWERelation 表示CWE间关系的结构体
type CWERelation struct {
	// Nature 关系性质，如"ChildOf"、"ParentOf"
	Nature string `json:"nature"`

	// CweID 相关CWE的ID
	CweID string `json:"cwe_id"`

	// ViewID 视图ID
	ViewID string `json:"view_id,omitempty"`

	// Ordinal 关系优先级
	Ordinal string `json:"ordinal,omitempty"`
}

// CWEConsequence 表示CWE可能导致的后果
type CWEConsequence struct {
	// Scope 影响范围
	Scope []string `json:"scope,omitempty"`

	// Impact 影响类型
	Impact []string `json:"impact,omitempty"`

	// Note 备注
	Note string `json:"note,omitempty"`
}

// CWEDetectionMethod 表示CWE的检测方法
type CWEDetectionMethod struct {
	// Method 方法名称
	Method string `json:"method"`

	// Description 描述
	Description string `json:"description,omitempty"`

	// Effectiveness 有效性
	Effectiveness string `json:"effectiveness,omitempty"`

	// EffectivenessNotes 有效性备注
	EffectivenessNotes string `json:"effectiveness_notes,omitempty"`
}

// CWEMitigation 表示CWE的缓解措施
type CWEMitigation struct {
	// MitigationID 缓解措施ID
	MitigationID string `json:"mitigation_id,omitempty"`

	// Phase 适用阶段
	Phase []string `json:"phase,omitempty"`

	// Strategy 策略
	Strategy string `json:"strategy,omitempty"`

	// Description 描述
	Description string `json:"description"`

	// Effectiveness 有效性
	Effectiveness string `json:"effectiveness,omitempty"`

	// EffectivenessNotes 有效性备注
	EffectivenessNotes string `json:"effectiveness_notes,omitempty"`
}

// CWEAlternateTerm 表示CWE的替代术语
type CWEAlternateTerm struct {
	// Term 术语
	Term string `json:"term"`

	// Description 描述
	Description string `json:"description,omitempty"`
}

// CWEApplicablePlatform 表示CWE适用的平台
type CWEApplicablePlatform struct {
	// Type 平台类型
	Type string `json:"type"`

	// Class 平台类别
	Class string `json:"class"`

	// Prevalence 流行程度
	Prevalence string `json:"prevalence,omitempty"`
}

// CWEObservedExample 表示CWE的实际观察到的例子
type CWEObservedExample struct {
	// Reference 引用标识符，如CVE号
	Reference string `json:"reference"`

	// Description 描述
	Description string `json:"description,omitempty"`

	// Link 链接
	Link string `json:"link,omitempty"`
}

// CWEContentHistoryEntry 表示CWE内容的历史记录条目
type CWEContentHistoryEntry struct {
	// Type 记录类型
	Type string `json:"type"`

	// SubmissionName/ModificationName 提交/修改者名称
	SubmissionName   string `json:"submission_name,omitempty"`
	ModificationName string `json:"modification_name,omitempty"`

	// SubmissionOrganization/ModificationOrganization 提交/修改组织
	SubmissionOrganization   string `json:"submission_organization,omitempty"`
	ModificationOrganization string `json:"modification_organization,omitempty"`

	// SubmissionDate/ModificationDate 提交/修改日期
	SubmissionDate   string `json:"submission_date,omitempty"`
	ModificationDate string `json:"modification_date,omitempty"`

	// ModificationComment 修改评论
	ModificationComment string `json:"modification_comment,omitempty"`

	// SubmissionVersion/ModificationVersion 提交/修改版本
	SubmissionVersion   string `json:"submission_version,omitempty"`
	ModificationVersion string `json:"modification_version,omitempty"`

	// SubmissionReleaseDate/ModificationReleaseDate 提交/修改发布日期
	SubmissionReleaseDate   string `json:"submission_release_date,omitempty"`
	ModificationReleaseDate string `json:"modification_release_date,omitempty"`
}

// CWEAudience 表示CWE视图的目标受众
type CWEAudience struct {
	// Type 受众类型
	Type string `json:"type"`

	// Description 描述
	Description string `json:"description,omitempty"`
}

// CWEViewMember 表示CWE视图的成员
type CWEViewMember struct {
	// CweID CWE ID
	CweID string `json:"cwe_id"`

	// ViewID 视图ID
	ViewID string `json:"view_id"`
}

// CWEMappingNotes 表示CWE映射注释
type CWEMappingNotes struct {
	// Usage 使用情况
	Usage string `json:"usage,omitempty"`

	// Rationale 理由
	Rationale string `json:"rationale,omitempty"`

	// Comments 评论
	Comments string `json:"comments,omitempty"`

	// Reasons 原因
	Reasons []string `json:"reasons,omitempty"`
}

// CWENote 表示CWE的备注
type CWENote struct {
	// Type 备注类型
	Type string `json:"type"`

	// Note 备注内容
	Note string `json:"note"`
}

// WeaknessResponse 表示API返回的弱点响应
type WeaknessResponse struct {
	APIResponse
	Weaknesses []*CWEWeakness `json:"weaknesses,omitempty"`
}

// CategoryResponse 表示API返回的分类响应
type CategoryResponse struct {
	APIResponse
	Categories []*CWECategory `json:"categories,omitempty"`
}

// ViewResponse 表示API返回的视图响应
type ViewResponse struct {
	APIResponse
	Views []*CWEView `json:"views,omitempty"`
}

// VersionResponse 表示API返回的版本响应
type VersionResponse struct {
	APIResponse
	Version     string `json:"version,omitempty"`
	ReleaseDate string `json:"release_date,omitempty"`
}

// CWEsResponse 表示API返回的多个CWE响应
type CWEsResponse struct {
	APIResponse
	CWEs map[string]*CWEWeakness `json:"cwes,omitempty"`
}
