// Copyright 2019 Yunion
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apis

type DomainizedResourceInput struct {
	// 指定项目归属域名称或ID
	// required: false
	ProjectDomain string `json:"project_domain"`

	// swagger:ignore
	// Deprecated
	Domain string `json:"domain" deprecated-by:"project_domain"`
	// swagger:ignore
	// Deprecated
	// Project domain Id filter, alias for project_domain
	ProjectDomainId string `json:"project_domain_id" deprecated-by:"project_domain"`
	// swagger:ignore
	// Deprecated
	// Domain Id filter, alias for project_domain
	DomainId string `json:"domain_id" deprecated-by:"project_domain"`
}

type ProjectizedResourceInput struct {
	// 指定项目的名称或ID
	// required: false
	Project string `json:"project"`
	// swagger:ignore
	// Deprecated
	// Filter by project_id, alias for project
	ProjectId string `json:"project_id" deprecated-by:"project"`
	// swagger:ignore
	// Deprecated
	// Filter by tenant ID or Name, alias for project
	Tenant string `json:"tenant" deprecated-by:"project"`
	// swagger:ignore
	// Deprecated
	// Filter by tenant_id, alias for project
	TenantId string `json:"tenant_id" deprecated-by:"project"`
}

type DomainizedResourceCreateInput struct {
	DomainizedResourceInput
}

type ProjectizedResourceCreateInput struct {
	DomainizedResourceInput
	ProjectizedResourceInput
}

type SharableVirtualResourceCreateInput struct {
	VirtualResourceCreateInput

	// description: indicate the resource is a public resource
	// required: false
	IsPublic *bool `json:"is_public"`

	// description: indicate the shared scope for a public resource, which can be domain or system or none
	// required: false
	PublicScope string `json:"public_scope"`
}

type VirtualResourceCreateInput struct {
	StatusStandaloneResourceCreateInput
	ProjectizedResourceCreateInput

	// description: indicate the resource is a system resource, which is not visible to user
	// required: false
	IsSystem *bool `json:"is_system"`
}

type EnabledBaseResourceCreateInput struct {
	// 该资源是否被管理员*人为*启用或者禁用
	// required: false
	Enabled *bool `json:"enabled"`
}

type StatusBaseResourceCreateInput struct {
	// 用来存储资源的状态
	// required: false
	Status string `json:"status"`
}

type EnabledStatusDomainLevelResourceCreateInput struct {
	StatusDomainLevelResourceCreateInput
	EnabledBaseResourceCreateInput
}

type StatusDomainLevelResourceCreateInput struct {
	DomainLevelResourceCreateInput
	StatusBaseResourceCreateInput
}

type DomainLevelResourceCreateInput struct {
	StandaloneResourceCreateInput
	DomainizedResourceCreateInput
}

type EnabledStatusStandaloneResourceCreateInput struct {
	StatusStandaloneResourceCreateInput
	EnabledBaseResourceCreateInput
}

type StatusStandaloneResourceCreateInput struct {
	StandaloneResourceCreateInput
	StatusBaseResourceCreateInput
}

type StandaloneResourceCreateInput struct {
	ResourceBaseCreateInput

	// description: resource name, required if generated_name is not given
	// unique: true
	// required: true
	// example: test-network
	Name string `json:"name"`

	// description: generated resource name, given a pattern to generate name, required if name is not given
	// unique: false
	// required: false
	// example: test###
	GenerateName string `json:"generate_name"`

	// description: resource description
	// required: false
	// example: test create network
	Description string `json:"description"`

	// description: the resource is an emulated resource
	// required: false
	IsEmulated *bool `json:"is_emulated"`

	// 标签列表,最多支持20个
	// example: { "user:rd": "op" }
	Metadata map[string]string `json:"__meta__"`
}

type JoinResourceBaseCreateInput struct {
	ResourceBaseCreateInput
}

type ResourceBaseCreateInput struct {
	ModelBaseCreateInput
}

type ModelBaseCreateInput struct {
	Meta
}

type PerformStatusInput struct {
	// 更改的目标状态值
	// required:true
	Status string `json:"status"`

	// 更改状态的原因描述
	// required:false
	Reason string `json:"reason"`
}

type GetDetailsStatusOutput struct {
	// 状态
	Status string `json:"status"`
}

type PerformProjectPublicInput struct {
	// 共享项目资源的共享范围，可能的值为：project, domain和system
	// pattern: project|domain|system
	Scope string `json:"scope"`

	// 如果共享范围为项目，则在此列表中指定共享的目标项目
	SharedProjects []string `json:"shared_projects"`
}

type PerformProjectPrivateInput struct {
}

type PerformChangeProjectOwnerInput struct {
	ProjectizedResourceInput
}

type PerformChangeDomainOwnerInput struct {
	DomainizedResourceInput
}

type PerformEnableInput struct {
}

type PerformDisableInput struct {
}
