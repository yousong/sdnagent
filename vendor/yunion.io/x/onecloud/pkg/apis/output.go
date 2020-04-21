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

type ModelBaseDetails struct {
	Meta

	// 资源是否可以删除, 若为flase, delete_fail_reason会返回不能删除的原因
	// example: true
	CanDelete bool `json:"can_delete"`

	// 资源不能删除的原因
	DeleteFailReason string `json:"delete_fail_reason"`

	// 资源是否可以更新, 若为false,update_fail_reason会返回资源不能删除的原因
	// example: true
	CanUpdate bool `json:"can_update"`

	// 资源不能删除的原因
	UpdateFailReason string `json:"update_fail_reason"`
}

type ModelBaseShortDescDetail struct {
	ResName string `json:"res_name"`
}

type SharedProject struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type SharableVirtualResourceDetails struct {
	VirtualResourceDetails

	SharedProjects []SharedProject `json:"shared_projects"`
}

type AdminSharableVirtualResourceDetails struct {
	SharableVirtualResourceDetails
}

type StandaloneResourceShortDescDetail struct {
	ModelBaseShortDescDetail

	Id   string `json:"id"`
	Name string `json:"name"`
}

type EnabledStatusDomainLevelResourceDetails struct {
	StatusDomainLevelResourceDetails
}

type StatusDomainLevelResourceDetails struct {
	DomainLevelResourceDetails
}

type DomainLevelResourceDetails struct {
	StandaloneResourceDetails

	DomainizedResourceInfo
}

type VirtualResourceDetails struct {
	StatusStandaloneResourceDetails

	ProjectizedResourceInfo
}

type VirtualJointResourceBaseDetails struct {
	JointResourceBaseDetails
}

type JointResourceBaseDetails struct {
	ResourceBaseDetails
}

type ResourceBaseDetails struct {
	ModelBaseDetails
}

type EnabledStatusStandaloneResourceDetails struct {
	StatusStandaloneResourceDetails
}

type StatusStandaloneResourceDetails struct {
	StandaloneResourceDetails
}

type StandaloneResourceDetails struct {
	ResourceBaseDetails

	// 标签
	Metadata map[string]string `json:"metadata"`
}

type DomainizedResourceInfo struct {
	// 资源归属项目的域名称
	ProjectDomain string `json:"project_domain"`
}

type ProjectizedResourceInfo struct {
	DomainizedResourceInfo

	// 资源归属项目的名称
	// alias:project
	Project string `json:"tenant"`

	// 资源归属项目的ID(向后兼容别名）
	// Deprecated
	TenantId string `json:"project_id"`

	// 资源归属项目的名称（向后兼容别名）
	// Deprecated
	Tenant string `json:"project"`
}
