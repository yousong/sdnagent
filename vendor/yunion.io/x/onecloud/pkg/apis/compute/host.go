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

package compute

import (
	"yunion.io/x/jsonutils"

	"yunion.io/x/onecloud/pkg/apis"
)

type HostSpec struct {
	apis.Meta

	Cpu         int            `json:"cpu"`
	Mem         int            `json:"mem"`
	NicCount    int            `json:"nic_count"`
	Manufacture string         `json:"manufacture"`
	Model       string         `json:"model"`
	Disk        DiskDriverSpec `json:"disk"`
	Driver      string         `json:"driver"`
}

type DiskDriverSpec map[string]DiskAdapterSpec

type DiskAdapterSpec map[string][]*DiskSpec

type DiskSpec struct {
	apis.Meta

	Type       string `json:"type"`
	Size       int64  `json:"size"`
	StartIndex int    `json:"start_index"`
	EndIndex   int    `json:"end_index"`
	Count      int    `json:"count"`
}

type HostListInput struct {
	apis.EnabledStatusStandaloneResourceListInput
	apis.DomainizedResourceListInput

	ManagedResourceListInput
	ZonalFilterListInput
	WireFilterListInput
	SchedtagFilterListInput

	StorageFilterListInput
	UsableResourceListInput

	// filter by ResourceType
	ResourceType string `json:"resource_type"`
	// filter by mac of any network interface
	AnyMac string `json:"any_mac"`
	// filter storages not attached to this host
	StorageNotAttached *bool `json:"storage_not_attached"`
	// filter by Hypervisor
	Hypervisor string `json:"hypervisor"`
	// filter host that is empty
	IsEmpty *bool `json:"is_empty"`
	// filter host that is baremetal
	Baremetal *bool `json:"baremetal"`

	// 机架
	Rack []string `json:"rack"`
	// 机位
	Slots []string `json:"slots"`
	// 管理口MAC
	AccessMac []string `json:"access_mac"`
	// 管理口Ip地址
	AccessIp []string `json:"access_ip"`
	// 物理机序列号信息
	SN []string `json:"sn"`
	// CPU大小
	CpuCount []int `json:"cpu_count"`
	// 内存大小,单位Mb
	MemSize []int `json:"mem_size"`
	// 存储类型
	StorageType []string `json:"storage_type"`
	// IPMI地址
	IpmiIp []string `json:"ipmi_ip"`
	// 宿主机状态
	// example: online
	HostStatus []string `json:"host_status"`
	// 宿主机类型
	HostType []string `json:"host_type"`
	// host服务软件版本
	Version []string `json:"version"`
	// OVN软件版本
	OvnVersion []string `json:"ovn_version"`
	// 是否处于维护状态
	IsMaintenance *bool `json:"is_maintenance"`
	// 是否为导入的宿主机
	IsImport *bool `json:"is_import"`
	// 是否允许PXE启动
	EnablePxeBoot *bool `json:"enable_pxe_boot"`
	// 主机UUID
	Uuid []string `json:"uuid"`
	// 主机启动模式, 可能值位PXE和ISO
	BootMode []string `json:"boot_mode"`
}

type HostDetails struct {
	apis.EnabledStatusStandaloneResourceDetails
	ManagedResourceInfo
	ZoneResourceInfo

	SHost

	Schedtags []SchedtagShortDescDetails `json:"schedtags"`

	ServerId  string `json:"server_id"`
	Server    string `json:"server"`
	ServerIps string `json:"server_ips"`
	// 网卡数量
	NicCount int `json:"nic_count"`
	// 网卡详情
	NicInfo []jsonutils.JSONObject `json:"nic_info"`
	// CPU超分比
	CpuCommit int `json:"cpu_commit"`
	// 内存超分比
	MemCommit int `json:"mem_commit"`
	// 云主机数量
	// example: 10
	Guests int `json:"guests"`
	// 非系统云主机数量
	// example: 0
	NonsystemGuests int `json:"nonsystem_guests"`
	// 运行中云主机数量
	// example: 2
	RunningGuests int `json:"running_geusts"`
	// CPU超分率
	CpuCommitRate float64 `json:"cpu_commit_rate"`
	// 内存超分率
	MemCommitRate float64 `json:"mem_commit_rate"`
	// 存储大小
	Storage int64 `json:"storage"`
	// 已使用存储大小
	StorageUsed int64 `json:"storage_used"`
	// 浪费存储大小(异常磁盘存储大小)
	StorageWaste int64 `json:"storage_waste"`
	// 虚拟存储大小
	StorageVirtual int64 `json:"storage_virtual"`
	// 可用存储大小
	StorageFree int64 `json:"storage_free"`
	// 存储超分率
	StorageCommitRate float64             `json:"storage_commit_rate"`
	Spec              *jsonutils.JSONDict `json:"spec"`
	IsPrepaidRecycle  bool                `json:"is_prepaid_recycle"`
	CanPrepare        bool                `json:"can_prepare"`
	PrepareFailReason string              `json:"prepare_fail_reason"`

	// 标签
	Metadata map[string]string `json:"metadata"`
}

type HostResourceInfo struct {
	// 归属云订阅ID
	ManagerId string `json:"manager_id"`

	ManagedResourceInfo

	// 归属可用区ID
	ZoneId string `json:"zone_id"`

	ZoneResourceInfo

	// 宿主机名称
	Host string `json:"host"`

	// 宿主机序列号
	HostSN string `json:"host_sn"`

	// 宿主机状态
	HostStatus string `json:"host_status"`

	// 宿主机服务状态`
	HostServiceStatus string `json:"host_service_status"`

	// 宿主机类型
	HostType string `json:"host_type"`
}

type HostFilterListInput struct {
	ZonalFilterListInput
	ManagedResourceListInput

	HostFilterListInputBase
}

type HostFilterListInputBase struct {
	HostResourceInput

	// 以宿主机序列号过滤
	HostSN string `json:"host_sn"`

	// 以宿主机名称排序
	OrderByHost string `json:"order_by_host"`

	// 以宿主机序列号名称排序
	OrderByHostSN string `json:"order_by_host_sn"`
}

type HostResourceInput struct {
	// 宿主机或物理机（ID或Name）
	Host string `json:"host"`
	// swagger:ignore
	// Deprecated
	// filter by host_id
	HostId string `json:"host_id" deprecated-by:"host"`
}
