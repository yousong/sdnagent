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

package models

import (
	"context"
	"fmt"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/util/compare"
	"yunion.io/x/pkg/util/regutils"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/cloudcommon/db/lockman"
	"yunion.io/x/onecloud/pkg/cloudcommon/db/taskman"
	"yunion.io/x/onecloud/pkg/cloudprovider"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/util/stringutils2"
)

type SNatDEntryManager struct {
	SNatEntryManager
}

var NatDEntryManager *SNatDEntryManager

func init() {
	NatDEntryManager = &SNatDEntryManager{
		SNatEntryManager: NewNatEntryManager(
			SNatDEntry{},
			"natdtables_tbl",
			"natdentry",
			"natdentries",
		),
	}
	NatDEntryManager.SetVirtualObject(NatDEntryManager)
}

type SNatDEntry struct {
	SNatEntry

	ExternalIP   string `width:"17" charset:"ascii" list:"user" create:"required"`
	ExternalPort int    `list:"user" create:"required"`

	InternalIP   string `width:"17" charset:"ascii" list:"user" create:"required"`
	InternalPort int    `list:"user" create:"required"`
	IpProtocol   string `width:"8" charset:"ascii" list:"user" create:"required"`
}

// NAT网关的目的地址转换规则列表
func (man *SNatDEntryManager) ListItemFilter(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.NatDEntryListInput,
) (*sqlchemy.SQuery, error) {
	q, err := man.SNatEntryManager.ListItemFilter(ctx, q, userCred, query.NatEntryListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SNatEntryManager.ListItemFilter")
	}

	if len(query.ExternalIP) > 0 {
		q = q.In("external_ip", query.ExternalIP)
	}
	if len(query.ExternalPort) > 0 {
		q = q.In("external_port", query.ExternalPort)
	}
	if len(query.InternalIP) > 0 {
		q = q.In("internal_ip", query.InternalIP)
	}
	if len(query.InternalPort) > 0 {
		q = q.In("internal_port", query.InternalPort)
	}
	if len(query.IpProtocol) > 0 {
		q = q.In("ip_protocol", query.IpProtocol)
	}

	return q, nil
}

func (manager *SNatDEntryManager) OrderByExtraFields(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.NatDEntryListInput,
) (*sqlchemy.SQuery, error) {
	q, err := manager.SNatEntryManager.OrderByExtraFields(ctx, q, userCred, query.NatEntryListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SNatEntryManager.OrderByExtraFields")
	}
	return q, nil
}

func (manager *SNatDEntryManager) QueryDistinctExtraField(q *sqlchemy.SQuery, field string) (*sqlchemy.SQuery, error) {
	var err error

	q, err = manager.SNatEntryManager.QueryDistinctExtraField(q, field)
	if err == nil {
		return q, nil
	}

	return q, httperrors.ErrNotFound
}

func (man *SNatDEntryManager) ValidateCreateData(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, data *jsonutils.JSONDict) (*jsonutils.JSONDict, error) {
	input := &api.SNatDCreateInput{}
	err := data.Unmarshal(input)
	if err != nil {
		return nil, httperrors.NewInputParameterError("Unmarshal input failed %s", err)
	}
	if len(input.NatgatewayId) == 0 || len(input.ExternalIpId) == 0 || len(input.ExternalIp) == 0 {
		return nil, httperrors.NewMissingParameterError("natgateway_id or external_ip_id or external_ip")
	}
	if input.ExternalPort < 1 || input.ExternalPort > 65535 {
		return nil, httperrors.NewInputParameterError("Port value error")
	}
	if input.InternalPort < 1 || input.InternalPort > 65535 {
		return nil, httperrors.NewInputParameterError("Port value error")
	}
	if !regutils.MatchIPAddr(input.InternalIp) {
		return nil, httperrors.NewInputParameterError("invalid internal ip address: %s", input.InternalIp)
	}

	// check ip + port
	eip, err := man.checkIPPort(input)
	if err != nil {
		return nil, httperrors.NewInputParameterError(err.Error())
	}

	// check that eip is suitable
	if len(eip.AssociateId) != 0 {
		if eip.AssociateId != input.NatgatewayId {
			return nil, httperrors.NewInputParameterError("eip has been binding to another instance")
		} else if !man.canBindIP(eip.IpAddr) {
			return nil, httperrors.NewInputParameterError("eip has been binding to snat rules")
		}
	} else {
		data.Add(jsonutils.NewBool(true), "need_bind")
	}
	data.Remove("external_ip_id")
	data.Add(jsonutils.NewString(eip.Id), "eip_id")
	data.Add(jsonutils.NewString(eip.ExternalId), "eip_external_id")
	data.Set("name", jsonutils.NewString(NatGatewayManager.NatNameFromReal(input.Name, input.NatgatewayId)))
	return data, nil
}

func (manager *SNatDEntryManager) checkIPPort(input *api.SNatDCreateInput) (*SElasticip, error) {
	q := manager.Query().Equals("external_ip", input.ExternalIp).Equals("external_port", input.ExternalPort)
	count, err := q.CountWithError()
	if err != nil {
		return nil, errors.Wrap(err, "fetch dnat with same external_ip and external_port")
	}
	if count > 0 {
		return nil, fmt.Errorf("there are dnat rules with same external ip and external port")
	}
	model, err := ElasticipManager.FetchById(input.ExternalIpId)
	if err != nil {
		return nil, err
	}
	if model == nil {
		return nil, httperrors.NewInputParameterError("No such eip")
	}
	eip := model.(*SElasticip)
	if eip.IpAddr != input.ExternalIp {
		return nil, fmt.Errorf("No such eip")
	}
	return eip, nil
}

func (manager *SNatDEntryManager) SyncNatDTable(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, nat *SNatGateway, extDTable []cloudprovider.ICloudNatDEntry) compare.SyncResult {
	syncOwnerId := provider.GetOwnerId()

	lockman.LockClass(ctx, manager, db.GetLockClassKey(manager, syncOwnerId))
	defer lockman.ReleaseClass(ctx, manager, db.GetLockClassKey(manager, syncOwnerId))

	result := compare.SyncResult{}
	dbNatDTables, err := nat.GetDTable()
	if err != nil {
		result.Error(err)
		return result
	}

	removed := make([]SNatDEntry, 0)
	commondb := make([]SNatDEntry, 0)
	commonext := make([]cloudprovider.ICloudNatDEntry, 0)
	added := make([]cloudprovider.ICloudNatDEntry, 0)
	if err := compare.CompareSets(dbNatDTables, extDTable, &removed, &commondb, &commonext, &added); err != nil {
		result.Error(err)
		return result
	}

	for i := 0; i < len(removed); i += 1 {
		err := removed[i].syncRemoveCloudNatDTable(ctx, userCred)
		if err != nil {
			result.DeleteError(err)
		} else {
			result.Delete()
		}
	}

	for i := 0; i < len(commondb); i += 1 {
		err := commondb[i].SyncWithCloudNatDTable(ctx, userCred, commonext[i], syncOwnerId)
		if err != nil {
			result.UpdateError(err)
			continue
		}
		syncMetadata(ctx, userCred, &commondb[i], commonext[i])
		result.Update()
	}

	for i := 0; i < len(added); i += 1 {
		routeTableNew, err := manager.newFromCloudNatDTable(ctx, userCred, syncOwnerId, nat, added[i])
		if err != nil {
			result.AddError(err)
			continue
		}
		syncMetadata(ctx, userCred, routeTableNew, added[i])
		result.Add()
	}
	return result
}

func (self *SNatDEntry) GetCloudproviderId() string {
	nat, _ := self.GetNatgateway()
	if nat != nil {
		return nat.GetCloudproviderId()
	}
	return ""
}

func (self *SNatDEntry) syncRemoveCloudNatDTable(ctx context.Context, userCred mcclient.TokenCredential) error {
	lockman.LockObject(ctx, self)
	defer lockman.ReleaseObject(ctx, self)

	err := self.ValidateDeleteCondition(ctx)
	if err != nil { // cannot delete
		return self.SetStatus(userCred, api.VPC_STATUS_UNKNOWN, "sync to delete")
	}
	return self.RealDelete(ctx, userCred)
}

func (self *SNatDEntry) SyncWithCloudNatDTable(ctx context.Context, userCred mcclient.TokenCredential, extEntry cloudprovider.ICloudNatDEntry, syncOwnerId mcclient.IIdentityProvider) error {
	diff, err := db.UpdateWithLock(ctx, self, func() error {
		self.Status = extEntry.GetStatus()
		self.ExternalIP = extEntry.GetExternalIp()
		self.ExternalPort = extEntry.GetExternalPort()
		self.InternalIP = extEntry.GetInternalIp()
		self.InternalPort = extEntry.GetInternalPort()
		self.IpProtocol = extEntry.GetIpProtocol()
		return nil
	})
	if err != nil {
		return err
	}

	SyncCloudDomain(userCred, self, syncOwnerId)

	db.OpsLog.LogSyncUpdate(self, diff, userCred)
	return nil
}

func (manager *SNatDEntryManager) newFromCloudNatDTable(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, nat *SNatGateway, extEntry cloudprovider.ICloudNatDEntry) (*SNatDEntry, error) {
	table := SNatDEntry{}
	table.SetModelManager(manager, &table)

	table.Name = NatGatewayManager.NatNameFromReal(extEntry.GetName(), nat.Id)
	table.Status = extEntry.GetStatus()
	table.ExternalId = extEntry.GetGlobalId()
	table.IsEmulated = extEntry.IsEmulated()
	table.NatgatewayId = nat.Id
	table.ExternalIP = extEntry.GetExternalIp()
	table.ExternalPort = extEntry.GetExternalPort()
	table.InternalIP = extEntry.GetInternalIp()
	table.InternalPort = extEntry.GetInternalPort()
	table.IpProtocol = extEntry.GetIpProtocol()

	err := manager.TableSpec().Insert(ctx, &table)
	if err != nil {
		log.Errorf("newFromCloudNatDTable fail %s", err)
		return nil, err
	}

	SyncCloudDomain(userCred, &table, ownerId)

	db.OpsLog.LogEvent(&table, db.ACT_CREATE, table.GetShortDesc(ctx), userCred)

	return &table, nil
}

func (self *SNatDEntry) GetExtraDetails(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	query jsonutils.JSONObject,
	isList bool,
) (api.NatDEntryDetails, error) {
	return api.NatDEntryDetails{}, nil
}

func (manager *SNatDEntryManager) FetchCustomizeColumns(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	query jsonutils.JSONObject,
	objs []interface{},
	fields stringutils2.SSortedStrings,
	isList bool,
) []api.NatDEntryDetails {
	rows := make([]api.NatDEntryDetails, len(objs))
	entryRows := manager.SNatEntryManager.FetchCustomizeColumns(ctx, userCred, query, objs, fields, isList)
	for i := range rows {
		rows[i] = api.NatDEntryDetails{
			NatEntryDetails: entryRows[i],
		}
	}
	return rows
}

func (self *SNatDEntry) PostCreate(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, data jsonutils.JSONObject) {
	if len(self.NatgatewayId) == 0 {
		return
	}
	// ValidateCreateData function make data must contain 'externalIpId' key
	taskData := data.(*jsonutils.JSONDict)
	task, err := taskman.TaskManager.NewTask(ctx, "SNatDEntryCreateTask", self, userCred, taskData, "", "", nil)
	if err != nil {
		log.Errorf("SNatDEntryCreateTask newTask error %s", err)
	} else {
		task.ScheduleRun(nil)
	}
}

func (self *SNatDEntry) CustomizeDelete(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, data jsonutils.JSONObject) error {
	if len(self.ExternalId) > 0 {
		return self.StartDeleteDNatTask(ctx, userCred)
	} else {
		return self.RealDelete(ctx, userCred)
	}
}

func (self *SNatDEntry) StartDeleteDNatTask(ctx context.Context, userCred mcclient.TokenCredential) error {
	task, err := taskman.TaskManager.NewTask(ctx, "SNatDEntryDeleteTask", self, userCred, nil, "", "", nil)
	if err != nil {
		log.Errorf("Start dnatEntry deleteTask fail %s", err)
		return err
	}
	task.ScheduleRun(nil)
	return nil
}

func (self *SNatDEntryManager) canBindIP(ipAddr string) bool {
	q := NatSEntryManager.Query().Equals("ip", ipAddr)
	count, _ := q.CountWithError()
	if count != 0 {
		return false
	}
	return true
}

func (self *SNatDEntry) CountByEIP() (int, error) {
	q := NatDEntryManager.Query().Equals("external_ip", self.ExternalIP)
	return q.CountWithError()
}
