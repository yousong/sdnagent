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
	"net"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/util/compare"
	"yunion.io/x/pkg/util/netutils"
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

type SNatSEntryManager struct {
	SNatEntryManager
	SNetworkResourceBaseManager
}

var NatSEntryManager *SNatSEntryManager

func init() {
	NatSEntryManager = &SNatSEntryManager{
		SNatEntryManager: NewNatEntryManager(
			SNatSEntry{},
			"natstables_tbl",
			"natsentry",
			"natsentries",
		),
	}
	NatSEntryManager.SetVirtualObject(NatSEntryManager)
}

type SNatSEntry struct {
	SNatEntry
	SNetworkResourceBase

	IP         string `charset:"ascii" list:"user" create:"required"`
	SourceCIDR string `width:"22" charset:"ascii" list:"user" create:"required"`
}

func (self *SNatSEntry) GetCloudproviderId() string {
	network, err := self.GetNetwork()
	if err == nil {
		return network.GetCloudproviderId()
	}
	return ""
}

func (self *SNatSEntry) GetNetwork() (*SNetwork, error) {
	if len(self.NetworkId) == 0 {
		return nil, nil
	}
	_network, err := NetworkManager.FetchById(self.NetworkId)
	if err != nil {
		return nil, err
	}
	return _network.(*SNetwork), nil
}

// NAT网关的源地址转换规则列表
func (man *SNatSEntryManager) ListItemFilter(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.NatSEntryListInput,
) (*sqlchemy.SQuery, error) {
	q, err := man.SNatEntryManager.ListItemFilter(ctx, q, userCred, query.NatEntryListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SNatEntryManager.ListItemFilter")
	}
	netQuery := api.NetworkFilterListInput{
		NetworkFilterListBase: query.NetworkFilterListBase,
	}
	q, err = man.SNetworkResourceBaseManager.ListItemFilter(ctx, q, userCred, netQuery)
	if err != nil {
		return nil, errors.Wrap(err, "SNetworkResourceBaseManager.ListItemFilter")
	}

	if len(query.IP) > 0 {
		q = q.In("ip", query.IP)
	}
	if len(query.SourceCIDR) > 0 {
		q = q.In("source_cidr", query.SourceCIDR)
	}

	return q, nil
}

func (manager *SNatSEntryManager) OrderByExtraFields(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.NatSEntryListInput,
) (*sqlchemy.SQuery, error) {
	var err error
	q, err = manager.SNatEntryManager.OrderByExtraFields(ctx, q, userCred, query.NatEntryListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SNatEntryManager.OrderByExtraFields")
	}
	netQuery := api.NetworkFilterListInput{
		NetworkFilterListBase: query.NetworkFilterListBase,
	}
	q, err = manager.SNetworkResourceBaseManager.OrderByExtraFields(ctx, q, userCred, netQuery)
	if err != nil {
		return nil, errors.Wrap(err, "SNetworkResourceBaseManager.OrderByExtraFields")
	}
	return q, nil
}

func (manager *SNatSEntryManager) QueryDistinctExtraField(q *sqlchemy.SQuery, field string) (*sqlchemy.SQuery, error) {
	var err error

	q, err = manager.SNatEntryManager.QueryDistinctExtraField(q, field)
	if err == nil {
		return q, nil
	}
	q, err = manager.SNetworkResourceBaseManager.QueryDistinctExtraField(q, field)
	if err == nil {
		return q, nil
	}

	return q, httperrors.ErrNotFound
}

func (man *SNatSEntryManager) ValidateCreateData(ctx context.Context, userCred mcclient.TokenCredential,
	ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, data *jsonutils.JSONDict) (*jsonutils.JSONDict, error) {
	input := &api.SNatSCreateInput{}
	err := data.Unmarshal(input)
	if err != nil {
		return nil, httperrors.NewInputParameterError("Unmarshal input failed %s", err)
	}
	if len(input.NatgatewayId) == 0 || len(input.ExternalIpId) == 0 || len(input.Ip) == 0 {
		return nil, httperrors.NewMissingParameterError("natgateway_id or external_ip_id or ip")
	}
	if len(input.SourceCidr) == 0 && len(input.NetworkId) == 0 {
		return nil, httperrors.NewMissingParameterError("sourceCIDR or network_id")
	}
	if len(input.SourceCidr) != 0 && len(input.NetworkId) != 0 {
		return nil, httperrors.NewInputParameterError("Only one of that sourceCIDR and netword_id is needed")
	}

	if len(input.SourceCidr) != 0 {
		//check sourceCidr and convert to netutils.IPV4Range
		sourceIPV4Range, err := newIPv4RangeFromCIDR(input.SourceCidr)
		if err != nil {
			return nil, httperrors.NewInputParameterError(err.Error())
		}
		// get natgateway
		model, err := man.FetchById(input.NatgatewayId)
		if err != nil {
			return nil, err
		}
		natgateway := model.(*SNatGateway)
		// get vpc
		vpc := natgateway.GetVpc()
		if vpc == nil {
			return nil, errors.Wrap(httperrors.ErrBadRequest, "invalid natgateway vpc")
		}

		vpcIPV4Range, err := newIPv4RangeFromCIDR(vpc.CidrBlock)
		if err != nil {
			return nil, errors.Wrap(err, "convert vpc cidr to ipv4range error")
		}
		if !vpcIPV4Range.ContainsRange(sourceIPV4Range) {
			return nil, httperrors.NewInputParameterError("cidr %s is not in range vpc %s", input.SourceCidr,
				vpc.CidrBlock)
		}

	} else {
		network, err := man.checkNetWorkId(input.NetworkId)
		if err != nil {
			return nil, httperrors.NewInputParameterError(err.Error())
		}
		data.Add(jsonutils.NewString(network.GetExternalId()), "network_ext_id")
	}

	model, err := ElasticipManager.FetchById(input.ExternalIpId)
	if err != nil {
		return nil, err
	}
	if model == nil {
		return nil, httperrors.NewInputParameterError("No such eip")
	}
	eip := model.(*SElasticip)
	if eip.IpAddr != input.Ip {
		return nil, errors.Error("No such eip")
	}

	// check that eip is suitable
	if len(eip.AssociateId) != 0 {
		if eip.AssociateId != input.NatgatewayId {
			return nil, httperrors.NewInputParameterError("eip has been binding to another instance")
		} else if !man.canBindIP(eip.IpAddr) {
			return nil, httperrors.NewInputParameterError("eip has been binding to dnat rules")
		}
	} else {
		data.Add(jsonutils.NewBool(true), "need_bind")
	}

	data.Remove("external_ip_id")
	data.Set("name", jsonutils.NewString(NatGatewayManager.NatNameFromReal(input.Name, input.NatgatewayId)))
	data.Add(jsonutils.NewString(eip.Id), "eip_id")
	data.Add(jsonutils.NewString(eip.ExternalId), "eip_external_id")
	return data, nil
}

func (manager *SNatSEntryManager) SyncNatSTable(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, nat *SNatGateway, extTable []cloudprovider.ICloudNatSEntry) compare.SyncResult {
	syncOwnerId := provider.GetOwnerId()

	lockman.LockClass(ctx, manager, db.GetLockClassKey(manager, syncOwnerId))
	defer lockman.ReleaseClass(ctx, manager, db.GetLockClassKey(manager, syncOwnerId))

	result := compare.SyncResult{}
	dbNatSTables, err := nat.GetSTable()
	if err != nil {
		result.Error(err)
		return result
	}

	removed := make([]SNatSEntry, 0)
	commondb := make([]SNatSEntry, 0)
	commonext := make([]cloudprovider.ICloudNatSEntry, 0)
	added := make([]cloudprovider.ICloudNatSEntry, 0)
	if err := compare.CompareSets(dbNatSTables, extTable, &removed, &commondb, &commonext, &added); err != nil {
		result.Error(err)
		return result
	}

	for i := 0; i < len(removed); i += 1 {
		err := removed[i].syncRemoveCloudNatSTable(ctx, userCred)
		if err != nil {
			result.DeleteError(err)
		} else {
			result.Delete()
		}
	}

	for i := 0; i < len(commondb); i += 1 {
		err := commondb[i].SyncWithCloudNatSTable(ctx, userCred, commonext[i], syncOwnerId, provider.Id)
		if err != nil {
			result.UpdateError(err)
			continue
		}
		syncMetadata(ctx, userCred, &commondb[i], commonext[i])
		result.Update()
	}

	for i := 0; i < len(added); i += 1 {
		routeTableNew, err := manager.newFromCloudNatSTable(ctx, userCred, syncOwnerId, nat, added[i], provider.Id)
		if err != nil {
			result.AddError(err)
			continue
		}
		syncMetadata(ctx, userCred, routeTableNew, added[i])
		result.Add()
	}
	return result
}

func (self *SNatSEntry) syncRemoveCloudNatSTable(ctx context.Context, userCred mcclient.TokenCredential) error {
	lockman.LockObject(ctx, self)
	defer lockman.ReleaseObject(ctx, self)

	err := self.ValidateDeleteCondition(ctx)
	if err != nil { // cannot delete
		return self.SetStatus(userCred, api.VPC_STATUS_UNKNOWN, "sync to delete")
	}
	return self.RealDelete(ctx, userCred)
}

func (self *SNatSEntry) SyncWithCloudNatSTable(ctx context.Context, userCred mcclient.TokenCredential, extEntry cloudprovider.ICloudNatSEntry, syncOwnerId mcclient.IIdentityProvider, managerId string) error {
	diff, err := db.UpdateWithLock(ctx, self, func() error {
		self.Status = extEntry.GetStatus()
		self.IP = extEntry.GetIP()
		self.SourceCIDR = extEntry.GetSourceCIDR()
		if extNetworkId := extEntry.GetNetworkId(); len(extNetworkId) > 0 {
			network, err := db.FetchByExternalIdAndManagerId(NetworkManager, extNetworkId, func(q *sqlchemy.SQuery) *sqlchemy.SQuery {
				wire := WireManager.Query().SubQuery()
				vpc := VpcManager.Query().SubQuery()
				return q.Join(wire, sqlchemy.Equals(wire.Field("id"), q.Field("wire_id"))).
					Join(vpc, sqlchemy.Equals(vpc.Field("id"), wire.Field("vpc_id"))).
					Filter(sqlchemy.Equals(vpc.Field("manager_id"), managerId))
			})
			if err != nil {
				return err
			}
			self.NetworkId = network.GetId()
		}
		return nil
	})
	if err != nil {
		return err
	}

	SyncCloudDomain(userCred, self, syncOwnerId)

	db.OpsLog.LogSyncUpdate(self, diff, userCred)
	return nil
}

func (manager *SNatSEntryManager) newFromCloudNatSTable(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, nat *SNatGateway, extEntry cloudprovider.ICloudNatSEntry, managerId string) (*SNatSEntry, error) {
	table := SNatSEntry{}
	table.SetModelManager(manager, &table)

	table.Name = NatGatewayManager.NatNameFromReal(extEntry.GetName(), nat.Id)
	table.Status = extEntry.GetStatus()
	table.ExternalId = extEntry.GetGlobalId()
	table.IsEmulated = extEntry.IsEmulated()
	table.NatgatewayId = nat.Id

	table.IP = extEntry.GetIP()
	table.SourceCIDR = extEntry.GetSourceCIDR()
	if extNetworkId := extEntry.GetNetworkId(); len(extNetworkId) > 0 {
		network, err := db.FetchByExternalIdAndManagerId(NetworkManager, extNetworkId, func(q *sqlchemy.SQuery) *sqlchemy.SQuery {
			wire := WireManager.Query().SubQuery()
			vpc := VpcManager.Query().SubQuery()
			return q.Join(wire, sqlchemy.Equals(wire.Field("id"), q.Field("wire_id"))).
				Join(vpc, sqlchemy.Equals(vpc.Field("id"), wire.Field("vpc_id"))).
				Filter(sqlchemy.Equals(vpc.Field("manager_id"), managerId))
		})
		if err != nil {
			return nil, err
		}
		table.NetworkId = network.GetId()
	}

	err := manager.TableSpec().Insert(ctx, &table)
	if err != nil {
		log.Errorf("newFromCloudNatSTable fail %s", err)
		return nil, err
	}

	SyncCloudDomain(userCred, &table, ownerId)

	db.OpsLog.LogEvent(&table, db.ACT_CREATE, table.GetShortDesc(ctx), userCred)

	return &table, nil
}

func (manager *SNatSEntryManager) checkNetWorkId(networkId string) (*SNetwork, error) {
	// check that is these snat rule has neworkid
	q := manager.Query().Equals("network_id", networkId)
	count, err := q.CountWithError()
	if err != nil {
		return nil, errors.Wrap(err, "count snat with networkId failed")
	}
	if count > 0 {
		return nil, fmt.Errorf("a network has only one snat rule")
	}
	model, err := NetworkManager.FetchById(networkId)
	if err != nil {
		return nil, errors.Wrap(err, "fetch network error")
	}
	if model == nil {
		return nil, httperrors.NewInputParameterError("no such network")
	}
	return model.(*SNetwork), nil
}

func (self *SNatSEntry) GetExtraDetails(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, isList bool) (api.NatSEntryDetails, error) {
	return api.NatSEntryDetails{}, nil
}

func (manager *SNatSEntryManager) FetchCustomizeColumns(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	query jsonutils.JSONObject,
	objs []interface{},
	fields stringutils2.SSortedStrings,
	isList bool,
) []api.NatSEntryDetails {
	rows := make([]api.NatSEntryDetails, len(objs))

	netIds := make([]string, len(objs))
	entryRows := manager.SNatEntryManager.FetchCustomizeColumns(ctx, userCred, query, objs, fields, isList)
	for i := range rows {
		rows[i] = api.NatSEntryDetails{
			NatEntryDetails: entryRows[i],
		}
		netIds[i] = objs[i].(*SNatSEntry).NetworkId
	}

	nets := make(map[string]SNetwork)
	err := db.FetchStandaloneObjectsByIds(NetworkManager, netIds, &nets)
	if err != nil {
		return rows
	}

	for i := range rows {
		if net, ok := nets[netIds[i]]; ok {
			rows[i].Network = api.SimpleNetwork{
				Id:            net.Id,
				Name:          net.Name,
				GuestIpStart:  net.GuestIpStart,
				GuestIpEnd:    net.GuestIpEnd,
				GuestIp6Start: net.GuestIp6Start,
				GuestIp6End:   net.GuestIp6End,
			}
		}
	}

	return rows
}

func (self *SNatSEntry) PostCreate(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, data jsonutils.JSONObject) {
	if len(self.NatgatewayId) == 0 {
		return
	}
	// ValidateCreateData function make data must contain 'externalIpId' key
	taskData := data.(*jsonutils.JSONDict)
	task, err := taskman.TaskManager.NewTask(ctx, "SNatSEntryCreateTask", self, userCred, taskData, "", "", nil)
	if err != nil {
		log.Errorf("SNatSEntryCreateTask newTask error %s", err)
	} else {
		task.ScheduleRun(nil)
	}
}

func (self *SNatSEntry) CustomizeDelete(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, data jsonutils.JSONObject) error {
	if len(self.ExternalId) > 0 {
		return self.StartDeleteSNatTask(ctx, userCred)
	} else {
		return self.RealDelete(ctx, userCred)
	}
}

func (self *SNatSEntry) StartDeleteSNatTask(ctx context.Context, userCred mcclient.TokenCredential) error {
	task, err := taskman.TaskManager.NewTask(ctx, "SNatSEntryDeleteTask", self, userCred, nil, "", "", nil)
	if err != nil {
		log.Errorf("Start snatEntry deleteTask fail %s", err)
		return err
	}
	task.ScheduleRun(nil)
	return nil
}

func (self *SNatSEntryManager) canBindIP(ipAddr string) bool {
	q := NatDEntryManager.Query().Equals("external_ip", ipAddr)
	count, _ := q.CountWithError()
	if count != 0 {
		return false
	}
	return true
}

func (self *SNatSEntry) CountByEIP() (int, error) {
	q := NatSEntryManager.Query().Equals("ip", self.IP)
	return q.CountWithError()
}

func newIPv4RangeFromCIDR(cidr string) (netutils.IPV4AddrRange, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return netutils.IPV4AddrRange{}, errors.Wrapf(err, "invalid cidr: %s", cidr)
	}
	return netutils.NewIPV4AddrRangeFromIPNet(ipNet), nil
}
