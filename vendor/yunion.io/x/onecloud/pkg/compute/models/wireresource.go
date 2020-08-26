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
	"database/sql"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/util/reflectutils"
	"yunion.io/x/pkg/utils"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/util/stringutils2"
)

type SWireResourceBase struct {
	// 二层网络ID
	WireId string `width:"36" charset:"ascii" nullable:"true" list:"user" create:"optional" json:"wire_id"`
}

type SWireResourceBaseManager struct {
	SVpcResourceBaseManager
	SZoneResourceBaseManager
}

func ValidateWireResourceInput(userCred mcclient.TokenCredential, input api.WireResourceInput) (*SWire, api.WireResourceInput, error) {
	wireObj, err := WireManager.FetchByIdOrName(userCred, input.Wire)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, input, errors.Wrapf(httperrors.ErrResourceNotFound, "%s %s", WireManager.Keyword(), input.Wire)
		} else {
			return nil, input, errors.Wrap(err, "WireManager.FetchByIdOrName")
		}
	}
	input.Wire = wireObj.GetId()
	return wireObj.(*SWire), input, nil
}

func (self *SWireResourceBase) GetWire() *SWire {
	w, _ := WireManager.FetchById(self.WireId)
	if w != nil {
		return w.(*SWire)
	}
	return nil
}

func (self *SWireResourceBase) GetCloudproviderId() string {
	vpc := self.GetVpc()
	if vpc != nil {
		return vpc.ManagerId
	}
	return ""
}

func (self *SWireResourceBase) GetVpc() *SVpc {
	wire := self.GetWire()
	if wire != nil {
		return wire.GetVpc()
	}
	return nil
}

func (self *SWireResourceBase) GetRegion() *SCloudregion {
	vpc := self.GetVpc()
	if vpc == nil {
		return nil
	}
	region, _ := vpc.GetRegion()
	return region
}

func (self *SWireResourceBase) GetZone() *SZone {
	wire := self.GetWire()
	if wire != nil {
		return wire.GetZone()
	}
	return nil
}

func (self *SWireResourceBase) GetExtraDetails(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject) api.WireResourceInfo {
	return api.WireResourceInfo{}
}

func (manager *SWireResourceBaseManager) FetchCustomizeColumns(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	query jsonutils.JSONObject,
	objs []interface{},
	fields stringutils2.SSortedStrings,
	isList bool,
) []api.WireResourceInfo {
	rows := make([]api.WireResourceInfo, len(objs))

	wireIds := make([]string, len(objs))
	for i := range objs {
		var base *SWireResourceBase
		err := reflectutils.FindAnonymouStructPointer(objs[i], &base)
		if err != nil {
			log.Errorf("Cannot find SWireResourceBase in object %#v: %s", objs[i], err)
			continue
		}
		wireIds[i] = base.WireId
	}

	wires := make(map[string]SWire)
	err := db.FetchStandaloneObjectsByIds(WireManager, wireIds, &wires)
	if err != nil {
		log.Errorf("FetchStandaloneObjectsByIds fail %s", err)
		return nil
	}

	vpcList := make([]interface{}, len(rows))
	zoneList := make([]interface{}, len(rows))
	for i := range rows {
		rows[i] = api.WireResourceInfo{}
		if _, ok := wires[wireIds[i]]; ok {
			wire := wires[wireIds[i]]
			rows[i].Wire = wire.Name
			rows[i].VpcId = wire.VpcId
			rows[i].ZoneId = wire.ZoneId
		}
		vpcList[i] = &SVpcResourceBase{rows[i].VpcId}
		zoneList[i] = &SZoneResourceBase{rows[i].ZoneId}
	}

	vpcRows := manager.SVpcResourceBaseManager.FetchCustomizeColumns(ctx, userCred, query, vpcList, fields, isList)
	zoneRows := manager.SZoneResourceBaseManager.FetchCustomizeColumns(ctx, userCred, query, zoneList, fields, isList)

	for i := range rows {
		rows[i].VpcResourceInfo = vpcRows[i]
		rows[i].Zone = zoneRows[i].Zone
	}
	return rows
}

func (manager *SWireResourceBaseManager) ListItemFilter(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.WireFilterListInput,
) (*sqlchemy.SQuery, error) {
	var err error
	if len(query.Wire) > 0 {
		wireObj, _, err := ValidateWireResourceInput(userCred, query.WireResourceInput)
		if err != nil {
			return nil, errors.Wrap(err, "ValidateWireResourceInput")
		}
		q = q.Equals("wire_id", wireObj.GetId())
	}

	wireQ := WireManager.Query("id").Snapshot()

	wireQ, err = manager.SVpcResourceBaseManager.ListItemFilter(ctx, wireQ, userCred, query.VpcFilterListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SVpcResourceBaseManager.ListItemFilter")
	}

	if len(query.ZoneList()) > 0 {
		region := &SCloudregion{}
		firstZone := query.FirstZone()
		sq := ZoneManager.Query().SubQuery()
		q := CloudregionManager.Query()
		q = q.Join(sq, sqlchemy.Equals(sq.Field("cloudregion_id"), q.Field("id"))).Filter(sqlchemy.OR(
			sqlchemy.Equals(sq.Field("id"), firstZone),
			sqlchemy.Equals(sq.Field("name"), firstZone),
		))
		count, err := q.CountWithError()
		if err != nil {
			return nil, errors.Wrap(err, "CountWithError")
		}
		if count < 1 {
			return nil, httperrors.NewResourceNotFoundError2("zone", firstZone)
		}
		err = q.First(region)
		if err != nil {
			return nil, errors.Wrap(err, "q.First")
		}
		if utils.IsInStringArray(region.Provider, api.REGIONAL_NETWORK_PROVIDERS) {
			vpcQ := VpcManager.Query().SubQuery()
			q = q.Join(vpcQ, sqlchemy.Equals(vpcQ.Field("id"), q.Field("vpc_id"))).
				Filter(sqlchemy.Equals(vpcQ.Field("cloudregion_id"), region.Id))
		} else {
			zoneQuery := api.ZonalFilterListInput{
				ZonalFilterListBase: query.ZonalFilterListBase,
			}
			wireQ, err = manager.SZoneResourceBaseManager.ListItemFilter(ctx, wireQ, userCred, zoneQuery)
			if err != nil {
				return nil, errors.Wrap(err, "SZoneResourceBaseManager.ListItemFilter")
			}
		}
	}

	if wireQ.IsAltered() {
		q = q.Filter(sqlchemy.In(q.Field("wire_id"), wireQ.SubQuery()))
	}
	return q, nil
}

func (manager *SWireResourceBaseManager) QueryDistinctExtraField(q *sqlchemy.SQuery, field string) (*sqlchemy.SQuery, error) {
	if field == "wire" {
		wireQuery := WireManager.Query("name", "id").Distinct().SubQuery()
		q.AppendField(wireQuery.Field("name", field))
		q = q.Join(wireQuery, sqlchemy.Equals(q.Field("wire_id"), wireQuery.Field("id")))
		q.GroupBy(wireQuery.Field("name"))
		return q, nil
	} else {
		wires := WireManager.Query("id", "zone_id", "vpc_id").SubQuery()
		q = q.LeftJoin(wires, sqlchemy.Equals(q.Field("wire_id"), wires.Field("id")))
		if field == "zone" {
			return manager.SZoneResourceBaseManager.QueryDistinctExtraField(q, field)
		} else {
			q, err := manager.SVpcResourceBaseManager.QueryDistinctExtraField(q, field)
			if err == nil {
				return q, nil
			} else {
				return q, httperrors.ErrNotFound
			}
		}
	}
}

func (manager *SWireResourceBaseManager) OrderByExtraFields(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.WireFilterListInput,
) (*sqlchemy.SQuery, error) {
	q, orders, fields := manager.GetOrderBySubQuery(q, userCred, query)
	if len(orders) > 0 {
		q = db.OrderByFields(q, orders, fields)
	}
	return q, nil
}

func (manager *SWireResourceBaseManager) GetOrderBySubQuery(
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.WireFilterListInput,
) (*sqlchemy.SQuery, []string, []sqlchemy.IQueryField) {
	wireQ := WireManager.Query("id", "name")
	var orders []string
	var fields []sqlchemy.IQueryField
	zoneQuery := api.ZonalFilterListInput{
		ZonalFilterListBase: query.ZonalFilterListBase,
	}
	if db.NeedOrderQuery(manager.SZoneResourceBaseManager.GetOrderByFields(zoneQuery)) {
		var zoneOrders []string
		var zoneFields []sqlchemy.IQueryField
		wireQ, zoneOrders, zoneFields = manager.SZoneResourceBaseManager.GetOrderBySubQuery(wireQ, userCred, zoneQuery)
		if len(zoneOrders) > 0 {
			orders = append(orders, zoneOrders...)
			fields = append(fields, zoneFields...)
		}
	}

	if db.NeedOrderQuery(manager.SVpcResourceBaseManager.GetOrderByFields(query.VpcFilterListInput)) {
		var vpcOrders []string
		var vpcFields []sqlchemy.IQueryField
		wireQ, vpcOrders, vpcFields = manager.SVpcResourceBaseManager.GetOrderBySubQuery(wireQ, userCred, query.VpcFilterListInput)
		if len(vpcOrders) > 0 {
			orders = append(orders, vpcOrders...)
			fields = append(fields, vpcFields...)
		}
	}

	if db.NeedOrderQuery(manager.GetOrderByFields(query)) {
		subq := wireQ.SubQuery()
		q = q.LeftJoin(subq, sqlchemy.Equals(q.Field("wire_id"), subq.Field("id")))
		if db.NeedOrderQuery([]string{query.OrderByWire}) {
			orders = append(orders, query.OrderByWire)
			fields = append(fields, subq.Field("name"))
		}
	}

	return q, orders, fields
}

func (manager *SWireResourceBaseManager) GetOrderByFields(query api.WireFilterListInput) []string {
	fields := make([]string, 0)
	zoneQuery := api.ZonalFilterListInput{
		ZonalFilterListBase: query.ZonalFilterListBase,
	}
	zoneFields := manager.SZoneResourceBaseManager.GetOrderByFields(zoneQuery)
	fields = append(fields, zoneFields...)
	vpcFields := manager.SVpcResourceBaseManager.GetOrderByFields(query.VpcFilterListInput)
	fields = append(fields, vpcFields...)
	fields = append(fields, query.OrderByWire)
	return fields
}

func (manager *SWireResourceBaseManager) ListItemExportKeys(ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	keys stringutils2.SSortedStrings,
) (*sqlchemy.SQuery, error) {
	if keys.ContainsAny(manager.GetExportKeys()...) {
		var err error
		subq := WireManager.Query("id", "name", "vpc_id", "zone_id").SubQuery()
		q = q.LeftJoin(subq, sqlchemy.Equals(q.Field("wire_id"), subq.Field("id")))
		if keys.Contains("wire") {
			q = q.AppendField(subq.Field("name", "wire"))
		}
		if keys.Contains("zone") {
			q, err = manager.SZoneResourceBaseManager.ListItemExportKeys(ctx, q, userCred, stringutils2.NewSortedStrings([]string{"zone"}))
			if err != nil {
				return nil, errors.Wrap(err, "SZoneResourceBaseManager.ListItemExportKeys")
			}
		}
		if keys.ContainsAny(manager.SVpcResourceBaseManager.GetExportKeys()...) {
			q, err = manager.SVpcResourceBaseManager.ListItemExportKeys(ctx, q, userCred, keys)
			if err != nil {
				return nil, errors.Wrap(err, "SVpcResourceBaseManager.ListItemExportKeys")
			}
		}
	}
	return q, nil
}

func (manager *SWireResourceBaseManager) GetExportKeys() []string {
	keys := []string{"wire"}
	keys = append(keys, "zone")
	keys = append(keys, manager.SVpcResourceBaseManager.GetExportKeys()...)
	return keys
}

func (self *SWireResourceBase) GetChangeOwnerCandidateDomainIds() []string {
	wire := self.GetWire()
	if wire != nil {
		return wire.GetChangeOwnerCandidateDomainIds()
	}
	return nil
}
