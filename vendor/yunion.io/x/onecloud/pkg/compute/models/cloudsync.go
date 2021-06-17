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
	"time"

	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/util/compare"
	"yunion.io/x/pkg/utils"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/cloudcommon/db/lockman"
	"yunion.io/x/onecloud/pkg/cloudprovider"
	"yunion.io/x/onecloud/pkg/compute/options"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/mcclient/auth"
	"yunion.io/x/onecloud/pkg/mcclient/modules"
)

type SSyncableBaseResource struct {
	SyncStatus    string    `width:"10" charset:"ascii" default:"idle" list:"domain"`
	LastSync      time.Time `list:"domain"` // = Column(DateTime, nullable=True)
	LastSyncEndAt time.Time `list:"domain"`
}

type SSyncableBaseResourceManager struct{}

func (self *SSyncableBaseResource) CanSync() bool {
	if self.SyncStatus == api.CLOUD_PROVIDER_SYNC_STATUS_QUEUED || self.SyncStatus == api.CLOUD_PROVIDER_SYNC_STATUS_SYNCING {
		if self.LastSync.IsZero() || time.Now().Sub(self.LastSync) > time.Duration(options.Options.MinimalSyncIntervalSeconds)*time.Second {
			return true
		} else {
			return false
		}
	} else {
		return true
	}
}

func (manager *SSyncableBaseResourceManager) ListItemFilter(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.SyncableBaseResourceListInput,
) (*sqlchemy.SQuery, error) {
	if len(query.SyncStatus) > 0 {
		q = q.In("sync_status", query.SyncStatus)
	}
	return q, nil
}

type sStoragecacheSyncPair struct {
	local  *SStoragecache
	region *SCloudregion
	remote cloudprovider.ICloudStoragecache
	isNew  bool
}

func (pair *sStoragecacheSyncPair) syncCloudImages(ctx context.Context, userCred mcclient.TokenCredential) compare.SyncResult {
	return pair.local.SyncCloudImages(ctx, userCred, pair.remote, pair.region)
}

func isInCache(pairs []sStoragecacheSyncPair, localCacheId string) bool {
	// log.Debugf("isInCache %d %s", len(pairs), localCacheId)
	for i := range pairs {
		if pairs[i].local.Id == localCacheId {
			return true
		}
	}
	return false
}

func syncRegionQuotas(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, driver cloudprovider.ICloudProvider, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion) error {
	quotas, err := remoteRegion.GetICloudQuotas()
	if err != nil {
		msg := fmt.Sprintf("GetICloudQuotas for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return err
	}
	result := CloudproviderQuotaManager.SyncQuotas(ctx, userCred, provider.GetOwnerId(), provider, localRegion, api.CLOUD_PROVIDER_QUOTA_RANGE_CLOUDREGION, quotas)
	syncResults.Add(CloudproviderQuotaManager, result)
	msg := result.Result()
	notes := fmt.Sprintf("SyncQuotas for region %s result: %s", localRegion.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return fmt.Errorf(msg)
	}
	return nil
}

func syncRegionZones(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion) ([]SZone, []cloudprovider.ICloudZone, error) {
	zones, err := remoteRegion.GetIZones()
	if err != nil {
		msg := fmt.Sprintf("GetZones for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return nil, nil, err
	}
	localZones, remoteZones, result := ZoneManager.SyncZones(ctx, userCred, localRegion, zones)
	syncResults.Add(ZoneManager, result)
	msg := result.Result()
	notes := fmt.Sprintf("SyncZones for region %s result: %s", localRegion.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return nil, nil, fmt.Errorf(msg)
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
	return localZones, remoteZones, nil
}

func syncRegionSkus(ctx context.Context, userCred mcclient.TokenCredential, localRegion *SCloudregion) {
	if localRegion == nil {
		log.Debugf("local region is nil, skipp...")
		return
	}

	regionId := localRegion.GetId()
	if len(regionId) == 0 {
		log.Debugf("local region Id is empty, skip...")
		return
	}

	cnt, err := ServerSkuManager.GetSkuCountByRegion(regionId)
	if err != nil {
		log.Errorf("GetSkuCountByRegion fail %s", err)
		return
	}

	if cnt == 0 {
		// 提前同步instance type.如果同步失败可能导致vm 内存显示为0
		if ret := SyncServerSkusByRegion(ctx, userCred, localRegion, nil); ret.IsError() {
			msg := fmt.Sprintf("Get Skus for region %s failed %s", localRegion.GetName(), ret.Result())
			log.Errorln(msg)
			// 暂时不终止同步
			// logSyncFailed(provider, task, msg)
			return
		}
	}

	if localRegion.GetDriver().IsSupportedElasticcache() {
		cnt, err = ElasticcacheSkuManager.GetSkuCountByRegion(regionId)
		if err != nil {
			log.Errorf("ElasticcacheSkuManager.GetSkuCountByRegion fail %s", err)
			return
		}

		if cnt == 0 {
			SyncElasticCacheSkusByRegion(ctx, userCred, localRegion)
		}
	}
}

func syncRegionEips(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	eips, err := remoteRegion.GetIEips()
	if err != nil {
		msg := fmt.Sprintf("GetIEips for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return
	}

	result := ElasticipManager.SyncEips(ctx, userCred, provider, localRegion, eips, provider.GetOwnerId())

	syncResults.Add(ElasticipManager, result)

	msg := result.Result()
	log.Infof("SyncEips for region %s result: %s", localRegion.Name, msg)
	if result.IsError() {
		return
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
}

func syncRegionBuckets(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion) {
	buckets, err := remoteRegion.GetIBuckets()
	if err != nil {
		msg := fmt.Sprintf("GetIBuckets for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return
	}

	result := BucketManager.syncBuckets(ctx, userCred, provider, localRegion, buckets)

	syncResults.Add(BucketManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("GetIBuckets for region %s result: %s", localRegion.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
}

func syncRegionVPCs(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	vpcs, err := remoteRegion.GetIVpcs()
	if err != nil {
		msg := fmt.Sprintf("GetVpcs for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return
	}

	localVpcs, remoteVpcs, result := VpcManager.SyncVPCs(ctx, userCred, provider, localRegion, vpcs)

	syncResults.Add(VpcManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncVPCs for region %s result: %s", localRegion.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
	for j := 0; j < len(localVpcs); j += 1 {
		func() {
			// lock vpc
			lockman.LockObject(ctx, &localVpcs[j])
			defer lockman.ReleaseObject(ctx, &localVpcs[j])

			if localVpcs[j].Deleted {
				return
			}

			syncVpcWires(ctx, userCred, syncResults, provider, &localVpcs[j], remoteVpcs[j], syncRange)
			if localRegion.GetDriver().IsSecurityGroupBelongVpc() || localRegion.GetDriver().IsSupportClassicSecurityGroup() || j == 0 { //有vpc属性的每次都同步,支持classic的vpc也同步，否则仅同步一次
				syncVpcSecGroup(ctx, userCred, syncResults, provider, &localVpcs[j], remoteVpcs[j], syncRange)
			}
			syncVpcNatgateways(ctx, userCred, syncResults, provider, &localVpcs[j], remoteVpcs[j], syncRange)
			syncVpcPeerConnections(ctx, userCred, syncResults, provider, &localVpcs[j], remoteVpcs[j], syncRange)
			syncVpcRouteTables(ctx, userCred, syncResults, provider, &localVpcs[j], remoteVpcs[j], syncRange)
		}()
	}
}

func syncRegionAccessGroups(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	accessGroups, err := remoteRegion.GetICloudAccessGroups()
	if err != nil {
		if errors.Cause(err) == cloudprovider.ErrNotImplemented || errors.Cause(err) == cloudprovider.ErrNotSupported {
			return
		}
		log.Errorf("GetICloudFileSystems for region %s error: %v", localRegion.Name, err)
		return
	}

	result := localRegion.SyncAccessGroups(ctx, userCred, provider, accessGroups)
	syncResults.Add(AccessGroupCacheManager, result)
	log.Infof("Sync Access Group Caches for region %s result: %s", localRegion.Name, result.Result())
}

func syncRegionFileSystems(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	filesystems, err := remoteRegion.GetICloudFileSystems()
	if err != nil {
		if errors.Cause(err) == cloudprovider.ErrNotImplemented || errors.Cause(err) == cloudprovider.ErrNotSupported {
			return
		}
		log.Errorf("GetICloudFileSystems for region %s error: %v", localRegion.Name, err)
		return
	}

	localFSs, removeFSs, result := localRegion.SyncFileSystems(ctx, userCred, provider, filesystems)
	syncResults.Add(FileSystemManager, result)
	log.Infof("Sync FileSystem for region %s result: %s", localRegion.Name, result.Result())

	for j := 0; j < len(localFSs); j += 1 {
		func() {
			// lock file system
			lockman.LockObject(ctx, &localFSs[j])
			defer lockman.ReleaseObject(ctx, &localFSs[j])

			if localFSs[j].Deleted {
				return
			}

			syncFileSystemMountTargets(ctx, userCred, &localFSs[j], removeFSs[j])
		}()
	}
}

func syncFileSystemMountTargets(ctx context.Context, userCred mcclient.TokenCredential, localFs *SFileSystem, remoteFs cloudprovider.ICloudFileSystem) {
	mountTargets, err := remoteFs.GetMountTargets()
	if err != nil {
		if errors.Cause(err) == cloudprovider.ErrNotImplemented || errors.Cause(err) == cloudprovider.ErrNotSupported {
			return
		}
		log.Errorf("GetMountTargets for %s error: %v", localFs.Name, err)
		return
	}
	result := localFs.SyncMountTargets(ctx, userCred, mountTargets)
	log.Infof("SyncMountTargets for FileSystem %s result: %s", localFs.Name, result.Result())
}

func syncVpcPeerConnections(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localVpc *SVpc, remoteVpc cloudprovider.ICloudVpc, syncRange *SSyncRange) {
	peerConnections, err := remoteVpc.GetICloudVpcPeeringConnections()
	if err != nil {
		if errors.Cause(err) == cloudprovider.ErrNotImplemented || errors.Cause(err) == cloudprovider.ErrNotSupported {
			return
		}
		log.Errorf("GetICloudVpcPeeringConnections for vpc %s failed %v", localVpc.Name, err)
		return
	}

	result := localVpc.SyncVpcPeeringConnections(ctx, userCred, peerConnections)
	syncResults.Add(VpcPeeringConnectionManager, result)

	accepterPeerings, err := remoteVpc.GetICloudAccepterVpcPeeringConnections()
	if err != nil {
		if errors.Cause(err) == cloudprovider.ErrNotImplemented || errors.Cause(err) == cloudprovider.ErrNotSupported {
			return
		}
		log.Errorf("GetICloudVpcPeeringConnections for vpc %s failed %v", localVpc.Name, err)
		return
	}
	backSyncResult := localVpc.BackSycVpcPeeringConnectionsVpc(accepterPeerings)
	syncResults.Add(VpcPeeringConnectionManager, backSyncResult)

	log.Infof("SyncVpcPeeringConnections for vpc %s result: %s", localVpc.Name, result.Result())
	if result.IsError() {
		return
	}
}

func syncVpcSecGroup(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localVpc *SVpc, remoteVpc cloudprovider.ICloudVpc, syncRange *SSyncRange) {
	secgroups, err := remoteVpc.GetISecurityGroups()
	if err != nil {
		msg := fmt.Sprintf("GetISecurityGroups for vpc %s failed %s", remoteVpc.GetId(), err)
		log.Errorf(msg)
		return
	}

	_, _, result := SecurityGroupCacheManager.SyncSecurityGroupCaches(ctx, userCred, provider, secgroups, localVpc)
	syncResults.Add(SecurityGroupCacheManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncSecurityGroupCaches for VPC %s result: %s", localVpc.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
}

func syncVpcRouteTables(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localVpc *SVpc, remoteVpc cloudprovider.ICloudVpc, syncRange *SSyncRange) {
	routeTables, err := remoteVpc.GetIRouteTables()
	if err != nil {
		msg := fmt.Sprintf("GetIRouteTables for vpc %s failed %s", remoteVpc.GetId(), err)
		log.Errorf(msg)
		return
	}
	localRouteTables, remoteRouteTables, result := RouteTableManager.SyncRouteTables(ctx, userCred, localVpc, routeTables, provider)

	syncResults.Add(RouteTableManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncRouteTables for VPC %s result: %s", localVpc.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	for i := 0; i < len(localRouteTables); i++ {
		func() {
			lockman.LockObject(ctx, &localRouteTables[i])
			defer lockman.ReleaseObject(ctx, &localRouteTables[i])

			if localRouteTables[i].Deleted {
				return
			}
			localRouteTables[i].SyncRouteTableRouteSets(ctx, userCred, remoteRouteTables[i], provider)
			localRouteTables[i].SyncRouteTableAssociations(ctx, userCred, remoteRouteTables[i], provider)
		}()
	}
}

func syncVpcNatgateways(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localVpc *SVpc, remoteVpc cloudprovider.ICloudVpc, syncRange *SSyncRange) {
	natGateways, err := remoteVpc.GetINatGateways()
	if err != nil {
		msg := fmt.Sprintf("GetINatGateways for vpc %s failed %s", remoteVpc.GetId(), err)
		log.Errorf(msg)
		return
	}
	localNatGateways, remoteNatGateways, result := NatGatewayManager.SyncNatGateways(ctx, userCred, provider.GetOwnerId(), provider, localVpc, natGateways)

	syncResults.Add(NatGatewayManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncNatGateways for VPC %s result: %s", localVpc.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}

	for i := 0; i < len(localNatGateways); i++ {
		func() {
			lockman.LockObject(ctx, &localNatGateways[i])
			defer lockman.ReleaseObject(ctx, &localNatGateways[i])

			if localNatGateways[i].Deleted {
				return
			}

			syncNatGatewayEips(ctx, userCred, provider, &localNatGateways[i], remoteNatGateways[i])
			syncNatDTable(ctx, userCred, provider, &localNatGateways[i], remoteNatGateways[i])
			syncNatSTable(ctx, userCred, provider, &localNatGateways[i], remoteNatGateways[i])
		}()
	}
}

func syncNatGatewayEips(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localNatGateway *SNatGateway, remoteNatGateway cloudprovider.ICloudNatGateway) {
	eips, err := remoteNatGateway.GetIEips()
	if err != nil {
		msg := fmt.Sprintf("GetIEIPs for NatGateway %s failed %s", remoteNatGateway.GetName(), err)
		log.Errorf(msg)
		return
	}
	result := localNatGateway.SyncNatGatewayEips(ctx, userCred, provider, eips)
	msg := result.Result()
	log.Infof("SyncNatGatewayEips for NatGateway %s result: %s", localNatGateway.Name, msg)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
}

func syncNatDTable(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localNatGateway *SNatGateway, remoteNatGateway cloudprovider.ICloudNatGateway) {
	dtable, err := remoteNatGateway.GetINatDTable()
	if err != nil {
		msg := fmt.Sprintf("GetINatDTable for NatGateway %s failed %s", remoteNatGateway.GetName(), err)
		log.Errorf(msg)
		return
	}
	result := NatDEntryManager.SyncNatDTable(ctx, userCred, provider, localNatGateway, dtable)
	msg := result.Result()
	log.Infof("SyncNatDTable for NatGateway %s result: %s", localNatGateway.Name, msg)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
}

func syncNatSTable(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localNatGateway *SNatGateway, remoteNatGateway cloudprovider.ICloudNatGateway) {
	stable, err := remoteNatGateway.GetINatSTable()
	if err != nil {
		msg := fmt.Sprintf("GetINatSTable for NatGateway %s failed %s", remoteNatGateway.GetName(), err)
		log.Errorf(msg)
		return
	}
	result := NatSEntryManager.SyncNatSTable(ctx, userCred, provider, localNatGateway, stable)
	msg := result.Result()
	log.Infof("SyncNatSTable for NatGateway %s result: %s", localNatGateway.Name, msg)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
}

func syncVpcWires(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localVpc *SVpc, remoteVpc cloudprovider.ICloudVpc, syncRange *SSyncRange) {
	wires, err := remoteVpc.GetIWires()
	if err != nil {
		msg := fmt.Sprintf("GetIWires for vpc %s failed %s", remoteVpc.GetId(), err)
		log.Errorf(msg)
		return
	}
	localWires, remoteWires, result := WireManager.SyncWires(ctx, userCred, localVpc, wires, provider)

	if syncResults != nil {
		syncResults.Add(WireManager, result)
	}

	msg := result.Result()
	notes := fmt.Sprintf("SyncWires for VPC %s result: %s", localVpc.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.GetParams()), notes, task.GetUserCred(), true)
	for i := 0; i < len(localWires); i += 1 {
		func() {
			lockman.LockObject(ctx, &localWires[i])
			defer lockman.ReleaseObject(ctx, &localWires[i])

			if localWires[i].Deleted {
				return
			}
			syncWireNetworks(ctx, userCred, syncResults, provider, &localWires[i], remoteWires[i], syncRange)
		}()
	}
}

func syncWireNetworks(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localWire *SWire, remoteWire cloudprovider.ICloudWire, syncRange *SSyncRange) {
	nets, err := remoteWire.GetINetworks()
	if err != nil {
		msg := fmt.Sprintf("GetINetworks for wire %s failed %s", remoteWire.GetId(), err)
		log.Errorf(msg)
		return
	}
	_, _, result := NetworkManager.SyncNetworks(ctx, userCred, localWire, nets, provider)

	if syncResults != nil {
		syncResults.Add(NetworkManager, result)
	}

	msg := result.Result()
	notes := fmt.Sprintf("SyncNetworks for wire %s result: %s", localWire.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.GetParams()), notes, task.GetUserCred(), true)
}

func syncZoneStorages(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, driver cloudprovider.ICloudProvider, localZone *SZone, remoteZone cloudprovider.ICloudZone, syncRange *SSyncRange, storageCachePairs []sStoragecacheSyncPair) []sStoragecacheSyncPair {
	storages, err := remoteZone.GetIStorages()
	if err != nil {
		msg := fmt.Sprintf("GetIStorages for zone %s failed %s", remoteZone.GetName(), err)
		log.Errorf(msg)
		return nil
	}
	localStorages, remoteStorages, result := StorageManager.SyncStorages(ctx, userCred, provider, localZone, storages)

	syncResults.Add(StorageManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncStorages for zone %s result: %s", localZone.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return nil
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.GetParams()), notes, task.GetUserCred(), true)

	newCacheIds := make([]sStoragecacheSyncPair, 0)
	for i := 0; i < len(localStorages); i += 1 {
		func() {
			lockman.LockObject(ctx, &localStorages[i])
			defer lockman.ReleaseObject(ctx, &localStorages[i])

			if localStorages[i].Deleted {
				return
			}

			if !isInCache(storageCachePairs, localStorages[i].StoragecacheId) && !isInCache(newCacheIds, localStorages[i].StoragecacheId) {
				cachePair := syncStorageCaches(ctx, userCred, provider, &localStorages[i], remoteStorages[i])
				if cachePair.remote != nil && cachePair.local != nil {
					newCacheIds = append(newCacheIds, cachePair)
				}
			}
			if !remoteStorages[i].DisableSync() {
				syncStorageDisks(ctx, userCred, syncResults, provider, driver, &localStorages[i], remoteStorages[i], syncRange)
			}
		}()
	}
	return newCacheIds
}

func syncStorageCaches(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localStorage *SStorage, remoteStorage cloudprovider.ICloudStorage) (cachePair sStoragecacheSyncPair) {
	log.Debugf("syncStorageCaches for storage %s", localStorage.GetId())
	remoteCache := remoteStorage.GetIStoragecache()
	if remoteCache == nil {
		log.Errorf("remote storageCache is nil")
		return
	}
	localCache, isNew, err := StoragecacheManager.SyncWithCloudStoragecache(ctx, userCred, remoteCache, provider)
	if err != nil {
		msg := fmt.Sprintf("SyncWithCloudStoragecache for storage %s failed %s", remoteStorage.GetName(), err)
		log.Errorf(msg)
		return
	}
	err = localStorage.SetStoragecache(userCred, localCache)
	if err != nil {
		msg := fmt.Sprintf("localStorage %s set cache failed: %s", localStorage.GetName(), err)
		log.Errorf(msg)
	}
	cachePair.local = localCache
	cachePair.remote = remoteCache
	cachePair.isNew = isNew
	cachePair.region = localStorage.GetRegion()
	return
}

func syncStorageDisks(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, driver cloudprovider.ICloudProvider, localStorage *SStorage, remoteStorage cloudprovider.ICloudStorage, syncRange *SSyncRange) {
	disks, err := remoteStorage.GetIDisks()
	if err != nil {
		msg := fmt.Sprintf("GetIDisks for storage %s failed %s", remoteStorage.GetName(), err)
		log.Errorf(msg)
		return
	}
	_, _, result := DiskManager.SyncDisks(ctx, userCred, driver, localStorage, disks, provider.GetOwnerId())

	syncResults.Add(DiskManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncDisks for storage %s result: %s", localStorage.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
}

func syncZoneHosts(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, driver cloudprovider.ICloudProvider, localZone *SZone, remoteZone cloudprovider.ICloudZone, syncRange *SSyncRange, storageCachePairs []sStoragecacheSyncPair) []sStoragecacheSyncPair {
	hosts, err := remoteZone.GetIHosts()
	if err != nil {
		msg := fmt.Sprintf("GetIHosts for zone %s failed %s", remoteZone.GetName(), err)
		log.Errorf(msg)
		return nil
	}
	localHosts, remoteHosts, result := HostManager.SyncHosts(ctx, userCred, provider, localZone, hosts)

	syncResults.Add(HostManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncHosts for zone %s result: %s", localZone.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return nil
	}
	var newCachePairs []sStoragecacheSyncPair
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
	for i := 0; i < len(localHosts); i += 1 {
		if len(syncRange.Host) > 0 && !utils.IsInStringArray(localHosts[i].Id, syncRange.Host) {
			continue
		}
		func() {
			lockman.LockObject(ctx, &localHosts[i])
			defer lockman.ReleaseObject(ctx, &localHosts[i])

			if localHosts[i].Deleted {
				return
			}

			syncMetadata(ctx, userCred, &localHosts[i], remoteHosts[i])
			newCachePairs = syncHostStorages(ctx, userCred, syncResults, provider, &localHosts[i], remoteHosts[i], storageCachePairs)
			syncHostWires(ctx, userCred, syncResults, provider, &localHosts[i], remoteHosts[i])
			syncHostVMs(ctx, userCred, syncResults, provider, driver, &localHosts[i], remoteHosts[i], syncRange)
		}()
	}
	return newCachePairs
}

func syncHostStorages(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localHost *SHost, remoteHost cloudprovider.ICloudHost, storageCachePairs []sStoragecacheSyncPair) []sStoragecacheSyncPair {
	storages, err := remoteHost.GetIStorages()
	if err != nil {
		msg := fmt.Sprintf("GetIStorages for host %s failed %s", remoteHost.GetName(), err)
		log.Errorf(msg)
		return nil
	}
	localStorages, remoteStorages, result := localHost.SyncHostStorages(ctx, userCred, storages, provider)

	syncResults.Add(StorageManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncHostStorages for host %s result: %s", localHost.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return nil
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)

	newCacheIds := make([]sStoragecacheSyncPair, 0)
	for i := 0; i < len(localStorages); i += 1 {
		syncMetadata(ctx, userCred, &localStorages[i], remoteStorages[i])
		if !isInCache(storageCachePairs, localStorages[i].StoragecacheId) && !isInCache(newCacheIds, localStorages[i].StoragecacheId) {
			cachePair := syncStorageCaches(ctx, userCred, provider, &localStorages[i], remoteStorages[i])
			if cachePair.remote != nil && cachePair.local != nil {
				newCacheIds = append(newCacheIds, cachePair)
			}
		}
	}
	return newCacheIds
}

func syncHostWires(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localHost *SHost, remoteHost cloudprovider.ICloudHost) {
	wires, err := remoteHost.GetIWires()
	if err != nil {
		msg := fmt.Sprintf("GetIWires for host %s failed %s", remoteHost.GetName(), err)
		log.Errorf(msg)
		return
	}
	result := localHost.SyncHostWires(ctx, userCred, wires)

	if syncResults != nil {
		syncResults.Add(WireManager, result)
	}

	msg := result.Result()
	notes := fmt.Sprintf("SyncHostWires for host %s result: %s", localHost.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.GetParams()), notes, task.GetUserCred(), true)
}

func syncHostVMs(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, driver cloudprovider.ICloudProvider, localHost *SHost, remoteHost cloudprovider.ICloudHost, syncRange *SSyncRange) {
	vms, err := remoteHost.GetIVMs()
	if err != nil {
		msg := fmt.Sprintf("GetIVMs for host %s failed %s", remoteHost.GetName(), err)
		log.Errorf(msg)
		return
	}
	syncVMPairs, result := localHost.SyncHostVMs(ctx, userCred, driver, vms, provider.GetOwnerId())

	syncResults.Add(GuestManager, result)

	msg := result.Result()
	notes := fmt.Sprintf("SyncHostVMs for host %s result: %s", localHost.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}

	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
	for i := 0; i < len(syncVMPairs); i += 1 {
		if !syncVMPairs[i].IsNew && !syncRange.DeepSync {
			continue
		}
		func() {
			lockman.LockObject(ctx, syncVMPairs[i].Local)
			defer lockman.ReleaseObject(ctx, syncVMPairs[i].Local)

			if syncVMPairs[i].Local.Deleted || syncVMPairs[i].Local.PendingDeleted {
				return
			}

			syncVMPeripherals(ctx, userCred, syncVMPairs[i].Local, syncVMPairs[i].Remote, localHost, provider, driver)
			// syncMetadata(ctx, userCred, syncVMPairs[i].Local, syncVMPairs[i].Remote)
			// syncVMNics(ctx, userCred, provider, localHost, syncVMPairs[i].Local, syncVMPairs[i].Remote)
			// syncVMDisks(ctx, userCred, provider, driver, localHost, syncVMPairs[i].Local, syncVMPairs[i].Remote, syncRange)
			// syncVMEip(ctx, userCred, provider, syncVMPairs[i].Local, syncVMPairs[i].Remote)
			// syncVMSecgroups(ctx, userCred, provider, syncVMPairs[i].Local, syncVMPairs[i].Remote)

		}()
	}
}

func syncVMPeripherals(ctx context.Context, userCred mcclient.TokenCredential, local *SGuest, remote cloudprovider.ICloudVM, host *SHost, provider *SCloudprovider, driver cloudprovider.ICloudProvider) {
	err := syncVMNics(ctx, userCred, provider, host, local, remote)
	if err != nil {
		log.Errorf("syncVMNics error %s", err)
	}
	err = syncVMDisks(ctx, userCred, provider, driver, host, local, remote)
	if err != nil {
		log.Errorf("syncVMDisks error %s", err)
	}
	err = syncVMEip(ctx, userCred, provider, local, remote)
	if err != nil {
		log.Errorf("syncVMEip error %s", err)
	}
	err = syncVMSecgroups(ctx, userCred, provider, local, remote)
	if err != nil {
		log.Errorf("syncVMSecgroups error %s", err)
	}
	result := local.SyncInstanceSnapshots(ctx, userCred, provider)
	if result.IsError() {
		log.Errorf("syncVMInstanceSnapshots error %v", result.AllError())
	}
}

func syncVMNics(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, host *SHost, localVM *SGuest, remoteVM cloudprovider.ICloudVM) error {
	nics, err := remoteVM.GetINics()
	if err != nil {
		// msg := fmt.Sprintf("GetINics for VM %s failed %s", remoteVM.GetName(), err)
		// log.Errorf(msg)
		return errors.Wrap(err, "remoteVM.GetINics")
	}
	result := localVM.SyncVMNics(ctx, userCred, host, nics, nil)
	msg := result.Result()
	notes := fmt.Sprintf("syncVMNics for VM %s result: %s", localVM.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return result.AllError()
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
	return nil
}

func syncVMDisks(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, driver cloudprovider.ICloudProvider, host *SHost, localVM *SGuest, remoteVM cloudprovider.ICloudVM) error {
	disks, err := remoteVM.GetIDisks()
	if err != nil {
		// msg := fmt.Sprintf("GetIDisks for VM %s failed %s", remoteVM.GetName(), err)
		// log.Errorf(msg)
		return errors.Wrap(err, "remoteVM.GetIDisks")
	}
	result := localVM.SyncVMDisks(ctx, userCred, driver, host, disks, provider.GetOwnerId())
	msg := result.Result()
	notes := fmt.Sprintf("syncVMDisks for VM %s result: %s", localVM.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return result.AllError()
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.Params), notes, task.UserCred, true)
	return nil
}

func syncVMEip(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localVM *SGuest, remoteVM cloudprovider.ICloudVM) error {
	eip, err := remoteVM.GetIEIP()
	if err != nil {
		// msg := fmt.Sprintf("GetIEIP for VM %s failed %s", remoteVM.GetName(), err)
		// log.Errorf(msg)
		return errors.Wrap(err, "remoteVM.GetIEIP")
	}
	result := localVM.SyncVMEip(ctx, userCred, provider, eip, provider.GetOwnerId())
	msg := result.Result()
	log.Infof("syncVMEip for VM %s result: %s", localVM.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	return nil
}

func syncVMSecgroups(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localVM *SGuest, remoteVM cloudprovider.ICloudVM) error {
	secgroupIds, err := remoteVM.GetSecurityGroupIds()
	if err != nil {
		// msg := fmt.Sprintf("GetSecurityGroupIds for VM %s failed %s", remoteVM.GetName(), err)
		// log.Errorf(msg)
		return errors.Wrap(err, "remoteVM.GetSecurityGroupIds")
	}
	return localVM.SyncVMSecgroups(ctx, userCred, secgroupIds)
}

func syncSkusFromPrivateCloud(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, region *SCloudregion, remoteRegion cloudprovider.ICloudRegion) {
	skus, err := remoteRegion.GetISkus()
	if err != nil {
		msg := fmt.Sprintf("GetISkus for region %s(%s) failed %v", region.Name, region.Id, err)
		log.Errorf(msg)
		return
	}

	result := ServerSkuManager.SyncPrivateCloudSkus(ctx, userCred, region, skus)

	syncResults.Add(ServerSkuManager, result)

	msg := result.Result()
	log.Infof("SyncCloudSkusByRegion for region %s result: %s", region.Name, msg)
	if result.IsError() {
		return
	}
	s := auth.GetSession(ctx, userCred, "", "")
	if _, err := modules.SchedManager.SyncSku(s, true); err != nil {
		log.Errorf("Sync scheduler sku cache error: %v", err)
	}
}

func syncRegionDBInstances(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	instances, err := remoteRegion.GetIDBInstances()
	if err != nil {
		msg := fmt.Sprintf("GetIDBInstances for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return
	}
	localInstances, remoteInstances, result := DBInstanceManager.SyncDBInstances(ctx, userCred, provider.GetOwnerId(), provider, localRegion, instances)

	syncResults.Add(DBInstanceManager, result)
	DBInstanceManager.SyncDBInstanceMasterId(ctx, userCred, provider, instances)

	msg := result.Result()
	log.Infof("SyncDBInstances for region %s result: %s", localRegion.Name, msg)
	if result.IsError() {
		return
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	for i := 0; i < len(localInstances); i++ {
		func() {
			lockman.LockObject(ctx, &localInstances[i])
			defer lockman.ReleaseObject(ctx, &localInstances[i])

			if localInstances[i].Deleted || localInstances[i].PendingDeleted {
				return
			}

			syncDBInstanceResource(ctx, userCred, syncResults, &localInstances[i], remoteInstances[i])
		}()
	}
}

func syncDBInstanceResource(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) {
	err := syncDBInstanceNetwork(ctx, userCred, syncResults, localInstance, remoteInstance)
	if err != nil {
		log.Errorf("syncDBInstanceNetwork error: %v", err)
	}
	err = syncDBInstanceSecgroups(ctx, userCred, syncResults, localInstance, remoteInstance)
	if err != nil {
		log.Errorf("syncDBInstanceSecgroups error: %v", err)
	}
	err = syncDBInstanceParameters(ctx, userCred, syncResults, localInstance, remoteInstance)
	if err != nil {
		log.Errorf("syncDBInstanceParameters error: %v", err)
	}
	err = syncDBInstanceDatabases(ctx, userCred, syncResults, localInstance, remoteInstance)
	if err != nil {
		log.Errorf("syncDBInstanceParameters error: %v", err)
	}
	err = syncDBInstanceAccounts(ctx, userCred, syncResults, localInstance, remoteInstance)
	if err != nil {
		log.Errorf("syncDBInstanceAccounts: %v", err)
	}
	err = syncDBInstanceBackups(ctx, userCred, syncResults, localInstance, remoteInstance)
	if err != nil {
		log.Errorf("syncDBInstanceBackups: %v", err)
	}
}

func syncDBInstanceNetwork(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) error {
	networks, err := remoteInstance.GetDBNetworks()
	if err != nil {
		return errors.Wrapf(err, "GetDBNetworks")
	}

	result := DBInstanceNetworkManager.SyncDBInstanceNetwork(ctx, userCred, localInstance, networks)
	syncResults.Add(DBInstanceNetworkManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceNetwork for dbinstance %s result: %s", localInstance.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil
}

func syncDBInstanceSecgroups(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) error {
	secIds, err := remoteInstance.GetSecurityGroupIds()
	if err != nil {
		return errors.Wrapf(err, "GetSecurityGroupIds")
	}
	result := DBInstanceSecgroupManager.SyncDBInstanceSecgroups(ctx, userCred, localInstance, secIds)
	syncResults.Add(DBInstanceSecgroupManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceSecgroups for dbinstance %s result: %s", localInstance.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil
}

func syncDBInstanceBackups(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) error {
	backups, err := remoteInstance.GetIDBInstanceBackups()
	if err != nil {
		return errors.Wrapf(err, "GetIDBInstanceBackups")
	}

	region := localInstance.GetRegion()
	provider := localInstance.GetCloudprovider()

	result := DBInstanceBackupManager.SyncDBInstanceBackups(ctx, userCred, provider, localInstance, region, backups)
	syncResults.Add(DBInstanceBackupManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceBackups for dbinstance %s result: %s", localInstance.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil
}

func syncDBInstanceParameters(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) error {
	parameters, err := remoteInstance.GetIDBInstanceParameters()
	if err != nil {
		return errors.Wrapf(err, "GetIDBInstanceParameters")
	}

	result := DBInstanceParameterManager.SyncDBInstanceParameters(ctx, userCred, localInstance, parameters)
	syncResults.Add(DBInstanceParameterManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceParameters for dbinstance %s result: %s", localInstance.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil
}

func syncRegionDBInstanceBackups(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) error {
	backups, err := remoteRegion.GetIDBInstanceBackups()
	if err != nil {
		return errors.Wrapf(err, "GetIDBInstanceBackups")
	}

	result := DBInstanceBackupManager.SyncDBInstanceBackups(ctx, userCred, provider, nil, localRegion, backups)
	syncResults.Add(DBInstanceBackupManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceBackups for region %s result: %s", localRegion.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil

}

func syncDBInstanceDatabases(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) error {
	databases, err := remoteInstance.GetIDBInstanceDatabases()
	if err != nil {
		return errors.Wrapf(err, "GetIDBInstanceDatabases")
	}

	result := DBInstanceDatabaseManager.SyncDBInstanceDatabases(ctx, userCred, localInstance, databases)
	syncResults.Add(DBInstanceDatabaseManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceDatabases for dbinstance %s result: %s", localInstance.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil
}

func syncDBInstanceAccounts(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localInstance *SDBInstance, remoteInstance cloudprovider.ICloudDBInstance) error {
	accounts, err := remoteInstance.GetIDBInstanceAccounts()
	if err != nil {
		return errors.Wrapf(err, "GetIDBInstanceAccounts")
	}

	localAccounts, remoteAccounts, result := DBInstanceAccountManager.SyncDBInstanceAccounts(ctx, userCred, localInstance, accounts)
	syncResults.Add(DBInstanceDatabaseManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceAccounts for dbinstance %s result: %s", localInstance.Name, msg)
	if result.IsError() {
		return result.AllError()
	}

	for i := 0; i < len(localAccounts); i++ {
		func() {
			lockman.LockObject(ctx, &localAccounts[i])
			defer lockman.ReleaseObject(ctx, &localAccounts[i])

			if localAccounts[i].Deleted {
				return
			}

			err = syncDBInstanceAccountPrivileges(ctx, userCred, syncResults, &localAccounts[i], remoteAccounts[i])
			if err != nil {
				log.Errorf("syncDBInstanceAccountPrivileges error: %v", err)
			}

		}()
	}
	return nil
}

func syncDBInstanceAccountPrivileges(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, localAccount *SDBInstanceAccount, remoteAccount cloudprovider.ICloudDBInstanceAccount) error {
	privileges, err := remoteAccount.GetIDBInstanceAccountPrivileges()
	if err != nil {
		return errors.Wrapf(err, "GetIDBInstanceAccountPrivileges for %s(%s)", localAccount.Name, localAccount.Id)
	}

	result := DBInstancePrivilegeManager.SyncDBInstanceAccountPrivileges(ctx, userCred, localAccount, privileges)
	syncResults.Add(DBInstancePrivilegeManager, result)

	msg := result.Result()
	log.Infof("SyncDBInstanceAccountPrivileges for account %s result: %s", localAccount.Name, msg)
	if result.IsError() {
		return result.AllError()
	}
	return nil
}

func syncRegionSnapshots(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	snapshots, err := remoteRegion.GetISnapshots()
	if err != nil {
		msg := fmt.Sprintf("GetISnapshots for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return
	}

	result := SnapshotManager.SyncSnapshots(ctx, userCred, provider, localRegion, snapshots, provider.GetOwnerId())

	syncResults.Add(SnapshotManager, result)

	msg := result.Result()
	log.Infof("SyncSnapshots for region %s result: %s", localRegion.Name, msg)
	if result.IsError() {
		return
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
}

func syncRegionSnapshotPolicies(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	snapshotPolicies, err := remoteRegion.GetISnapshotPolicies()
	if err != nil {
		log.Errorf("GetISnapshotPolicies for region %s failed %s", remoteRegion.GetName(), err)
		return
	}

	result := SnapshotPolicyManager.SyncSnapshotPolicies(
		ctx, userCred, provider, localRegion, snapshotPolicies, provider.GetOwnerId())
	syncResults.Add(SnapshotPolicyManager, result)
	msg := result.Result()
	log.Infof("SyncSnapshotPolicies for region %s result: %s", localRegion.Name, msg)
	if result.IsError() {
		return
	}
}

func syncRegionNetworkInterfaces(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localRegion *SCloudregion, remoteRegion cloudprovider.ICloudRegion, syncRange *SSyncRange) {
	networkInterfaces, err := remoteRegion.GetINetworkInterfaces()
	if err != nil {
		msg := fmt.Sprintf("GetINetworkInterfaces for region %s failed %s", remoteRegion.GetName(), err)
		log.Errorf(msg)
		return
	}
	localInterfaces, remoteInterfaces, result := NetworkInterfaceManager.SyncNetworkInterfaces(ctx, userCred, provider, localRegion, networkInterfaces)

	syncResults.Add(NetworkInterfaceManager, result)

	msg := result.Result()
	log.Infof("SyncNetworkInterfaces for region %s result: %s", localRegion.Name, msg)
	if result.IsError() {
		return
	}

	for i := 0; i < len(localInterfaces); i++ {
		func() {
			lockman.LockObject(ctx, &localInterfaces[i])
			defer lockman.ReleaseObject(ctx, &localInterfaces[i])

			if localInterfaces[i].Deleted {
				return
			}

			syncInterfaceAddresses(ctx, userCred, &localInterfaces[i], remoteInterfaces[i])
		}()
	}
}

func syncInterfaceAddresses(ctx context.Context, userCred mcclient.TokenCredential, localInterface *SNetworkInterface, remoteInterface cloudprovider.ICloudNetworkInterface) {
	addresses, err := remoteInterface.GetICloudInterfaceAddresses()
	if err != nil {
		msg := fmt.Sprintf("GetICloudInterfaceAddresses for networkinterface %s failed %s", remoteInterface.GetName(), err)
		log.Errorf(msg)
		return
	}

	result := NetworkinterfacenetworkManager.SyncInterfaceAddresses(ctx, userCred, localInterface, addresses)
	msg := result.Result()
	notes := fmt.Sprintf("SyncInterfaceAddresses for networkinterface %s result: %s", localInterface.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
}

func syncPublicCloudProviderInfo(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	syncResults SSyncResultSet,
	provider *SCloudprovider,
	driver cloudprovider.ICloudProvider,
	localRegion *SCloudregion,
	remoteRegion cloudprovider.ICloudRegion,
	syncRange *SSyncRange,
) error {
	if syncRange != nil && len(syncRange.Region) > 0 && !utils.IsInStringArray(localRegion.Id, syncRange.Region) {
		// no need to sync
		return nil
	}

	log.Debugf("Start sync cloud provider %s(%s) on region %s(%s)",
		provider.Name, provider.Provider, remoteRegion.GetName(), remoteRegion.GetId())

	storageCachePairs := make([]sStoragecacheSyncPair, 0)

	syncRegionQuotas(ctx, userCred, syncResults, driver, provider, localRegion, remoteRegion)

	localZones, remoteZones, _ := syncRegionZones(ctx, userCred, syncResults, provider, localRegion, remoteRegion)

	if !driver.GetFactory().NeedSyncSkuFromCloud() {
		syncRegionSkus(ctx, userCred, localRegion)
		SyncRegionDBInstanceSkus(ctx, userCred, localRegion.Id, true)
		SyncRegionNatSkus(ctx, userCred, localRegion.Id, true)
		SyncRegionNasSkus(ctx, userCred, localRegion.Id, true)
	} else {
		syncSkusFromPrivateCloud(ctx, userCred, syncResults, localRegion, remoteRegion)
	}

	// no need to lock public cloud region as cloud region for public cloud is readonly

	if cloudprovider.IsSupportObjectstore(driver) {
		syncRegionBuckets(ctx, userCred, syncResults, provider, localRegion, remoteRegion)
	}

	if cloudprovider.IsSupportCompute(driver) {
		// 需要先同步vpc，避免私有云eip找不到network
		syncRegionVPCs(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)

		syncRegionEips(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
		// sync snapshot policies before sync disks
		syncRegionSnapshotPolicies(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)

		for j := 0; j < len(localZones); j += 1 {

			if len(syncRange.Zone) > 0 && !utils.IsInStringArray(localZones[j].Id, syncRange.Zone) {
				continue
			}
			// no need to lock zone as public cloud zone is read-only

			newPairs := syncZoneStorages(ctx, userCred, syncResults, provider, driver, &localZones[j], remoteZones[j], syncRange, storageCachePairs)
			if len(newPairs) > 0 {
				storageCachePairs = append(storageCachePairs, newPairs...)
			}
			newPairs = syncZoneHosts(ctx, userCred, syncResults, provider, driver, &localZones[j], remoteZones[j], syncRange, storageCachePairs)
			if len(newPairs) > 0 {
				storageCachePairs = append(storageCachePairs, newPairs...)
			}
		}

		// sync snapshots after sync disks
		syncRegionSnapshots(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
	}

	syncRegionAccessGroups(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
	syncRegionFileSystems(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)

	if cloudprovider.IsSupportLoadbalancer(driver) {
		syncRegionLoadbalancerAcls(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
		syncRegionLoadbalancerCertificates(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
		syncRegionLoadbalancers(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
	}

	if cloudprovider.IsSupportCompute(driver) {
		syncRegionNetworkInterfaces(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
	}

	if cloudprovider.IsSupportRds(driver) {
		syncRegionDBInstances(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
		syncRegionDBInstanceBackups(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
	}

	if cloudprovider.IsSupportElasticCache(driver) {
		syncElasticcaches(ctx, userCred, syncResults, provider, localRegion, remoteRegion, syncRange)
	}

	if cloudprovider.IsSupportCompute(driver) {
		log.Debugf("storageCachePairs count %d", len(storageCachePairs))
		for i := range storageCachePairs {
			// always sync private cloud cached images
			if storageCachePairs[i].isNew || syncRange.DeepSync || !driver.GetFactory().IsPublicCloud() {
				result := storageCachePairs[i].syncCloudImages(ctx, userCred)

				syncResults.Add(StoragecachedimageManager, result)

				msg := result.Result()
				log.Infof("syncCloudImages result: %s", msg)
			}
		}
	}

	return nil
}

func syncOnPremiseCloudProviderInfo(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	syncResults SSyncResultSet,
	provider *SCloudprovider,
	driver cloudprovider.ICloudProvider,
	syncRange *SSyncRange,
) error {
	log.Debugf("Start sync on-premise provider %s(%s)", provider.Name, provider.Provider)

	iregion, err := driver.GetOnPremiseIRegion()
	if err != nil {
		msg := fmt.Sprintf("GetOnPremiseIRegion for provider %s failed %s", provider.GetName(), err)
		log.Errorf(msg)
		return err
	}

	localRegion := CloudregionManager.FetchDefaultRegion()

	if cloudprovider.IsSupportObjectstore(driver) {
		syncRegionBuckets(ctx, userCred, syncResults, provider, localRegion, iregion)
	}

	storageCachePairs := make([]sStoragecacheSyncPair, 0)
	if cloudprovider.IsSupportCompute(driver) {
		ihosts, err := iregion.GetIHosts()
		if err != nil {
			msg := fmt.Sprintf("GetIHosts for provider %s failed %s", provider.GetName(), err)
			log.Errorf(msg)
			return err
		}

		localHosts, remoteHosts, result := HostManager.SyncHosts(ctx, userCred, provider, nil, ihosts)

		syncResults.Add(HostManager, result)

		msg := result.Result()
		notes := fmt.Sprintf("SyncHosts for provider %s result: %s", provider.Name, msg)
		log.Infof(notes)

		for i := 0; i < len(localHosts); i += 1 {
			if len(syncRange.Host) > 0 && !utils.IsInStringArray(localHosts[i].Id, syncRange.Host) {
				continue
			}
			newCachePairs := syncHostStorages(ctx, userCred, syncResults, provider, &localHosts[i], remoteHosts[i], storageCachePairs)
			if len(newCachePairs) > 0 {
				storageCachePairs = append(storageCachePairs, newCachePairs...)
			}
			syncHostNics(ctx, userCred, provider, &localHosts[i], remoteHosts[i])
			syncOnPremiseHostWires(ctx, userCred, syncResults, provider, &localHosts[i], remoteHosts[i])
			syncHostVMs(ctx, userCred, syncResults, provider, driver, &localHosts[i], remoteHosts[i], syncRange)
		}
	}

	if cloudprovider.IsSupportCompute(driver) {
		log.Debugf("storageCachePairs count %d", len(storageCachePairs))
		for i := range storageCachePairs {
			// alway sync on-premise cached images
			// if storageCachePairs[i].isNew || syncRange.DeepSync {
			result := storageCachePairs[i].syncCloudImages(ctx, userCred)
			syncResults.Add(StoragecachedimageManager, result)
			msg := result.Result()
			log.Infof("syncCloudImages for stroagecache %s result: %s", storageCachePairs[i].local.GetId(), msg)
			// }
		}
	}

	return nil
}

func syncOnPremiseHostWires(ctx context.Context, userCred mcclient.TokenCredential, syncResults SSyncResultSet, provider *SCloudprovider, localHost *SHost, remoteHost cloudprovider.ICloudHost) {
	log.Infof("start to sync OnPremeseHostWires")
	if provider.Provider != api.CLOUD_PROVIDER_VMWARE {
		return
	}
	result := localHost.SyncEsxiHostWires(ctx, userCred, remoteHost)
	if syncResults != nil {
		syncResults.Add(HostManager, result)
	}

	msg := result.Result()
	notes := fmt.Sprintf("SyncEsxiHostWires for host %s result: %s", localHost.Name, msg)
	if result.IsError() {
		log.Errorf(notes)
		return
	} else {
		log.Infof(notes)
	}
	db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
}

func syncHostNics(ctx context.Context, userCred mcclient.TokenCredential, provider *SCloudprovider, localHost *SHost, remoteHost cloudprovider.ICloudHost) {
	result := localHost.SyncHostExternalNics(ctx, userCred, remoteHost)
	msg := result.Result()
	notes := fmt.Sprintf("SyncHostWires for host %s result: %s", localHost.Name, msg)
	log.Infof(notes)
	if result.IsError() {
		return
	}
	// db.OpsLog.LogEvent(provider, db.ACT_SYNC_HOST_COMPLETE, msg, userCred)
	// logclient.AddActionLog(provider, getAction(task.GetParams()), notes, task.GetUserCred(), true)
}

func (manager *SCloudproviderregionManager) fetchRecordsByQuery(q *sqlchemy.SQuery) []SCloudproviderregion {
	recs := make([]SCloudproviderregion, 0)
	err := db.FetchModelObjects(manager, q, &recs)
	if err != nil {
		return nil
	}
	return recs
}

func (manager *SCloudproviderregionManager) initAllRecords() {
	recs := manager.fetchRecordsByQuery(manager.Query())
	for i := range recs {
		db.Update(&recs[i], func() error {
			recs[i].SyncStatus = api.CLOUD_PROVIDER_SYNC_STATUS_IDLE
			return nil
		})
	}
}

func SyncCloudProject(userCred mcclient.TokenCredential, model db.IVirtualModel, syncOwnerId mcclient.IIdentityProvider, extModel cloudprovider.IVirtualResource, managerId string) {
	newOwnerId, err := func() (mcclient.IIdentityProvider, error) {
		_manager, err := CloudproviderManager.FetchById(managerId)
		if err != nil {
			return nil, errors.Wrapf(err, "CloudproviderManager.FetchById(%s)", managerId)
		}
		manager := _manager.(*SCloudprovider)
		rm, err := manager.GetProjectMapping()
		if err != nil {
			if errors.Cause(err) == cloudprovider.ErrNotFound {
				return nil, nil
			}
			return nil, errors.Wrapf(err, "GetProjectMapping")
		}
		account := manager.GetCloudaccount()
		if account == nil {
			return nil, fmt.Errorf("can not find manager %s account", manager.Name)
		}
		if rm != nil && rm.Enabled.Bool() {
			extTags, err := extModel.GetTags()
			if err != nil {
				return nil, errors.Wrapf(err, "extModel.GetTags")
			}
			if rm.Rules != nil {
				for _, rule := range *rm.Rules {
					domainId, projectId, newProj, isMatch := rule.IsMatchTags(extTags)
					if isMatch {
						if len(newProj) > 0 {
							domainId, projectId, err = account.getOrCreateTenant(context.TODO(), newProj, "", "auto create from tag")
							if err != nil {
								return nil, errors.Wrapf(err, "getOrCreateTenant(%s)", newProj)
							}
						}
						if len(domainId) > 0 && len(projectId) > 0 {
							return &db.SOwnerId{DomainId: domainId, ProjectId: projectId}, nil
						}
					}
				}
			}
		}
		return nil, nil
	}()
	if err != nil {
		log.Errorf("try sync project for %s %s by tags error: %v", model.Keyword(), model.GetName(), err)
	}
	if extProjectId := extModel.GetProjectId(); len(extProjectId) > 0 && newOwnerId == nil {
		extProject, err := ExternalProjectManager.GetProject(extProjectId, managerId)
		if err != nil {
			log.Errorf("sync project for %s %s error: %v", model.Keyword(), model.GetName(), err)
		} else if len(extProject.ProjectId) > 0 {
			newOwnerId = extProject.GetOwnerId()
		}
	}
	if newOwnerId == nil && syncOwnerId != nil && len(syncOwnerId.GetProjectId()) > 0 {
		newOwnerId = syncOwnerId
	}
	if newOwnerId == nil {
		newOwnerId = userCred
	}
	model.SyncCloudProjectId(userCred, newOwnerId)
}

func SyncCloudDomain(userCred mcclient.TokenCredential, model db.IDomainLevelModel, syncOwnerId mcclient.IIdentityProvider) {
	var newOwnerId mcclient.IIdentityProvider
	if syncOwnerId != nil && len(syncOwnerId.GetProjectDomainId()) > 0 {
		newOwnerId = syncOwnerId
	}
	if newOwnerId == nil {
		newOwnerId = userCred
	}
	model.SyncCloudDomainId(userCred, newOwnerId)
}
