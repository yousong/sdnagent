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
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	v "yunion.io/x/pkg/util/version"

	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/compute/options"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/mcclient/auth"
	"yunion.io/x/onecloud/pkg/mcclient/modules"
)

/*
资源套餐下载连接信息
server: 虚拟机
elasticcache: 弹性缓存(redis&memcached)
*/
type SSkuResourcesMeta struct {
	DBInstanceBase   string `json:"dbinstance_base"`
	ServerBase       string `json:"server_base"`
	ElasticCacheBase string `json:"elastic_cache_base"`
}

func (self *SSkuResourcesMeta) getZoneIdBySuffix(zoneMaps map[string]string, suffix string) string {
	for externalId, id := range zoneMaps {
		if strings.HasSuffix(externalId, suffix) {
			return id
		}
	}
	return ""
}

func (self *SSkuResourcesMeta) GetDBInstanceSkusByRegionExternalId(regionExternalId string) ([]SDBInstanceSku, error) {
	regionId, zoneMaps, err := self.GetRegionIdAndZoneMaps(regionExternalId)
	if err != nil {
		return nil, errors.Wrap(err, "GetRegionIdAndZoneMaps")
	}
	result := []SDBInstanceSku{}
	objs, err := self.getSkusByRegion(self.DBInstanceBase, regionExternalId)
	if err != nil {
		return nil, errors.Wrapf(err, "getSkusByRegion")
	}
	for _, obj := range objs {
		sku := SDBInstanceSku{}
		sku.SetModelManager(DBInstanceSkuManager, &sku)
		err = obj.Unmarshal(&sku)
		if err != nil {
			return nil, errors.Wrapf(err, "obj.Unmarshal")
		}
		if len(sku.Zone1) > 0 {
			zoneId := self.getZoneIdBySuffix(zoneMaps, sku.Zone1) // Huawei rds sku zone1 maybe is cn-north-4f
			if len(zoneId) == 0 {
				log.Errorf("invalid sku %s(%s) %s zone1: %s", sku.Name, sku.Id, sku.CloudregionId, sku.Zone1)
				continue
			}
			sku.Zone1 = zoneId
		}

		if len(sku.Zone2) > 0 {
			zoneId := self.getZoneIdBySuffix(zoneMaps, sku.Zone2)
			if len(zoneId) == 0 {
				log.Errorf("invalid sku %s(%s) %s zone2: %s", sku.Name, sku.Id, sku.CloudregionId, sku.Zone2)
				continue
			}
			sku.Zone2 = zoneId
		}

		if len(sku.Zone3) > 0 {
			zoneId := self.getZoneIdBySuffix(zoneMaps, sku.Zone3)
			if len(zoneId) == 0 {
				log.Errorf("invalid sku %s(%s) %s zone3: %s", sku.Name, sku.Id, sku.CloudregionId, sku.Zone3)
				continue
			}
			sku.Zone3 = zoneId
		}

		sku.Id = ""
		sku.CloudregionId = regionId

		result = append(result, sku)
	}
	return result, nil
}

func (self *SSkuResourcesMeta) getCloudregion(regionExternalId string) (*SCloudregion, error) {
	region, err := db.FetchByExternalId(CloudregionManager, regionExternalId)
	if err != nil {
		return nil, errors.Wrapf(err, "db.FetchByExternalId(%s)", regionExternalId)
	}
	return region.(*SCloudregion), nil
}

func (self *SSkuResourcesMeta) GetRegionIdAndZoneMaps(regionExternalId string) (string, map[string]string, error) {
	region, err := self.getCloudregion(regionExternalId)
	if err != nil {
		return "", nil, errors.Wrap(err, "getCloudregion")
	}
	zones, err := region.GetZones()
	if err != nil {
		return "", nil, errors.Wrap(err, "GetZones")
	}
	zoneMaps := map[string]string{}
	for _, zone := range zones {
		zoneMaps[zone.ExternalId] = zone.Id
	}
	return region.Id, zoneMaps, nil
}

func (self *SSkuResourcesMeta) GetServerSkusByRegionExternalId(regionExternalId string) ([]SServerSku, error) {
	regionId, zoneMaps, err := self.GetRegionIdAndZoneMaps(regionExternalId)
	if err != nil {
		return nil, errors.Wrap(err, "GetRegionIdAndZoneMaps")
	}
	result := []SServerSku{}
	objs, err := self.getSkusByRegion(self.ServerBase, regionExternalId)
	if err != nil {
		return nil, errors.Wrap(err, "getSkusByRegion")
	}
	for _, obj := range objs {
		sku := SServerSku{}
		sku.SetModelManager(ElasticcacheSkuManager, &sku)
		err = obj.Unmarshal(&sku)
		if err != nil {
			return nil, errors.Wrapf(err, "obj.Unmarshal")
		}
		if len(sku.ZoneId) > 0 {
			zoneId := self.getZoneIdBySuffix(zoneMaps, sku.ZoneId)
			if len(zoneId) == 0 {
				return nil, fmt.Errorf("invalid sku %s %s zoneId: %s", sku.Id, sku.CloudregionId, sku.ZoneId)
			}
			sku.ZoneId = zoneId
		}
		sku.Id = ""
		sku.CloudregionId = regionId
		result = append(result, sku)
	}
	return result, nil
}

func (self *SSkuResourcesMeta) GetElasticCacheSkusByRegionExternalId(regionExternalId string) ([]SElasticcacheSku, error) {
	regionId, zoneMaps, err := self.GetRegionIdAndZoneMaps(regionExternalId)
	if err != nil {
		return nil, errors.Wrap(err, "GetRegionIdAndZoneMaps")
	}
	result := []SElasticcacheSku{}
	objs, err := self.getSkusByRegion(self.ElasticCacheBase, regionExternalId)
	if err != nil {
		return nil, errors.Wrap(err, "getSkusByRegion")
	}
	for _, obj := range objs {
		sku := SElasticcacheSku{}
		sku.SetModelManager(ElasticcacheSkuManager, &sku)
		err = obj.Unmarshal(&sku)
		if err != nil {
			return nil, errors.Wrapf(err, "obj.Unmarshal")
		}
		if len(sku.ZoneId) > 0 {
			zoneId := self.getZoneIdBySuffix(zoneMaps, sku.ZoneId)
			if len(zoneId) == 0 {
				return nil, fmt.Errorf("invalid sku %s %s master zoneId: %s", sku.Id, sku.CloudregionId, sku.ZoneId)
			}
			sku.ZoneId = zoneId
		}
		if len(sku.SlaveZoneId) > 0 {
			zoneId := self.getZoneIdBySuffix(zoneMaps, sku.SlaveZoneId)
			if len(zoneId) == 0 {
				return nil, fmt.Errorf("invalid sku %s %s slave zoneId: %s", sku.Id, sku.CloudregionId, sku.SlaveZoneId)
			}
			sku.SlaveZoneId = zoneId
		}
		sku.Id = ""
		sku.CloudregionId = regionId
		result = append(result, sku)
	}
	return result, nil
}

func (self *SSkuResourcesMeta) getSkusByRegion(base string, region string) ([]jsonutils.JSONObject, error) {
	url := fmt.Sprintf("%s/%s.json", base, region)
	items, err := self._get(url)
	if err != nil {
		return nil, errors.Wrap(err, "getSkusByRegion.get")
	}
	return items, nil
}

func (self *SSkuResourcesMeta) _get(url string) ([]jsonutils.JSONObject, error) {
	if !strings.HasPrefix(url, "http") {
		return nil, fmt.Errorf("SkuResourcesMeta.get invalid url %s.expected has prefix 'http'", url)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("SkuResourcesMeta.get.NewRequest %s", err)
	}

	userAgent := "vendor/yunion-OneCloud@" + v.Get().GitVersion
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SkuResourcesMeta.get.Get %s", err)
	}

	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("SkuResourcesMeta.get.ReadAll %s", err)
	}

	jsonContent, err := jsonutils.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("SkuResourcesMeta.get.Parse %s", err)
	}

	var ret []jsonutils.JSONObject
	err = jsonContent.Unmarshal(&ret)
	if err != nil {
		return nil, fmt.Errorf("SkuResourcesMeta.get.Unmarshal %s content: %s url: %s", err, jsonContent, url)
	}

	return ret, nil
}

// 全量同步elasticcache sku列表.
func SyncElasticCacheSkus(ctx context.Context, userCred mcclient.TokenCredential, isStart bool) {
	if isStart {
		cnt, err := CloudaccountManager.Query().IsTrue("is_public_cloud").CountWithError()
		if err != nil && err != sql.ErrNoRows {
			log.Debugf("SyncElasticCacheSkus %s.sync skipped...", err)
			return
		} else if cnt == 0 {
			log.Debugf("SyncElasticCacheSkus no public cloud.sync skipped...")
			return
		}

		cnt, err = ElasticcacheSkuManager.Query().Limit(1).CountWithError()
		if err != nil && err != sql.ErrNoRows {
			log.Errorf("SyncElasticCacheSkus.QueryElasticcacheSku %s", err)
			return
		} else if cnt > 0 {
			log.Debugf("SyncElasticCacheSkus synced skus, skip...")
			return
		}
	}

	meta, err := FetchSkuResourcesMeta()
	if err != nil {
		log.Errorf("SyncElasticCacheSkus.FetchSkuResourcesMeta %s", err)
		return
	}

	cloudregions := fetchSkuSyncCloudregions()
	for i := range cloudregions {
		region := &cloudregions[i]

		if region.GetDriver().IsSupportedElasticcache() {
			result := ElasticcacheSkuManager.SyncElasticcacheSkus(ctx, userCred, region, meta)
			notes := fmt.Sprintf("SyncElasticCacheSkusByRegion %s result: %s", region.Name, result.Result())
			log.Infof(notes)
		} else {
			notes := fmt.Sprintf("SyncElasticCacheSkusByRegion %s not support elasticcache", region.Name)
			log.Infof(notes)
		}
	}
}

// 同步Region elasticcache sku列表.
func SyncElasticCacheSkusByRegion(ctx context.Context, userCred mcclient.TokenCredential, region *SCloudregion) error {
	if !region.GetDriver().IsSupportedElasticcache() {
		notes := fmt.Sprintf("SyncElasticCacheSkusByRegion %s not support elasticcache", region.Name)
		log.Infof(notes)
		return nil
	}

	meta, err := FetchSkuResourcesMeta()
	if err != nil {
		return errors.Wrap(err, "SyncElasticCacheSkusByRegion.FetchSkuResourcesMeta")
	}

	result := ElasticcacheSkuManager.SyncElasticcacheSkus(ctx, userCred, region, meta)
	notes := fmt.Sprintf("SyncElasticCacheSkusByRegion %s result: %s", region.Name, result.Result())
	log.Infof(notes)
	return nil
}

// 全量同步sku列表.
func SyncServerSkus(ctx context.Context, userCred mcclient.TokenCredential, isStart bool) {
	if isStart {
		cnt, err := ServerSkuManager.GetPublicCloudSkuCount()
		if err != nil {
			log.Errorf("GetPublicCloudSkuCount fail %s", err)
			return
		}
		if cnt > 0 {
			log.Debugf("GetPublicCloudSkuCount synced skus, skip...")
			return
		}
	}

	meta, err := FetchSkuResourcesMeta()
	if err != nil {
		log.Errorf("SyncServerSkus.FetchSkuResourcesMeta %s", err)
		return
	}

	cloudregions := fetchSkuSyncCloudregions()
	for i := range cloudregions {
		region := &cloudregions[i]
		result := ServerSkuManager.SyncServerSkus(ctx, userCred, region, meta)
		notes := fmt.Sprintf("SyncServerSkusByRegion %s result: %s", region.Name, result.Result())
		log.Infof(notes)
	}

	// 清理无效的sku
	log.Debugf("DeleteInvalidSkus in processing...")
	ServerSkuManager.PendingDeleteInvalidSku()
}

// 同步指定region sku列表
func SyncServerSkusByRegion(ctx context.Context, userCred mcclient.TokenCredential, region *SCloudregion) error {
	meta, err := FetchSkuResourcesMeta()
	if err != nil {
		return errors.Wrap(err, "SyncServerSkusByRegion.FetchSkuResourcesMeta")
	}

	result := ServerSkuManager.SyncServerSkus(ctx, userCred, region, meta)
	notes := fmt.Sprintf("SyncServerSkusByRegion %s result: %s", region.Name, result.Result())
	log.Infof(notes)
	return nil
}

func FetchSkuResourcesMeta() (*SSkuResourcesMeta, error) {
	s := auth.GetAdminSession(context.Background(), options.Options.Region, "")
	meta, err := modules.OfflineCloudmeta.GetSkuSourcesMeta(s)
	if err != nil {
		return nil, errors.Wrap(err, "fetchSkuSourceUrls.GetSkuSourcesMeta")
	}

	ret := &SSkuResourcesMeta{}
	err = meta.Unmarshal(ret)
	if err != nil {
		return nil, errors.Wrap(err, "fetchSkuSourceUrls.Unmarshal")
	}

	return ret, nil
}

func fetchSkuSyncCloudregions() []SCloudregion {
	cloudregions := []SCloudregion{}
	q := CloudregionManager.Query()
	q = q.In("provider", CloudproviderManager.GetPublicProviderProvidersQuery())
	err := db.FetchModelObjects(CloudregionManager, q, &cloudregions)
	if err != nil {
		log.Errorf("fetchSkuSyncCloudregions.FetchCloudregions failed: %v", err)
		return nil
	}

	return cloudregions
}
