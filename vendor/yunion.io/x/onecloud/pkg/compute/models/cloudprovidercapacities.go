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
	"sort"

	"yunion.io/x/pkg/errors"

	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/util/stringutils2"
)

// +onecloud:swagger-gen-ignore
type SCloudproviderCapabilityManager struct {
	db.SResourceBaseManager
}

var CloudproviderCapabilityManager *SCloudproviderCapabilityManager

func init() {
	CloudproviderCapabilityManager = &SCloudproviderCapabilityManager{
		SResourceBaseManager: db.NewResourceBaseManager(
			SCloudproviderCapability{},
			"cloudprovider_capabilities_tbl",
			"cloudprovider_capability",
			"cloudprovider_capabilities",
		),
	}
	CloudproviderCapabilityManager.SetVirtualObject(CloudproviderCapabilityManager)
}

type SCloudproviderCapability struct {
	db.SResourceBase

	CloudproviderId string `width:"36" charset:"ascii" nullable:"false" primary:"true"`
	CloudregionId   string `width:"36" charset:"ascii" nullable:"false" default:"" primary:"true"`
	Capability      string `width:"18" charset:"ascii" nullable:"false" primary:"true"`
}

func (manager *SCloudproviderCapabilityManager) setCapabilities(ctx context.Context, userCred mcclient.TokenCredential, cloudproviderId string, capabilities []string) error {
	return manager.setRegionCapabilities(ctx, userCred, cloudproviderId, "", capabilities)
}

func (manager *SCloudproviderCapabilityManager) setRegionCapabilities(ctx context.Context, userCred mcclient.TokenCredential, cloudproviderId string, cloudregionId string, capabilities []string) error {
	oldCapabilities, err := manager.getRegionCapabilities(cloudproviderId, cloudregionId)
	if err != nil {
		return errors.Wrap(err, "manager.getCapabilities")
	}
	oldCapas := stringutils2.NewSortedStrings(oldCapabilities)
	newCapas := stringutils2.NewSortedStrings(capabilities)
	deleted, _, added := stringutils2.Split(oldCapas, newCapas)

	cpc := SCloudproviderCapability{
		CloudproviderId: cloudproviderId,
		CloudregionId:   cloudregionId,
	}
	cpc.SetModelManager(manager, &cpc)

	for _, capability := range added {
		cpc.Capability = capability
		err := manager.TableSpec().InsertOrUpdate(ctx, &cpc)
		if err != nil {
			return errors.Wrap(err, "manager.TableSpec().InsertOrUpdate")
		}
	}
	for _, capability := range deleted {
		cpc.Capability = capability
		err := cpc.Delete(ctx, userCred)
		if err != nil {
			return errors.Wrap(err, "cpc.Delete")
		}
	}
	return nil
}

func (manager *SCloudproviderCapabilityManager) getCapabilities(cloudproviderId string) ([]string, error) {
	return manager.getRegionCapabilities(cloudproviderId, "")
}

func (manager *SCloudproviderCapabilityManager) getRegionCapabilities(cloudproviderId string, cloudregionId string) ([]string, error) {
	q := manager.Query().Equals("cloudprovider_id", cloudproviderId).Equals("cloudregion_id", cloudregionId)
	capabilities := make([]SCloudproviderCapability, 0)
	err := db.FetchModelObjects(manager, q, &capabilities)
	if err != nil {
		return nil, errors.Wrap(err, "db.FetchModelObjects")
	}
	capaStrs := make([]string, len(capabilities))
	for i := range capabilities {
		capaStrs[i] = capabilities[i].Capability
	}
	sort.Strings(capaStrs)
	return capaStrs, nil
}

func (manager *SCloudproviderCapabilityManager) removeCapabilities(ctx context.Context, userCred mcclient.TokenCredential, cloudproviderId string) error {
	return manager.removeRegionCapabilities(ctx, userCred, cloudproviderId, "")
}

func (manager *SCloudproviderCapabilityManager) removeRegionCapabilities(ctx context.Context, userCred mcclient.TokenCredential, cloudproviderId string, cloudregionId string) error {
	return manager.setRegionCapabilities(ctx, userCred, cloudproviderId, cloudregionId, []string{})
}
