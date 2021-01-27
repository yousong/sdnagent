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

package zoneman

import (
	"fmt"
)

type zoneManShared struct {
	zoneId uint16
}

func newZoneManShared(opts ...ZoneManOption) (ZoneMan, error) {
	for _, optI := range opts {
		switch opt := optI.(type) {
		case sharedZoneIdOption:
			return &zoneManShared{
				zoneId: opt.zoneId,
			}, nil
		}
	}
	return nil, fmt.Errorf("no shared zone id option")
}

func (zm *zoneManShared) AllocateZoneId(mac string) (uint16, error) {
	return zm.zoneId, nil
}

func (zm *zoneManShared) FreeZoneId(mac string) {
}
