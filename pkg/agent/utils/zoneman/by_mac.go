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
	"errors"
	"fmt"
	"hash/fnv"
)

type zoneManByMac struct {
	zm   map[string]uint16
	zmr  map[uint16]string
	base uint16
}

func newZoneManByMac(opts ...ZoneManOption) (ZoneMan, error) {
	for _, optI := range opts {
		switch opt := optI.(type) {
		case baseZoneIdOption:
			return &zoneManByMac{
				zm:   map[string]uint16{},
				zmr:  map[uint16]string{},
				base: opt.base,
			}, nil
		}
	}
	return nil, fmt.Errorf("no base zone id option")
}

func (zm *zoneManByMac) AllocateZoneId(mac string) (uint16, error) {
	if i, ok := zm.zm[mac]; ok {
		return zm.base + i, nil
	}
	total := (1 << 16) - uint32(zm.base)
	if len(zm.zm) >= int(total) {
		return 0, errors.New("id depleted")
	}
	h := fnv.New32()
	h.Write([]byte(mac))
	i := uint16(h.Sum32() % total)
	j := i
	for {
		if _, ok := zm.zmr[i]; !ok {
			zm.zmr[i] = mac
			zm.zm[mac] = i
			return zm.base + i, nil
		}
		i += 1
		i %= uint16(total)
		if i == j {
			break
		}
	}
	return 0, errors.New("error that never returns")
}

func (zm *zoneManByMac) allocated(mac string) bool {
	_, ok := zm.zm[mac]
	return ok
}

func (zm *zoneManByMac) FreeZoneId(mac string) {
	if i, ok := zm.zm[mac]; ok {
		delete(zm.zm, mac)
		delete(zm.zmr, i)
	}
}
