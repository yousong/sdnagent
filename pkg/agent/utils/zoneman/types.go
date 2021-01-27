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

type ZoneMan interface {
	AllocateZoneId(mac string) (uint16, error)
	FreeZoneId(mac string)
}

type ZoneManOption interface{}

type baseZoneIdOption struct {
	base uint16
}

func BaseZoneIdOption(base uint16) ZoneManOption {
	return baseZoneIdOption{
		base: base,
	}
}

type sharedZoneIdOption struct {
	zoneId uint16
}

func SharedZoneIdOption(zoneId uint16) ZoneManOption {
	return sharedZoneIdOption{
		zoneId: zoneId,
	}
}

type newZoneManFunc func(...ZoneManOption) (ZoneMan, error)

var zoneMen = map[string]newZoneManFunc{
	"by_mac": newZoneManByMac,
	"shared": newZoneManShared,
}

func New(typ string, opts ...ZoneManOption) (ZoneMan, error) {
	f, ok := zoneMen[typ]
	if !ok {
		return nil, fmt.Errorf("unknown method %s", typ)
	}
	return f(opts...)
}
