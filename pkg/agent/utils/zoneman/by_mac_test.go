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

import "testing"
import (
	"fmt"
)

func TestByMac(t *testing.T) {
	base := 1000
	start := 382
	end := 0x10000 + 382 - base
	man, err := New("by_mac", BaseZoneIdOption(uint16(base)))
	if err != nil {
		t.Fatalf("new zone: %v", err)
	}
	mm := map[uint16]string{}
	for i := start; i < end; i++ {
		m := fmt.Sprintf("%d", i)
		j, err := man.AllocateZoneId(m)
		if err != nil {
			t.Errorf("err: %s", err)
			return
		}
		if om, ok := mm[j]; ok {
			t.Errorf("err: dup id %d from %s, %s", j, m, om)
			return
		}
		mm[j] = m
	}
	j, err := man.AllocateZoneId("xxoo")
	if err == nil {
		t.Errorf("should exhausted, got %d", j)
		return
	}
	manByMac := man.(*zoneManByMac)
	for i := start; i < end; i++ {
		m := fmt.Sprintf("%d", i)
		if !manByMac.allocated(m) {
			t.Errorf("should be there: %s", m)
			return
		}
		man.FreeZoneId(m)
		if manByMac.allocated(m) {
			t.Errorf("should not be there: %s", m)
			return
		}
	}
}
