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

package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/digitalocean/go-openvswitch/ovs"

	//"github.com/vishvananda/netlink"
	"yunion.io/x/log"

	"yunion.io/x/sdnagent/pkg/agent/common"
	"yunion.io/x/sdnagent/pkg/agent/utils"
)

type ovnReq struct {
	guestId string
	nics    []*utils.GuestNIC
}

type ovnMan struct {
	Ip  string // fetch from region
	Mac string // hash

	hostId    string
	guestNics map[string][]*utils.GuestNIC
	watcher   *serversWatcher
	c         chan *ovnReq
}

func newOvnMan(watcher *serversWatcher) *ovnMan {
	man := &ovnMan{
		watcher:   watcher,
		guestNics: map[string][]*utils.GuestNIC{},
		c:         make(chan *ovnReq),
	}
	return man
}

func (man *ovnMan) Start(ctx context.Context) {
	wg := ctx.Value("wg").(*sync.WaitGroup)
	defer wg.Done()

	man.init(ctx)

	cleanupTicker := time.NewTicker(WatcherRefreshRate)
	defer cleanupTicker.Stop()
	for {
		select {
		case req := <-man.c:
			man.guestNics[req.guestId] = req.nics
			man.ensureGuestFlows(ctx, req.guestId)
		case <-cleanupTicker.C:
			man.cleanup(ctx)
		case <-ctx.Done():
			log.Infof("ovn man bye")
			return
		}
	}
}

func (man *ovnMan) init(ctx context.Context) {
	//man.fetchMac(ctx) TODO
	man.ensureMappedBridge(ctx)
	man.ensureBasicFlows(ctx)
}

func (man *ovnMan) fetchIp(ctx context.Context) {
}

func (man *ovnMan) ensureMappedBridge(ctx context.Context) {
	var args []string

	args = []string{
		"ovs-vsctl",
		"--", "--may-exist", "add-br", common.OvnMappedBridge,
		"--", "set", "Bridge", common.OvnMappedBridge, fmt.Sprintf("other-config:hwaddr=%s", man.Mac),
	}

	args = []string{
		"ip", "link", "set", common.OvnMappedBridge, "up",
	}

	args = []string{
		"ip", "addr", "add", man.Mac, "dev", common.OvnMappedBridge,
	}

	args = []string{
		"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "100.64.0.0/17",
		"-m", "comment", "--comment", "sdnagent: ovn distgw",
		"-j", "MASQUERADE",
	}

	args = args
}

func (man *ovnMan) ensureBasicFlows(ctx context.Context) {
	s := fmt.Sprintf("priority=3050,in_port=LOCAL,arp,arp_op=1,arp_tpa=100.64.0.0/17,actions=move:NXM_OF_ETH_SRC->NXM_OF_ETH_DST,load:%s->NXM_OF_ETH_SRC,load:0x2->NXM_OF_ARP_OP,load:%s->NXM_NX_ARP_SHA,move:NXM_OF_ARP_TPA->NXM_OF_ARP_SPA,move:NXM_NX_ARP_SHA->NXM_NX_ARP_THA,move:NXM_OF_ARP_SPA->NXM_OF_ARP_TPA,output=in_port", man.Mac)
	s = s
}

func (man *ovnMan) ensureMappedBridgeVpcPort(ctx context.Context, vpcId string) {
	var (
		args       []string
		mine, peer = man.pnamePair(vpcId)
		ifaceId    = fmt.Sprintf("vpc-h/%s/%s", vpcId, man.hostId)
	)
	args = []string{
		"ovs-vsctl",
		"--", "--may-exist", "add-port", common.OvnMappedBridge, mine,
		"--", "set", "Interface", mine, "type=patch", fmt.Sprintf("options:peer=%s", peer),
		"--", "--may-exist", "add-port", common.OvnIntegrationBridge, peer,
		"--", "set", "Interface", peer, "type=patch", fmt.Sprintf("options:peer=%s", mine), fmt.Sprintf("external_ids:iface-id=%s", ifaceId),
	}
	args = args
}

func (man *ovnMan) pnamePair(vpcId string) (string, string) {
	var (
		mine = fmt.Sprintf("v-%s", vpcId)
		peer = fmt.Sprintf("v-%s-p", vpcId)
	)
	return mine, peer
}

func (man *ovnMan) ensureGuestFlows(ctx context.Context, guestId string) {
	var (
		nics   = man.guestNics[guestId]
		flows  []*ovs.Flow
		vpcIds map[string]bool
	)
	for _, nic := range nics {
		vpcId := nic.Vpc.Id
		if _, ok := vpcIds[vpcId]; !ok {
			vpcIds[vpcId] = true
			man.ensureMappedBridgeVpcPort(ctx, vpcId)
		}

		var (
			mine, _ = man.pnamePair(vpcId)
			pnoMine int
		)
		if psMine, err := utils.DumpPort(common.OvnMappedBridge, mine); err != nil {
			log.Errorf("ovn: dump port %s %s", common.OvnMappedBridge, mine)
			continue
		} else {
			pnoMine = psMine.PortID
		}
		flows = append(flows,
			utils.F(0, 30200,
				fmt.Sprintf("in_port=LOCAL,nw_dst=%s", nic.Vpc.MappedIpAddr),
				fmt.Sprintf("mod_dl_dst:%s,mod_nw_dst:%s,output=%d", common.OvnGatewayMac, nic.IP, pnoMine),
			),
			utils.F(0, 30100,
				fmt.Sprintf("in_port=%d,dl_src=%s,ip,nw_src=%s", pnoMine, common.OvnGatewayMac, nic.IP),
				fmt.Sprintf("mod_dl_dst:%s,mod_nw_src:%s,output=LOCAL", man.Mac, nic.Vpc.MappedIpAddr),
			),
		)
	}
}

func (man *ovnMan) SetHostId(ctx context.Context, hostId string) {
	if man.hostId == "" {
		man.hostId = hostId
		return
	}
	if man.hostId == hostId {
		return
	}
	// quit on host id change
}

func (man *ovnMan) SetGuestNICs(ctx context.Context, guestId string, nics []*utils.GuestNIC) {
	req := &ovnReq{
		guestId: guestId,
		nics:    nics,
	}
	man.c <- req
}

func (man *ovnMan) cleanup(ctx context.Context) {
	// log
	//

	for guestId, nics := range man.guestNics {
		if len(nics) == 0 {
			delete(man.guestNics, guestId)
		}
	}

	// remove unused vpc patch ports
	var vpcIds map[string]bool
	for guestId, nics := range man.guestNics {
		guestId = guestId
		for _, nic := range nics {
			vpcIds[nic.Vpc.Id] = true
		}
	}
	for {
		vpcId := ""
		if _, ok := vpcIds[vpcId]; !ok {
			// remove the port
		}
	}

	// sync flows
}

// NOTE: KEEP THIS IN SYNC WITH CODE ABOVE
//
// Flows
//
// 30200 in_port=LOCAL,nw_dst=VM_MAPPED,actions=mod_dl_dst:lr_mac,mod_nw_dst:VM_IP,output=brvpcp
// 30100 in_port=brvpcp,dl_src=lr_mac,ip,nw_src=VM_IP,actions=mod_dl_dst:man.Mac,mod_nw_src:VM_MAPPED,output=LOCAL
//
//  3050 in_port=LOCAL,arp,arp_op=1,...
//  3010 ip,nw_dst=100.64.0.0/17,actions=DROP
