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

	//"github.com/vishvananda/netlink"
	"yunion.io/x/log"

	"yunion.io/x/sdnagent/pkg/agent/common"
	"yunion.io/x/sdnagent/pkg/agent/utils"
)

const (
	OvnMappedBridge = "brmapped"
)

type ovnReq struct {
	VpcId           string
	VpcMappedIpAddr string
	HostId          string
	NIC             GuestNIC
}

type ovnMan struct {
	HostId string

	Ip  string // fetch from region
	Mac string // hash

	vpcNics map[string]utils.GuestNIC

	watcher *serversWatcher
	c       chan ovnReq
}

func newOvnMan(watcher *serversWatcher) *ovnMan {
	man := &ovnMan{
		watcher: w,
		vpcNics: map[string]utils.GuestNIC{},
	}
	return man
}

func (man *ovnMan) Start(ctx context.Context) {
	wg := ctx.Value("wg").(*sync.WaitGroup)
	defer wg.Done()

	man.ensureMappedBridge(ctx)

	cleanupTicker := time.NewTicker(WatcherRefreshRate)
	defer cleanupTicker.Stop()
	for {
		select {
		case <-cleanupTicker.C:
			man.cleanup(ctx)
		case <-ctx.Done():
			log.Infof("ovn man bye")
			return
		}
	}
}

func (man *ovnMan) ensureMappedBridge(ctx context.Context) {
	var args []string

	args = []string{
		"ovs-vsctl",
		"--", "--may-exist", "add-br", OvnMappedBridge,
		"--", "set", "Bridge", OvnMappedBridge, fmt.Sprintf("other-config:hwaddr=%s", man.Mac),
	}

	args = []string{
		"ip", "link", "set", OvnMappedBridge, "up",
	}

	args = []string{
		"ip", "addr", "add", man.Mac, "dev", OvnMappedBridge,
	}

	args = []string{
		"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "100.64.0.0/17",
		"-m", "comment", "--comment", "sdnagent: ovn distgw",
		"-j", "MASQUERADE",
	}

	args = args
}

func (man *ovnMan) ensureMappedBridgeVpcPort(ctx context.Context, vpcId string) {
	var (
		args    []string
		mine    = fmt.Sprintf("v-%s", vpcId) // allow arbitary names?
		peer    = fmt.Sprintf("v-%s-p", vpcId)
		ifaceId = fmt.Sprintf("vpc-h/%s/%s", vpcId, man.HostId)
	)
	args = []string{
		"ovs-vsctl",
		"--", "--may-exist", "add-port", OvnMappedBridge, mine,
		"--", "set", "Interface", mine, "type=patch", fmt.Sprintf("options:peer=%s", peer),
		"--", "--may-exist", "add-port", common.OvnIntegrationBridge, peer,
		"--", "set", "Interface", peer, "type=patch", fmt.Sprintf("options:peer=%s", mine), fmt.Sprintf("external_ids:iface-id=%s", ifaceId),
	}
	args = args
}

func (man *ovnMan) ensureBasicFlow(ctx context.Context) {
	s := fmt.Sprintf("priority=3050,in_port=LOCAL,arp,arp_op=1,arp_tpa=100.64.0.0/17,actions=move:NXM_OF_ETH_SRC->NXM_OF_ETH_DST,load:%s->NXM_OF_ETH_SRC,load:0x2->NXM_OF_ARP_OP,load:%s->NXM_NX_ARP_SHA,move:NXM_OF_ARP_TPA->NXM_OF_ARP_SPA,move:NXM_NX_ARP_SHA->NXM_NX_ARP_THA,move:NXM_OF_ARP_SPA->NXM_OF_ARP_TPA,output=in_port", man.Mac)
	s = s
}

func (man *ovnMan) SetHostId(ctx context.Context, hostId string) {
	if man.HostId == "" {
		man.HostId = hostId
		return
	}
	if man.HostId == hostId {
		return
	}
	// quit on host id change
}

func (man *ovnMan) EnsureVpcNIC(ctx context.Context, nic utils.GuestNIC) {
}

func (man *ovnMan) cleanup(ctx context.Context) {
	// log removed ports
}

// when to do cleanup
//
// NOTE: KEEP THIS IN SYNC WITH CODE ABOVE
//
// Flows
//
// 30200 in_port=LOCAL,nw_dst=VM_MAPPED,actions=mod_dl_dst:lr_mac,mod_nw_dst:VM_IP,output=brvpcp
// 30100 in_port=brvpcp,dl_src=lr_mac,ip,nw_src=VM_IP,actions=mod_dl_dst:man.Mac,mod_nw_src:VM_MAPPED,output=LOCAL
//
//  3050 in_port=LOCAL,arp,arp_op=1,...
//  3010 ip,nw_dst=100.64.0.0/17,actions=DROP
