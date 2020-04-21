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
	"os/exec"
	"strings"
	"sync"
	"time"

	"crypto/md5"

	"github.com/coreos/go-iptables/iptables"
	"github.com/digitalocean/go-openvswitch/ovs"

	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"

	apis "yunion.io/x/onecloud/pkg/apis/compute"
	//"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/mcclient/auth"
	mcclient_modules "yunion.io/x/onecloud/pkg/mcclient/modules"
	"yunion.io/x/onecloud/pkg/util/iproute2"

	"yunion.io/x/sdnagent/pkg/agent/common"
	"yunion.io/x/sdnagent/pkg/agent/utils"
)

// TODO
func hashMac(in ...string) string {
	h := md5.New()
	for _, s := range in {
		h.Write([]byte(s))
	}
	sum := h.Sum(nil)
	b := sum[0]
	b &= 0xfe
	b |= 0x02
	mac := fmt.Sprintf("%02x", b)
	for _, b := range sum[1:6] {
		mac += fmt.Sprintf(":%02x", b)
	}
	return mac
}

type ovnReq struct {
	guestId string
	nics    []*utils.GuestNIC
}

type ovnMan struct {
	hostId string
	ip     string // fetch from region
	mac    string // hash

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

	refreshTicker := time.NewTicker(WatcherRefreshRate)
	defer refreshTicker.Stop()
	for {
		select {
		case req := <-man.c:
			man.guestNics[req.guestId] = req.nics
			man.ensureGuestFlows(ctx, req.guestId)
		case <-refreshTicker.C:
			man.cleanup(ctx)
			man.refresh(ctx)
		case <-ctx.Done():
			log.Infof("ovn man bye")
			return
		}
	}
}

func (man *ovnMan) setIpMac(ctx context.Context) error {
	man.mac = hashMac(man.hostId)
	{
		hc := man.watcher.hostConfig
		apiVer := ""
		s := auth.GetAdminSession(ctx, hc.Region, apiVer)
		obj, err := mcclient_modules.Hosts.Get(s, man.hostId, nil)
		if err != nil {
			return errors.Wrapf(err, "GET host %s", man.hostId)
		}
		man.ip, _ = obj.GetString("ovn_mapped_ip_addr")
		if man.ip == "" {
			return errors.Errorf("Host %s has no mapped addr", man.hostId)
		}
	}

	if err := man.ensureMappedBridge(ctx); err != nil {
		return err
	}
	man.ensureBasicFlows(ctx)
	return nil
}

func (man *ovnMan) ensureMappedBridge(ctx context.Context) error {
	{
		args := []string{
			"ovs-vsctl",
			"--", "--may-exist", "add-br", common.OvnMappedBridge,
			"--", "set", "Bridge", common.OvnMappedBridge, fmt.Sprintf("other-config:hwaddr=%s", man.mac),
		}
		if err := man.exec(ctx, args); err != nil {
			return errors.Wrap(err, "ovn: ensure mapped bridge")
		}
	}

	if err := iproute2.NewLink(common.OvnMappedBridge).Up().Err(); err != nil {
		return errors.Wrapf(err, "ovn: set link %s up", common.OvnMappedBridge)
	}

	if err := iproute2.NewAddress(common.OvnMappedBridge, man.ip).Exact().Err(); err != nil {
		return errors.Wrapf(err, "ovn: set %s address %s", common.OvnMappedBridge, man.ip)
	}

	{
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return err
		}
		var (
			p    = apis.VpcMappedCidr()
			tbl  = "nat"
			chn  = "POSTROUTING"
			spec = []string{
				"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", p.String(),
				"-m", "comment", "--comment", "sdnagent: ovn distgw",
				"-j", "MASQUERADE",
			}
		)
		if err := ipt.AppendUnique(tbl, chn, spec...); err != nil {
			return errors.Wrapf(err, "ovn: append POSTROUTING masq rule")
		}
	}
	return nil
}

func (man *ovnMan) ensureBasicFlows(ctx context.Context) {
	var (
		p       = apis.VpcMappedCidr()
		actions = []string{
			"move:NXM_OF_ETH_SRC->NXM_OF_ETH_DST",
			fmt.Sprintf("load:%s->NXM_OF_ETH_SRC", man.mac),
			"load:0x2->NXM_OF_ARP_OP",
			fmt.Sprintf("load:%s->NXM_NX_ARP_SHA", man.mac),
			"move:NXM_OF_ARP_TPA->NXM_OF_ARP_SPA",
			"move:NXM_NX_ARP_SHA->NXM_NX_ARP_THA",
			"move:NXM_OF_ARP_SPA->NXM_OF_ARP_TPA",
			"output=in_port",
		}
	)
	flows := []*ovs.Flow{
		utils.F(3050, 0,
			fmt.Sprintf("in_port=LOCAL,arp,arp_op=1,arp_tpa=%s", p.String()),
			strings.Join(actions, ",")),
		utils.F(3010, 0,
			fmt.Sprintf("ip,nw_dst=%s", p.String()),
			"drop"),
	}
	flowman := man.watcher.agent.GetFlowMan(common.OvnMappedBridge)
	flowman.updateFlows(ctx, "o", flows)
}

func (man *ovnMan) ensureMappedBridgeVpcPort(ctx context.Context, vpcId string) error {
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
	if err := man.exec(ctx, args); err != nil {
		return errors.Wrapf(err, "ovn: ensure port: vpc %s", vpcId)
	}
	return nil
}

func (man *ovnMan) exec(ctx context.Context, args []string) error {
	if len(args) == 0 {
		panic("exec: empty args")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	_, err := cmd.Output()
	if err != nil {
		s := ""
		for _, arg := range args {
			if arg != "--" {
				s += " " + arg
			} else {
				s += "\n  " + arg
			}
		}
		err = errors.Wrap(err, s)
		return err
	}
	return nil
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
			if err := man.ensureMappedBridgeVpcPort(ctx, vpcId); err != nil {
				log.Errorln(err)
				continue
			}
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
				fmt.Sprintf("mod_dl_dst:%s,mod_nw_src:%s,output=LOCAL", man.mac, nic.Vpc.MappedIpAddr),
			),
		)
	}
	flowman := man.watcher.agent.GetFlowMan(common.OvnMappedBridge)
	flowman.updateFlows(ctx, guestId, flows)
}

func (man *ovnMan) SetHostId(ctx context.Context, hostId string) {
	if man.hostId == "" {
		man.hostId = hostId
		man.setIpMac(ctx)
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
		break
	}
}

func (man *ovnMan) refresh(ctx context.Context) {
}

// NOTE: KEEP THIS IN SYNC WITH CODE ABOVE
//
// Flows
//
// 30200 in_port=LOCAL,nw_dst=VM_MAPPED,actions=mod_dl_dst:lr_mac,mod_nw_dst:VM_IP,output=brvpcp
// 30100 in_port=brvpcp,dl_src=lr_mac,ip,nw_src=VM_IP,actions=mod_dl_dst:man.mac,mod_nw_src:VM_MAPPED,output=LOCAL
//
//  3050 in_port=LOCAL,arp,arp_op=1,...
//  3010 ip,nw_dst=100.64.0.0/17,actions=drop
