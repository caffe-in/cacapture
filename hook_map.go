package main

import (
	"bytes"
	"cacapture/assets"
	"fmt"
	"math"
	"net"
	"runtime"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func AttachEbpfMap(containerID string, ifname string, bpfFileName string) (networkMapID, skbEventMapID uint32, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	nsHandle, err := netns.GetFromDocker(containerID)
	if err != nil {
		panic(err)
	}
	fmt.Println(nsHandle)
	defer nsHandle.Close()

	var probe_egress = &manager.Probe{
		Section:          "classifier/egress",
		EbpfFuncName:     "egress_cls_func",
		Ifname:           ifname,
		NetworkDirection: manager.Egress,
	}
	var probe_ingress = &manager.Probe{
		Section:          "classifier/ingress",
		EbpfFuncName:     "ingress_cls_func",
		Ifname:           ifname,
		NetworkDirection: manager.Ingress,
	}
	var bpfManager = &manager.Manager{
		Probes: []*manager.Probe{probe_egress, probe_ingress},
		Maps: []*manager.Map{
			{
				Name: "skb_events",
			},
		},
	}
	var bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		fmt.Printf("couldn't find asset %v", err)
	}
	netInf, _ := net.Interfaces()
	for _, v := range netInf {
		fmt.Println(v.Name)
	}
	err = netns.Set(nsHandle)
	if err != nil {
		panic(err)
	}

	if err = bpfManager.InitWithOptions(bytes.NewReader(byteBuf), bpfManagerOptions); err != nil {
		fmt.Printf("couldn't init manager %v", err)
	}
	if err = bpfManager.Start(); err != nil {
		fmt.Printf("couldn't start bootstrap manager %v .", err)
	}

	networkMap, found, err := bpfManager.GetMap("network_map")
	if !found {
		return 0, 0, fmt.Errorf("network_map not found")
	}
	networkMapInfo, err := networkMap.Info()
	if err != nil {
		return 0, 0, fmt.Errorf("network_map info err %v", err)
	}
	nnetworkMapID, found := networkMapInfo.ID()
	if !found {
		return 0, 0, fmt.Errorf("network_map id not found")
	}

	skbEventsMap, found, err := bpfManager.GetMap("skb_events")
	if !found {
		return 0, 0, fmt.Errorf("skb_events map not found")
	}
	skbEventMapInfo, err := skbEventsMap.Info()
	if err != nil {
		return 0, 0, fmt.Errorf("skb_events map info err %v", err)
	}
	sskbEventsMapID, found := skbEventMapInfo.ID()

	if !found {
		return 0, 0, fmt.Errorf("skb_events map id not found")
	}

	return uint32(nnetworkMapID), uint32(sskbEventsMapID), nil

}
