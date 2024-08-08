package main

import (
	"context"
	"fmt"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/runner"
	"github.com/iami317/sx/pkg/scan"
	"github.com/projectdiscovery/goflags"
)

func main() {
	options := &runner.Options{
		//Proxy:    "socks5://192.168.8.109:8888",
		Host:     goflags.StringSlice([]string{"192.168.32.149"}),
		ScanType: runner.SynScan,
		TopPorts: "full", //100  1000 full
		//Ports:             "22,8080,8084",
		Interface: "en0",
		//OnlyHostDiscovery: true,
		//ExcludeCDN:   true,
		ExcludeIps:   "",
		ExcludePorts: "",
		//IcmpEchoRequestProbe:        true,
		//IcmpTimestampRequestProbe:   true,
		//IcmpAddressMaskRequestProbe: true,
		//Ping:                        true,
		ArpPing:    false,
		Rate:       runner.DefaultRateSynScan,
		Threads:    100,
		IPVersion:  []string{scan.IPv4},
		Retries:    runner.DefaultRetriesSynScan,
		Timeout:    runner.DefaultPortTimeoutSynScan,
		WarmUpTime: 15,
		//Debug:      true,
		Verbose: true,

		OnResult: func(hostResult *result.HostResult) {
			if len(hostResult.Ports) > 0 {
				fmt.Printf("***ip:%v **** host:%v **** IsCdn:%v **** CdnName:%v *** Port:%v\n", hostResult.IP, hostResult.Host, hostResult.IsCDNIP, hostResult.CdnName, hostResult.Ports[0].String())
			}
			fmt.Printf("***ip:%v **** host:%v **** IsCdn:%v **** CdnName:%v\n", hostResult.IP, hostResult.Host, hostResult.IsCDNIP, hostResult.CdnName)
		},
		OnReceive: func(hostResult *result.HostResult) {
			if len(hostResult.Ports) > 0 {
				fmt.Printf("---ip:%v **** host:%v **** IsCdn:%v **** CdnName:%v *** Port:%v\n", hostResult.IP, hostResult.Host, hostResult.IsCDNIP, hostResult.CdnName, hostResult.Ports[0].String())
			} else {
				fmt.Printf("---ip:%v **** host:%v **** IsCdn:%v **** CdnName:%v\n", hostResult.IP, hostResult.Host, hostResult.IsCDNIP, hostResult.CdnName)
			}

		},
	}
	nbxRunner, err := runner.NewRunner(options)
	if err != nil {
		fmt.Println(err)
	}
	defer nbxRunner.Close()

	if err = nbxRunner.RunEnumeration(context.Background()); err != nil {
		fmt.Println(err)
	}
}
