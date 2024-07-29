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
	host := []string{
		"59.82.12.138",
		"59.82.37.30",
		"59.82.14.215",
		"59.82.15.82",
		"59.82.44.41",
		"59.82.9.177",
		"118.187.65.194",
		"59.82.44.168",
		"47.92.99.162",
		"59.82.9.180",
		"59.82.8.66",
		"59.82.14.249",
		"59.82.9.179",
		"203.93.127.226",
		"59.82.8.65",
		"113.113.82.105",
		"59.82.9.178",
		"59.82.13.252",
		"59.82.44.105",
		"59.82.34.190",
	}
	options := &runner.Options{
		//Proxy:    "socks5://192.168.8.109:8888",
		Host:     goflags.StringSlice(host),
		ScanType: runner.ConnectScan,
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
		Retries:    1, //runner.DefaultRetriesSynScan,
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
		OnProgress: func(c, e uint64) {
			//fmt.Printf("需要探测目标总数：%v,发包数量：%v\n", c, e)
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
