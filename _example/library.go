package main

import (
	"context"
	"fmt"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/runner"
	"github.com/iami317/sx/pkg/scan"
	"github.com/projectdiscovery/goflags"
	"time"
)

func main() {
	t := time.Now()
	options := &runner.Options{
		//Proxy:    "socks5://192.168.8.109:8888",
		Host: goflags.StringSlice([]string{"192.168.100.0/24"}),
		//Host:     goflags.StringSlice([]string{"192.168.100.149"}),
		ScanType: runner.SynScan,
		//ScanType: runner.ConnectScan,
		TopPorts: "1000", //100  1000 full
		//Ports: "1-65535",
		//Interface: "en0",
		//OnlyHostDiscovery: true,
		//ExcludeCDN:   true,
		//ExcludeIps:   "192.168.100.148,192.168.100.149",
		//ExcludePorts: "22",
		//IcmpEchoRequestProbe:        true,
		//IcmpTimestampRequestProbe:   true,
		//IcmpAddressMaskRequestProbe: true,
		//Ping:       true,
		//ArpPing:    false,
		Rate: 2000,
		//Threads:    1000,
		IPVersion:  []string{scan.IPv4, scan.IPv6},
		Retries:    2,
		Timeout:    1500,
		WarmUpTime: 100,
		Debug:      false,
		//Resolvers:  "tcp:114.114.114.114:53,tcp:8.8.8.8:53",
		Verbose: false,

		//OnResult: func(hostResult *result.HostResult) {
		//	if len(hostResult.Ports) > 0 {
		//		for _, port := range hostResult.Ports {
		//			fmt.Printf("***ip:%v ***host:%v ***Port:%v\n", hostResult.IP, hostResult.Host, port)
		//		}
		//
		//	}
		//},
		OnReceive: func(hostResult *result.HostResult) {
			if len(hostResult.Ports) > 0 {
				for _, port := range hostResult.Ports {
					fmt.Printf("---ip:%v ---Protocol:%v port:%v\n", hostResult.IP, port.Protocol, port.Port)
				}

			}
		},
		OnProgress: func(c, e uint64) {
			fmt.Println(c)
			fmt.Println(e)
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
	fmt.Println(time.Since(t).Seconds())
}
