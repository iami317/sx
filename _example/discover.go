package main

import (
	"context"
	"fmt"
	"github.com/iami317/sx/pkg/result"
	"log"
	"time"

	"github.com/iami317/sx/pkg/runner"
	"github.com/projectdiscovery/goflags"
)

func main() {
	t := time.Now()
	num := 0
	target := goflags.StringSlice{"192.168.101.93"}
	ctx := context.Background()
	options := runner.Options{
		Host: target,
		OnResult: func(hr *result.HostResult) {
			log.Println("OnResult------", hr.IP)
		},
		OnReceive: func(hostResult *result.HostResult) {
			log.Println("OnReceive------", hostResult.IP)
		},
		OnlyHostDiscovery:           true,
		ScanType:                    runner.SynScan,
		Ping:                        true,
		IcmpEchoRequestProbe:        true,
		IcmpTimestampRequestProbe:   true,
		IcmpAddressMaskRequestProbe: true,
		TcpSynPingProbes:            runner.Probes,
		TcpAckPingProbes:            runner.Probes,
		Threads:                     2500,
		Rate:                        25000,
		Timeout:                     time.Duration(300) * time.Millisecond,
		Retries:                     0,
		Silent:                      true,
		WarmUpTime:                  200,
		Verify:                      false,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer naabuRunner.Close()

	naabuRunner.RunEnumeration(ctx)

	fmt.Println("=============NUM", num, time.Since(t).Seconds())
}
