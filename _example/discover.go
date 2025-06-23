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

var probes = goflags.StringSlice{"7", "9", "13", "21", "22", "23", "25", "26", "37", "53", "79", "80", "81", "88", "106", "110", "111", "113", "119", "135", "139", "143", "144", "179", "199", "389", "427", "443", "444", "445",
	"465", "513", "514", "515", "543", "544", "548", "554", "587", "631", "646", "873", "990", "993", "995", "1025", "1026", "1026", "1027", "1028", "1029", "1110", "1433", "1720", "1723",
	"1755", "1900", "2000", "2001", "2049", "2121", "2717", "3000", "3128", "3306", "3389", "3986", "4899", "5000", "5009", "5051", "5060", "5101", "5190", "5357", "5432", "5631", "5666", "5800", "5900", "6000", "6001",
	"6646", "7070", "8000", "8008", "8009", "8080", "8081", "8443", "8888", "9100", "9999", "10000", "32768", "49152", "49153", "49154", "49155", "49156", "49157"}

func main() {
	t := time.Now()
	num := 0
	target := goflags.StringSlice{"192.168.101.92"}
	ctx := context.Background()
	options := runner.Options{
		Host: target,
		OnResult: func(hr *result.HostResult) {
			log.Println("OnResult------", hr.IP)
		},
		OnReceive: func(hostResult *result.HostResult) {
			log.Println("OnReceive------", hostResult.IP)
		},
		OnlyHostDiscovery: true,
		ScanType:          runner.SynScan,
		Ping:              true,
		//IcmpEchoRequestProbe:        true,
		//IcmpTimestampRequestProbe:   true,
		//IcmpAddressMaskRequestProbe: true,
		//ArpPing:                     true,
		//IPv6NeighborDiscoveryPing: true,
		TcpSynPingProbes: probes,
		TcpAckPingProbes: probes,
		Threads:          25,
		Rate:             200,
		Timeout:          runner.DefaultPortTimeoutSynScan,
		Retries:          3,
		Silent:           true,
		WarmUpTime:       2,
		Verify:           true,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer naabuRunner.Close()

	naabuRunner.RunEnumeration(ctx)

	fmt.Println("=============NUM", num, time.Since(t).Seconds())
}
