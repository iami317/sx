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
	target := goflags.StringSlice{"192.168.101.92"}
	ctx := context.Background()
	options := runner.Options{
		Host: target,
		OnResult: func(hr *result.HostResult) {
			log.Println("OnResult------", hr.IP, hr.Ports)
		},
		OnReceive: func(hostResult *result.HostResult) {
			log.Println("OnReceive------", hostResult.IP, hostResult.Ports)
		},
		ScanType:   runner.SynScan,
		Threads:    25,
		Rate:       200,
		Timeout:    runner.DefaultPortTimeoutSynScan,
		Retries:    3,
		Silent:     true,
		WarmUpTime: 2,
		Verify:     true,
		Ports:      "22,443",
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer naabuRunner.Close()

	naabuRunner.RunEnumeration(ctx)

	fmt.Println("=============NUM", num, time.Since(t).Seconds())
}
