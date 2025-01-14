package main

import (
	"context"
	"fmt"
	"github.com/iami317/logx"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/runner"
	"github.com/iami317/sx/pkg/scan"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"os"
	"os/signal"
)

func main() {
	icmpTest()
}

func icmpTest() {
	optionsFlagSet := runner.ParseOptions()
	fmt.Println("主机发现ICMP-1，目标：", optionsFlagSet.Host)
	options := &runner.Options{
		Host:              optionsFlagSet.Host,
		OnlyHostDiscovery: true,
		Rate:              runner.DefaultRateSynScan,
		Threads:           25,
		IPVersion:         []string{scan.IPv4},
		Retries:           runner.DefaultRetriesSynScan,
		Timeout:           runner.DefaultPortTimeoutSynScan,
		WarmUpTime:        10,
		Debug:             true,
		Verbose:           false,
		//OnProgress: func(c, e uint64) {
		//	if c > 0 {
		//		progress, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(e)/float64(c)), 64)
		//		runtime.RunTimeApp.IpProgress(info.TaskHistoryId, progress)
		//	}
		//},
	}
	options.ScanType = runner.SynScan
	options.Ping = true
	options.IcmpEchoRequestProbe = true
	options.IcmpTimestampRequestProbe = true
	options.IcmpAddressMaskRequestProbe = true
	fmt.Println("IcmpEchoRequestProbe:", options.IcmpEchoRequestProbe)
	fmt.Println("IcmpTimestampRequestProbe:", options.IcmpTimestampRequestProbe)
	fmt.Println("IcmpAddressMaskRequestProbe:", options.IcmpAddressMaskRequestProbe)
	fmt.Println("ArpPing:", options.ArpPing)
	fmt.Println("TcpSynPingProbes:", options.TcpSynPingProbes)
	fmt.Println("TcpAckPingProbes:", options.TcpAckPingProbes)

	onReceive := func(hostResult *result.HostResult) {
		fmt.Println("onReceive", hostResult)

	}
	onResult := func(hostResult *result.HostResult) {
		fmt.Println("onResult", hostResult)
	}
	options.OnResult = onResult
	options.OnReceive = onReceive
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("Could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			naabuRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	err = naabuRunner.RunEnumeration(context.TODO())

	if err != nil {
		logx.Errorf("Could not run enumeration: %s", err)
	}
}

func arpTest() {
	optionsFlagSet := runner.ParseOptions()
	fmt.Println("主机发现ARP，目标：", optionsFlagSet.Host)
	options := &runner.Options{
		Host:              optionsFlagSet.Host,
		OnlyHostDiscovery: true,
		Rate:              runner.DefaultRateSynScan,
		Threads:           25,
		IPVersion:         []string{scan.IPv4},
		Retries:           runner.DefaultRetriesSynScan,
		Timeout:           runner.DefaultPortTimeoutSynScan,
		WarmUpTime:        10,
		Debug:             true,
		Verbose:           false,
		//OnProgress: func(c, e uint64) {
		//	if c > 0 {
		//		progress, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(e)/float64(c)), 64)
		//		runtime.RunTimeApp.IpProgress(info.TaskHistoryId, progress)
		//	}
		//},
	}
	options.ArpPing = true
	fmt.Println("IcmpEchoRequestProbe:", options.IcmpEchoRequestProbe)
	fmt.Println("IcmpTimestampRequestProbe:", options.IcmpTimestampRequestProbe)
	fmt.Println("IcmpAddressMaskRequestProbe:", options.IcmpAddressMaskRequestProbe)
	fmt.Println("ArpPing:", options.ArpPing)
	fmt.Println("TcpSynPingProbes:", options.TcpSynPingProbes)
	fmt.Println("TcpAckPingProbes:", options.TcpAckPingProbes)
	onReceive := func(hostResult *result.HostResult) {
		fmt.Println("onReceive", hostResult)

	}
	onResult := func(hostResult *result.HostResult) {
		fmt.Println("onResult", hostResult)
	}
	options.OnResult = onResult
	options.OnReceive = onReceive
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("Could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			naabuRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	err = naabuRunner.RunEnumeration(context.TODO())

	if err != nil {
		logx.Errorf("Could not run enumeration: %s", err)
	}
}

func tcpTest() {
	optionsFlagSet := runner.ParseOptions()
	fmt.Println("主机发现TCP，目标：", optionsFlagSet.Host)
	options := &runner.Options{
		Host:              optionsFlagSet.Host,
		OnlyHostDiscovery: true,
		Rate:              runner.DefaultRateSynScan,
		Threads:           25,
		IPVersion:         []string{scan.IPv4},
		Retries:           runner.DefaultRetriesSynScan,
		Timeout:           runner.DefaultPortTimeoutSynScan,
		WarmUpTime:        10,
		Debug:             true,
		Verbose:           false,
		//OnProgress: func(c, e uint64) {
		//	if c > 0 {
		//		progress, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(e)/float64(c)), 64)
		//		runtime.RunTimeApp.IpProgress(info.TaskHistoryId, progress)
		//	}
		//},
	}
	options.TcpSynPingProbes = []string{"80", "443"}
	fmt.Println("IcmpEchoRequestProbe:", options.IcmpEchoRequestProbe)
	fmt.Println("IcmpTimestampRequestProbe:", options.IcmpTimestampRequestProbe)
	fmt.Println("IcmpAddressMaskRequestProbe:", options.IcmpAddressMaskRequestProbe)
	fmt.Println("ArpPing:", options.ArpPing)
	fmt.Println("TcpSynPingProbes:", options.TcpSynPingProbes)
	fmt.Println("TcpAckPingProbes:", options.TcpAckPingProbes)
	onReceive := func(hostResult *result.HostResult) {
		fmt.Println("onReceive", hostResult)

	}
	onResult := func(hostResult *result.HostResult) {
		fmt.Println("onResult", hostResult)
	}
	options.OnResult = onResult
	options.OnReceive = onReceive
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("Could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			naabuRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	err = naabuRunner.RunEnumeration(context.TODO())

	if err != nil {
		logx.Errorf("Could not run enumeration: %s", err)
	}
}

//根据传参执行
//func main() {
//	options := runner.ParseOptions()
//	onReceive := func(hostResult *result.HostResult) {
//		fmt.Println("onReceive", hostResult)
//
//	}
//	onResult := func(hostResult *result.HostResult) {
//		fmt.Println("onResult", hostResult)
//	}
//	options.OnResult = onResult
//	options.OnReceive = onReceive
//	naabuRunner, err := runner.NewRunner(options)
//	if err != nil {
//		logx.Errorf("Could not create runner: %s", err)
//		return
//	}
//	// Setup graceful exits
//	c := make(chan os.Signal, 1)
//	signal.Notify(c, os.Interrupt)
//	go func() {
//		for range c {
//			naabuRunner.ShowScanResultOnExit()
//			logx.Infof("CTRL+C pressed: Exiting")
//			naabuRunner.Close()
//			os.Exit(1)
//		}
//	}()
//
//	err = naabuRunner.RunEnumeration(context.TODO())
//
//	if err != nil {
//		logx.Errorf("Could not run enumeration: %s", err)
//	}
//}
