package main

import (
	"context"
	"fmt"
	"github.com/iami317/logx"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/runner"
	"github.com/iami317/sx/pkg/scan"
	"os"
	"os/signal"
	"strings"
)

//func main() {
//	icmpTest()
//}

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
	sxRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("Could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			sxRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			sxRunner.Close()
			os.Exit(1)
		}
	}()

	err = sxRunner.RunEnumeration(context.TODO())

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
	sxRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("Could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			sxRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			sxRunner.Close()
			os.Exit(1)
		}
	}()

	err = sxRunner.RunEnumeration(context.TODO())

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
	sxRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("Could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			sxRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			sxRunner.Close()
			os.Exit(1)
		}
	}()

	err = sxRunner.RunEnumeration(context.TODO())

	if err != nil {
		logx.Errorf("Could not run enumeration: %s", err)
	}
}

// 根据传参执行
func main() {
	options := runner.ParseOptions()
	onReceive := func(hostResult *result.HostResult) {
		fmt.Printf("onReceive:%+v", hostResult)
		fmt.Println()

	}
	onResult := func(hostResult *result.HostResult) {
		fmt.Printf("onResult:%+v", hostResult)
	}
	options.OnResult = onResult
	options.OnReceive = onReceive
	//options.OnProgress = func(c, f uint64) {
	//	PrintProgress(c, f)
	//}
	options.Rate = 10000
	sxRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Errorf("could not create runner: %s", err)
		return
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			sxRunner.ShowScanResultOnExit()
			logx.Infof("CTRL+C pressed: Exiting")
			sxRunner.Close()
			os.Exit(1)
		}
	}()

	err = sxRunner.RunEnumeration(context.TODO())

	if err != nil {
		logx.Errorf("Could not run enumeration: %s", err)
	}
}

// 动态打印进度条
func PrintProgress(current, total uint64) {
	percent := float64(current) / float64(total) * 100
	barWidth := 50
	filledWidth := int(percent / 100 * float64(barWidth))
	emptyWidth := barWidth - filledWidth

	bar := strings.Repeat("█", filledWidth) + strings.Repeat(" ", emptyWidth)
	fmt.Printf("\r进度: [%s] %.1f%% (%d/%d)", bar, percent, current, total)
}
