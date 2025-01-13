package main

import (
	"context"
	"fmt"
	"github.com/iami317/logx"
	"github.com/iami317/sx/pkg/result"
	"os"
	"os/signal"

	"github.com/iami317/sx/pkg/runner"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
)

func main() {
	options := runner.ParseOptions()
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
