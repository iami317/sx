package main

import (
	"context"
	"github.com/iami317/logx"
	"os"
	"os/signal"
	"syscall"

	"github.com/iami317/sx/pkg/runner"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()
	sxRunner, err := runner.NewRunner(options)
	if err != nil {
		logx.Fatalf("could not create runner: %s", err)
	}

	// Setup context with cancelation
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		logx.Infof("received signal: %s, exiting gracefully...", sig)

		// Cancel context to stop ongoing tasks
		cancel()

		// Try to save resume config if needed
		if options.ResumeCfg != nil && options.ResumeCfg.ShouldSaveResume() {
			logx.Infof("creating resume file: %s", runner.DefaultResumeFilePath())
			if err := options.ResumeCfg.SaveResumeConfig(); err != nil {
				logx.Errorf("couldn't create resume file: %s", err)
			}
		}

		// Show scan result if runner is available
		if sxRunner != nil {
			sxRunner.ShowScanResultOnExit()

			if err := sxRunner.Close(); err != nil {
				logx.Errorf("couldn't close runner: %s", err)
			}
		}

		os.Exit(1)
	}()

	// Start enumeration
	if err := sxRunner.RunEnumeration(ctx); err != nil {
		logx.Fatalf("could not run enumeration: %s", err)
	}

	defer func() {
		if err := sxRunner.Close(); err != nil {
			logx.Errorf("couldn't close runner: %s", err)
		}
		// On successful execution, cleanup resume config if needed
		if options.ResumeCfg != nil {
			options.ResumeCfg.CleanupResumeConfig()
		}
	}()
}
