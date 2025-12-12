package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/iami317/sx/pkg/runner"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()
	sxRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("could not create runner: %s\n", err)
	}

	// Setup context with cancelation
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		gologger.Info().Msgf("received signal: %s, exiting gracefully...\n", sig)

		// Cancel context to stop ongoing tasks
		cancel()

		// Try to save resume config if needed
		if options.ResumeCfg != nil && options.ResumeCfg.ShouldSaveResume() {
			gologger.Info().Msgf("creating resume file: %s\n", runner.DefaultResumeFilePath())
			if err := options.ResumeCfg.SaveResumeConfig(); err != nil {
				gologger.Error().Msgf("couldn't create resume file: %s\n", err)
			}
		}

		// Show scan result if runner is available
		if sxRunner != nil {
			sxRunner.ShowScanResultOnExit()

			if err := sxRunner.Close(); err != nil {
				gologger.Error().Msgf("couldn't close runner: %s\n", err)
			}
		}

		// Final flush if gologger has a Close method (placeholder if exists)
		// Example: gologger.Close()

		os.Exit(1)
	}()

	// Start enumeration
	if err := sxRunner.RunEnumeration(ctx); err != nil {
		gologger.Fatal().Msgf("could not run enumeration: %s\n", err)
	}

	defer func() {
		if err := sxRunner.Close(); err != nil {
			gologger.Error().Msgf("Couldn't close runner: %s\n", err)
		}
		// On successful execution, cleanup resume config if needed
		if options.ResumeCfg != nil {
			options.ResumeCfg.CleanupResumeConfig()
		}
	}()
}
