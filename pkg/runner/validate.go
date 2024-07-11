package runner

import (
	"flag"
	"fmt"
	"github.com/iami317/logx"
	"net"
	"strings"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/scan"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	osutil "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var (
	errNoInputList = errors.New("no input list provided")
	errOutputMode  = errors.New("both verbose and silent mode specified")
	errZeroValue   = errors.New("cannot be zero")
)

// ValidateOptions validates the configuration options passed
func (options *Options) ValidateOptions() error {
	// Check if Host, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if options.Host == nil && len(flag.Args()) == 0 {
		return errNoInputList
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errOutputMode
	}

	if options.Timeout == 0 {
		return errors.Wrap(errZeroValue, "timeout")
	} else if !privileges.IsPrivileged && options.Timeout == DefaultPortTimeoutSynScan {
		options.Timeout = DefaultPortTimeoutConnectScan
	}

	if options.Rate == 0 {
		return errors.Wrap(errZeroValue, "rate")
	} else if !privileges.IsPrivileged && options.Rate == DefaultRateSynScan {
		options.Rate = DefaultRateConnectScan
	}

	if !privileges.IsPrivileged && options.Retries == DefaultRetriesSynScan {
		options.Retries = DefaultRetriesConnectScan
	}

	if options.Interface != "" {
		if _, err := net.InterfaceByName(options.Interface); err != nil {
			return fmt.Errorf("interface %s not found", options.Interface)
		}
	}

	if fileutil.FileExists(options.Resolvers) {
		chanResolvers, err := fileutil.ReadFile(options.Resolvers)
		if err != nil {
			return err
		}
		for resolver := range chanResolvers {
			options.baseResolvers = append(options.baseResolvers, resolver)
		}
	} else if options.Resolvers != "" {
		for _, resolver := range strings.Split(options.Resolvers, ",") {
			options.baseResolvers = append(options.baseResolvers, strings.TrimSpace(resolver))
		}
	}

	// passive mode enables automatically stream
	if options.Passive {
		options.Stream = true
	}

	// stream passive
	if options.Verify && options.Stream && !options.Passive {
		return errors.New("verify not supported in stream active mode")
	}

	// Parse and validate source ip and source port
	// checks if source ip is ip only
	isOnlyIP := iputil.IsIP(options.SourceIP)
	if options.SourceIP != "" && !isOnlyIP {
		ip, port, err := net.SplitHostPort(options.SourceIP)
		if err != nil {
			return err
		}
		options.SourceIP = ip
		options.SourcePort = port
	}

	if len(options.IPVersion) > 0 && !sliceutil.ContainsItems([]string{scan.IPv4, scan.IPv6}, options.IPVersion) {
		return errors.New("IP Version must be 4 and/or 6")
	}
	// Return error if any host discovery releated option is provided but host discovery is disabled
	if options.SkipHostDiscovery && options.hasProbes() {
		return errors.New("discovery probes were provided but host discovery is disabled")
	}

	// Host Discovery mode needs provileged access
	if options.OnlyHostDiscovery && !privileges.IsPrivileged {
		if osutil.IsWindows() {
			return errors.New("host discovery not (yet) supported on windows")
		}
		return errors.New("sudo access required to perform host discovery")
	}

	if options.PortThreshold < 0 || options.PortThreshold > 65535 {
		return errors.New("port threshold must be between 0 and 65535")
	}

	if options.Proxy != "" && options.ScanType == SynScan {
		logx.Warnf("Syn Scan can't be used with socks proxy: falling back to connect scan")
		options.ScanType = ConnectScan
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	if options.Verbose {
		logx.SetLevel("verbose")
	}
	if options.Debug {
		logx.SetLevel("debug")
	}

	if options.Silent {
		logx.SetLevel("silent")
	}
}

// ConfigureHostDiscovery enables default probes if none is specified
// but host discovery option was requested
func (options *Options) configureHostDiscovery() {
	if options.shouldDiscoverHosts() && !options.hasProbes() {
		// if no options were defined enable
		// - ICMP Echo Request
		// - ICMP timestamp
		// - TCP SYN on port 80
		// - TCP SYN on port 443
		// - TCP ACK on port 80
		// - TCP ACK on port 443
		options.IcmpEchoRequestProbe = true
		options.IcmpTimestampRequestProbe = true
		options.TcpSynPingProbes = append(options.TcpSynPingProbes, "80")
		options.TcpSynPingProbes = append(options.TcpSynPingProbes, "443")
		options.TcpAckPingProbes = append(options.TcpAckPingProbes, "80")
		options.TcpAckPingProbes = append(options.TcpAckPingProbes, "443")
	}
}
