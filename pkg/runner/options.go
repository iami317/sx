package runner

import (
	"github.com/iami317/logx"
	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/scan"
	"os"

	"github.com/projectdiscovery/goflags"
)

// Options contains the configuration options for tuning
// the port enumeration process.
// nolint:maligned // just an option structure
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	JSON           bool // JSON specifies whether to use json for output format or text file
	Silent         bool // Silent suppresses any extra text and only writes found host:port to screen
	Verify         bool // Verify is used to check if the ports found were valid using CONNECT method
	Ping           bool // Ping uses ping probes to discover fastest active host and discover dead hosts
	Debug          bool // Prints out debug information
	ExcludeCDN     bool // Excludes ip of knows CDN ranges for full port scan
	InterfacesList bool // InterfacesList show interfaces list

	Retries       int                 // Retries is the number of retries for the port
	Rate          int                 // Rate is the rate of port scan requests
	Timeout       int                 // Timeout is the seconds to wait for ports to respond
	WarmUpTime    int                 // WarmUpTime between scan phases
	Host          goflags.StringSlice // Host is the single host or comma-separated list of hosts to find ports for
	Ports         string              // Ports is the ports to use for enumeration
	ExcludePorts  string              // ExcludePorts is the list of ports to exclude from enumeration
	ExcludeIps    string              // Ips or cidr to be excluded from the scan
	TopPorts      string              // Tops ports to scan
	PortThreshold int                 // PortThreshold is the number of ports to find before skipping the host
	SourceIP      string              // SourceIP to use in TCP packets
	SourcePort    string              // Source Port to use in packets
	Interface     string              // Interface to use for TCP packets
	Threads       int                 // Internal worker threads
	ScanAllIPS    bool                // Scan all the ips
	IPVersion     goflags.StringSlice // IP Version to use while resolving hostnames
	ScanType      string              // Scan Type
	Proxy         string              // Socks5 proxy
	ProxyAuth     string              // Socks5 proxy authentication (username:password)
	Resolvers     string              // Resolvers (comma separated or file)
	baseResolvers []string
	OnResult      result.ResultFn // callback on final host result
	OnReceive     result.ResultFn // callback on response receive
	//OnProgress        result.ProgressFn
	Stream            bool
	Passive           bool
	OutputCDN         bool // display cdn in use
	OnlyHostDiscovery bool // Perform only host discovery
	SkipHostDiscovery bool // Skip host discovery
	TcpSynPingProbes  goflags.StringSlice
	TcpAckPingProbes  goflags.StringSlice
	// UdpPingProbes               goflags.StringSlice - planned
	// STcpInitPingProbes          goflags.StringSlice - planned
	IcmpEchoRequestProbe        bool
	IcmpTimestampRequestProbe   bool
	IcmpAddressMaskRequestProbe bool
	// IpProtocolPingProbes        goflags.StringSlice - planned
	ArpPing                   bool
	IPv6NeighborDiscoveryPing bool
	// HostDiscoveryIgnoreRST      bool - planned
	// ReversePTR lookup for ips
	ReversePTR bool
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`a port scanning tool written in Go that allows you to enumerate open ports for hosts in a fast and reliable manner.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Host, "host", "", nil, "hosts to scan ports for (comma-separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "hosts to exclude from the scan (comma-separated)"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "top ports to scan (default 100) [full,100,1000]"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "ports to exclude from scan (comma-separated)"),
		flagSet.IntVarP(&options.PortThreshold, "pts", "port-threshold", 0, "port threshold to skip port scan for the host"),
		flagSet.BoolVarP(&options.ExcludeCDN, "ec", "exclude-cdn", false, "skip full port scans for CDN/WAF (only scan for port 80,443)"),
		flagSet.BoolVarP(&options.OutputCDN, "cdn", "display-cdn", false, "display cdn in use"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "general internal worker threads"),
		flagSet.IntVar(&options.Rate, "rate", DefaultRateSynScan, "packets to send per second"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "write output in JSON lines format"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.BoolVarP(&options.ScanAllIPS, "sa", "scan-all-ips", false, "scan all the IP's associated with DNS record"),
		flagSet.StringSliceVarP(&options.IPVersion, "iv", "ip-version", []string{scan.IPv4}, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", SynScan, "type of port scan (SYN/CONNECT)"),
		flagSet.StringVar(&options.SourceIP, "source-ip", "", "source ip and port (x.x.x.x:yyy)"),
		flagSet.BoolVarP(&options.InterfacesList, "il", "interface-list", false, "list available interfaces and public ip"),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "network Interface to use for port scan"),
		flagSet.StringVar(&options.Resolvers, "r", "", "list of custom resolver dns resolution (comma separated or from file)"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "socks5 proxy (ip[:port] / fqdn[:port]"),
		flagSet.StringVar(&options.ProxyAuth, "proxy-auth", "", "socks5 proxy authentication (username:password)"),
		flagSet.BoolVar(&options.Stream, "stream", false, "stream mode (disables resume, nmap, verify, retries, shuffling, etc)"),
		flagSet.BoolVar(&options.Passive, "passive", false, "display passive open ports using shodan internetdb api"),
	)

	flagSet.CreateGroup("host-discovery", "Host-Discovery",
		flagSet.BoolVarP(&options.OnlyHostDiscovery, "host-discovery", "sn", false, "Perform Only Host Discovery"),
		flagSet.BoolVarP(&options.SkipHostDiscovery, "skip-host-discovery", "Pn", false, "Skip Host discovery"),
		flagSet.StringSliceVarP(&options.TcpSynPingProbes, "probe-tcp-syn", "ps", nil, "TCP SYN Ping (host discovery needs to be enabled)", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.TcpAckPingProbes, "probe-tcp-ack", "pa", nil, "TCP ACK Ping (host discovery needs to be enabled)", goflags.StringSliceOptions),
		flagSet.BoolVarP(&options.IcmpEchoRequestProbe, "probe-icmp-echo", "pe", false, "ICMP echo request Ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.IcmpTimestampRequestProbe, "probe-icmp-timestamp", "pp", false, "ICMP timestamp request Ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.IcmpAddressMaskRequestProbe, "probe-icmp-address-mask", "pm", false, "ICMP address mask request Ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.ArpPing, "arp-ping", "arp", false, "ARP ping (host discovery needs to be enabled)"),
		flagSet.BoolVarP(&options.IPv6NeighborDiscoveryPing, "nd-ping", "nd", false, "IPv6 Neighbor Discovery (host discovery needs to be enabled)"),
		flagSet.BoolVar(&options.ReversePTR, "rev-ptr", false, "Reverse PTR lookup for input ips"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "number of retries for the port scan"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "millisecond to wait before timing out"),
		flagSet.IntVar(&options.WarmUpTime, "warm-up-time", 2, "time in seconds between scan phases"),
		flagSet.BoolVar(&options.Ping, "ping", false, "ping probes for verification of host"),
		flagSet.BoolVar(&options.Verify, "verify", false, "validate the ports again with TCP verification"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "display debugging information"),
		flagSet.BoolVarP(&options.Verbose, "v", "verbose", false, "display verbose output"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display only results in output"),
	)

	_ = flagSet.Parse()

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := showNetworkInterfaces()
		if err != nil {
			logx.Errorf("Could not get network interfaces: %s", err)
		}
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.ValidateOptions()
	if err != nil {
		logx.Fatalf("Program exiting: %s", err)
	}

	return options
}

func (options *Options) shouldDiscoverHosts() bool {
	return (options.OnlyHostDiscovery || !options.SkipHostDiscovery) && !options.Passive
}

func (options *Options) hasProbes() bool {
	return options.ArpPing || options.IPv6NeighborDiscoveryPing || options.IcmpAddressMaskRequestProbe ||
		options.IcmpEchoRequestProbe || options.IcmpTimestampRequestProbe || len(options.TcpAckPingProbes) > 0 ||
		len(options.TcpAckPingProbes) > 0
}

func (options *Options) shouldUseRawPackets() bool {
	return isOSSupported() && privileges.IsPrivileged && options.ScanType == SynScan
}
