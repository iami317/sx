package runner

import (
	"fmt"
	"os"
	"time"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/scan"
	"github.com/projectdiscovery/networkpolicy"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/projectdiscovery/utils/structs"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
// nolint:maligned // just an option structure
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	JSON           bool // JSON specifies whether to use json for output format or text file
	Silent         bool // Silent suppresses any extra text and only writes found host:port to screen
	Stdin          bool // Stdin specifies whether stdin input was given to the process
	Verify         bool // Verify is used to check if the ports found were valid using CONNECT method
	Ping           bool // Ping uses ping probes to discover fastest active host and discover dead hosts
	Debug          bool // Prints out debug information
	ExcludeCDN     bool // Excludes ip of knows CDN ranges for full port scan
	InterfacesList bool // InterfacesList show interfaces list

	Retries int // Retries is the number of retries for the port
	Rate    int // Rate is the rate of port scan requests
	// Timeout        int                 // Timeout is the milliseconds to wait for ports to respond
	Timeout             time.Duration
	WarmUpTime          int                 // WarmUpTime between scan phases
	Host                goflags.StringSlice // Host is the single host or comma-separated list of hosts to find ports for
	HostsFile           string              // HostsFile is the file containing list of hosts to find port for
	Output              string              // Output is the file to write found ports to.
	ListOutputFields    bool                // OutputFields is the list of fields to output (comma separated)
	ExcludeOutputFields goflags.StringSlice // ExcludeOutputFields is the list of fields to exclude from the output
	Ports               string              // Ports is the ports to use for enumeration
	PortsFile           goflags.StringSlice // PortsFile is the file containing ports to use for enumeration
	ExcludePorts        goflags.StringSlice // ExcludePorts is the list of ports to exclude from enumeration
	ExcludeIps          string              // Ips or cidr to be excluded from the scan
	ExcludeIpsFile      string              // File containing Ips or cidr to exclude from the scan
	TopPorts            string              // Tops ports to scan
	PortThreshold       int                 // PortThreshold is the number of ports to find before skipping the host
	SourceIP            string              // SourceIP to use in TCP packets
	SourcePort          string              // Source Port to use in packets
	Interface           string              // Interface to use for TCP packets
	ConfigFile          string              // Config file contains a scan configuration
	Threads             int                 // Internal worker threads
	// Deprecated: stats are automatically available through local endpoint (maybe used on cloud?)
	StatsInterval               int                 // StatsInterval is the number of seconds to display stats after
	ScanAllIPS                  bool                // Scan all the ips
	IPVersion                   goflags.StringSlice // IP Version to use while resolving hostnames
	ScanType                    string              // Scan Type
	ConnectPayload              string              // Payload to use with CONNECT scan types
	Proxy                       string              // Socks5 proxy
	ProxyAuth                   string              // Socks5 proxy authentication (username:password)
	Resolvers                   string              // Resolvers (comma separated or file)
	baseResolvers               []string
	OnResult                    result.ResultFn // callback on final host result
	OnReceive                   result.ResultFn // callback on response receive
	CSV                         bool
	Resume                      bool
	ResumeCfg                   *ResumeCfg
	OutputCDN                   bool // display cdn in use
	OnlyHostDiscovery           bool // Perform only host discovery
	WithHostDiscovery           bool // Enable Host discovery
	TcpSynPingProbes            goflags.StringSlice
	TcpAckPingProbes            goflags.StringSlice
	IcmpEchoRequestProbe        bool
	IcmpTimestampRequestProbe   bool
	IcmpAddressMaskRequestProbe bool
	// IpProtocolPingProbes        goflags.StringSlice - planned
	ArpPing                   bool
	IPv6NeighborDiscoveryPing bool
	// HostDiscoveryIgnoreRST      bool - planned
	InputReadTimeout time.Duration
	DisableStdin     bool
	// ReversePTR lookup for ips
	ReversePTR bool

	NetworkPolicyOptions *networkpolicy.Options
	// AssetUpload for projectdiscovery cloud
	AssetUpload bool
	OnClose     func()
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`sx是一个用Go语言编写的端口扫描工具，可以快速、可靠地枚举主机开放的端口。`)

	flagSet.CreateGroup("input", "输入",
		flagSet.StringSliceVarP(&options.Host, "host", "", nil, "要扫描端口的主机(以逗号分隔)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.HostsFile, "l", "list", "", "扫描端口的主机列表(文件)"),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "要从扫描中排除的主机(以逗号分隔)"),
		flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "要从扫描中排除的主机列表(文件)"),
	)

	flagSet.CreateGroup("port", "端口",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "要扫描的端口,示例:80,443,100-200"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "扫描的主要端口(默认100)[full,100,1000]"),
		flagSet.StringSliceVarP(&options.ExcludePorts, "ep", "exclude-ports", nil, "扫描中排除的端口(文件或逗号分隔)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.PortsFile, "pf", "ports-file", nil, "包含要扫描的端口列表文件(逗号分隔)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.IntVarP(&options.PortThreshold, "pts", "port-threshold", 0, "跳过主机端口扫描的端口阈值"),
		flagSet.BoolVarP(&options.ExcludeCDN, "ec", "exclude-cdn", false, "对CDN/WAF跳过全端口扫描 (只扫描80,443)"),
		flagSet.BoolVarP(&options.OutputCDN, "cdn", "display-cdn", false, "显示探测到的CDN"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "运行线程数量"),
		flagSet.IntVar(&options.Rate, "rate", DefaultRateSynScan, "每秒发送数据包数量"),
	)

	flagSet.CreateGroup("output", "输出",
		flagSet.StringVarP(&options.Output, "output", "o", "", "将输出写入指定文件(可选)"),
		flagSet.BoolVarP(&options.ListOutputFields, "list-output-fields", "lof", false, "要输出的字段列表(逗号分隔)"),
		flagSet.StringSliceVarP(&options.ExcludeOutputFields, "exclude-output-fields", "eof", nil, "根据条件排除输出字段", goflags.NormalizedOriginalStringSliceOptions),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "输出json格式"),
		flagSet.BoolVar(&options.CSV, "csv", false, "输出csv格式"),
	)

	flagSet.CreateGroup("config", "配置",
		flagSet.StringVar(&cfgFile, "config", "", "配置文件的路径 (默认:$HOME/.config/sx/config.yaml)"),
		flagSet.BoolVarP(&options.ScanAllIPS, "sa", "scan-all-ips", false, "扫描与DNS记录相关的所有IP"),
		flagSet.StringSliceVarP(&options.IPVersion, "iv", "ip-version", []string{scan.IPv4}, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", ConnectScan, "端口扫描类型 (SYN/CONNECT)"),
		flagSet.StringVar(&options.SourceIP, "source-ip", "", "源ip和端口 (x.x.x.x:yyy - might not work on OSX) "),
		flagSet.StringVarP(&options.ConnectPayload, "cp", "connect-payload", "", "payload to send in CONNECT scans (optional)"),
		flagSet.BoolVarP(&options.InterfacesList, "il", "interface-list", false, "展示可用的网络接口和公网IP"),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "网络接口名称"),
		flagSet.StringVar(&options.Resolvers, "r", "", "自定义解析器DNS解析列表 (逗号分隔或文件)"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "socks5 proxy (ip[:port] / fqdn[:port]"),
		flagSet.StringVar(&options.ProxyAuth, "proxy-auth", "", "Socks5代理认证(用户名:密码)"),
		flagSet.BoolVar(&options.Resume, "resume", false, "使用resume.cfg恢复扫描"),
		flagSet.DurationVarP(&options.InputReadTimeout, "input-read-timeout", "irt", 3*time.Minute, "输入读取超时"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "禁用标准输入处理"),
	)

	flagSet.CreateGroup("host-discovery", "主机探测",
		flagSet.BoolVarP(&options.OnlyHostDiscovery, "host-discovery", "sn", false, "执行主机发现"),
		flagSet.BoolVarP(&options.WithHostDiscovery, "with-host-discovery", "wn", false, "启用主机发现功能"),
		flagSet.StringSliceVarP(&options.TcpSynPingProbes, "probe-tcp-syn", "ps", nil, "TCP SYN Ping (需要启用主机发现)", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.TcpAckPingProbes, "probe-tcp-ack", "pa", nil, "TCP ACK Ping (需要启用主机发现)", goflags.StringSliceOptions),
		flagSet.BoolVarP(&options.IcmpEchoRequestProbe, "probe-icmp-echo", "pe", false, "ICMP echo request Ping (需要启用主机发现)"),
		flagSet.BoolVarP(&options.IcmpTimestampRequestProbe, "probe-icmp-timestamp", "pp", false, "ICMP timestamp request Ping (需要启用主机发现)"),
		flagSet.BoolVarP(&options.IcmpAddressMaskRequestProbe, "probe-icmp-address-mask", "pm", false, "ICMP address mask request Ping (需要启用主机发现)"),
		flagSet.BoolVarP(&options.ArpPing, "arp-ping", "arp", false, "ARP ping (需要启用主机发现)"),
		flagSet.BoolVarP(&options.IPv6NeighborDiscoveryPing, "nd-ping", "nd", false, "IPv6 Neighbor Discovery (需要启用主机发现)"),
		flagSet.BoolVar(&options.ReversePTR, "rev-ptr", false, "反向PTR查找输入ip"),
	)

	flagSet.CreateGroup("optimization", "优化",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "端口扫描的重试次数"),
		flagSet.DurationVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "超时前等待的毫秒数"),
		flagSet.IntVar(&options.WarmUpTime, "warm-up-time", 2, "扫描等待的秒数"),
		flagSet.BoolVar(&options.Ping, "ping", false, "Ping探测用于验证主机"),
		flagSet.BoolVar(&options.Verify, "verify", false, "使用TCP再次验证端口"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "显示debug信息"),
		flagSet.BoolVarP(&options.Verbose, "v", "verbose", false, "显示verbose信息"),
		flagSet.BoolVar(&options.Silent, "silent", false, "仅仅显示结果信息"),
	)

	_ = flagSet.Parse()

	if options.ListOutputFields {
		fields, err := structs.GetStructFields(Result{})
		if err != nil {
			gologger.Fatal().Msgf("could not get struct fields: %s\n", err)
		}
		for _, field := range fields {
			fmt.Println(field)
		}
		os.Exit(0)
	}

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("could not read config: %s\n", err)
		}
	}

	// Check if stdin pipe was given
	options.Stdin = !options.DisableStdin && fileutil.HasStdin()

	options.ResumeCfg = NewResumeCfg()
	if options.ShouldLoadResume() {
		if err := options.ResumeCfg.ConfigureResume(); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
	}
	options.configureOutput()

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := showNetworkInterfaces()
		if err != nil {
			gologger.Error().Msgf("could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.ValidateOptions()
	if err != nil {
		gologger.Fatal().Msgf("program exiting: %s\n", err)
	}

	return options
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFilePath())
}

func (options *Options) shouldDiscoverHosts() bool {
	return (options.OnlyHostDiscovery || options.WithHostDiscovery) && scan.PkgRouter != nil
}

func (options *Options) hasProbes() bool {
	return options.ArpPing || options.IPv6NeighborDiscoveryPing || options.IcmpAddressMaskRequestProbe ||
		options.IcmpEchoRequestProbe || options.IcmpTimestampRequestProbe || len(options.TcpAckPingProbes) > 0 ||
		len(options.TcpAckPingProbes) > 0
}

func (options *Options) shouldUseRawPackets() bool {
	return isOSSupported() && privileges.IsPrivileged && options.ScanType == SynScan && scan.PkgRouter != nil
}

func (options *Options) ShouldScanIPv4() bool {
	return sliceutil.Contains(options.IPVersion, "4")
}

func (options *Options) ShouldScanIPv6() bool {
	return sliceutil.Contains(options.IPVersion, "6")
}

func (options *Options) GetTimeout() time.Duration {
	if options.Timeout < time.Millisecond*500 {
		if options.ScanType == SynScan {
			return DefaultPortTimeoutSynScan
		}
		return DefaultPortTimeoutConnectScan
	}
	return options.Timeout
}
