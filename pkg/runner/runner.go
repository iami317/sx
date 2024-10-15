package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/iami317/logx"
	"github.com/projectdiscovery/retryablehttp-go"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Mzack9999/gcache"
	"github.com/iami317/sx/pkg/port"
	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/protocol"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/scan"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/remeh/sizedwaitgroup"
)

// Runner is an instance of the port enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options       *Options
	scanner       *scan.Scanner
	limiter       *ratelimit.Limiter
	wgScan        sizedwaitgroup.SizedWaitGroup
	dnsClient     *dnsx.DNSX
	streamChannel chan Target

	unique gcache.Cache[string, struct{}]
}

type Stats struct {
	Total int
}

type Target struct {
	Ip   string
	Cidr string
	Fqdn string
	Port string
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists, etc
func NewRunner(options *Options) (*Runner, error) {
	options.configureOutput()

	options.configureHostDiscovery()

	// default to ipv4 if no ipversion was specified
	if len(options.IPVersion) == 0 {
		options.IPVersion = []string{scan.IPv4}
	}

	if options.Retries == 0 {
		options.Retries = DefaultRetriesSynScan
	}

	runner := &Runner{
		options: options,
	}

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if sliceutil.Contains(options.IPVersion, "6") {
		dnsOptions.QuestionTypes = append(dnsOptions.QuestionTypes, dns.TypeAAAA)
	}
	if len(runner.options.baseResolvers) > 0 {
		dnsOptions.BaseResolvers = runner.options.baseResolvers
	}
	dnsClient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsClient = dnsClient

	excludedIps, err := runner.parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	runner.streamChannel = make(chan Target)

	uniqueCache := gcache.New[string, struct{}](1500).Build()
	runner.unique = uniqueCache

	scanOpts := &scan.Options{
		Timeout:       time.Duration(options.Timeout) * time.Millisecond,
		Retries:       options.Retries,
		Rate:          options.Rate,
		PortThreshold: options.PortThreshold,
		ExcludeCdn:    options.ExcludeCDN,
		OutputCdn:     options.OutputCDN,
		ExcludedIps:   excludedIps,
		Proxy:         options.Proxy,
		ProxyAuth:     options.ProxyAuth,
		Stream:        options.Stream,
		OnReceive:     options.OnReceive,
	}

	if scanOpts.OnReceive == nil {
		scanOpts.OnReceive = runner.onReceive
	}

	scanner, err := scan.NewScanner(scanOpts)
	if err != nil {
		return nil, err
	}
	runner.scanner = scanner

	runner.scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	return runner, nil
}

func (r *Runner) onReceive(hostResult *result.HostResult) {
	if !IpMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
		return
	}

	dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
	if err != nil {
		return
	}

	// receive event has only one port
	for _, p := range hostResult.Ports {
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
		if r.unique.Has(ipPort) {
			return
		}
	}

	// recover hostnames from ip:port combination
	for _, p := range hostResult.Ports {
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
		if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
			if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
				// replace bare ip:port with host
				for idx, ipCandidate := range dt {
					if iputil.IsIP(ipCandidate) {
						dt[idx] = otherName
					}
				}
			}
		}
		_ = r.unique.Set(ipPort, struct{}{})
	}

	buffer := bytes.Buffer{}
	for _, host := range dt {
		buffer.Reset()
		if host == "ip" {
			host = hostResult.IP
		}

		isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)
		// console output
		if r.options.JSON {
			data := &Result{IP: hostResult.IP, TimeStamp: time.Now().UTC()}
			if r.options.OutputCDN {
				data.IsCDNIP = isCDNIP
				data.CDNName = cdnName
			}
			if host != hostResult.IP {
				data.Host = host
			}
			for _, p := range hostResult.Ports {
				data.Port = p.Port
				data.Protocol = p.Protocol.String()
				data.TLS = p.TLS
				if r.options.JSON {
					b, err := data.JSON()
					if err != nil {
						continue
					}
					buffer.Write([]byte(fmt.Sprintf("%s", b)))
				}
			}
		}
		if r.options.JSON {
			logx.Infof("%s", buffer.String())
		} else {
			for _, p := range hostResult.Ports {
				if r.options.OutputCDN && isCDNIP {
					logx.Infof("%s:%d [%s]", host, p.Port, cdnName)
				} else {
					logx.Infof("%s:%d", host, p.Port)
				}
			}
		}
	}
}

// RunEnumeration 在指定的目标上运行端口枚举流
func (r *Runner) RunEnumeration(pctx context.Context) error {
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	if privileges.IsPrivileged && r.options.ScanType == SynScan {
		if r.options.SourceIP != "" {
			logx.Verbosef("设置源IP:%v", r.options.SourceIP)
			err := r.SetSourceIP(r.options.SourceIP)
			if err != nil {
				return err
			}
		}
		if r.options.Interface != "" {
			logx.Verbosef("设置网络接口:%v", r.options.Interface)
			err := r.SetInterface(r.options.Interface)
			if err != nil {
				return err
			}
		}
		if r.options.SourcePort != "" {
			logx.Verbosef("设置源端口:%v", r.options.SourcePort)
			err := r.SetSourcePort(r.options.SourcePort)
			if err != nil {
				return err
			}
		}
		r.scanner.StartWorkers(ctx)
	}
	if r.options.Stream {
		go r.Load() //nolint
	} else {
		err := r.Load()
		if err != nil {
			return err
		}
	}

	// Scan workers
	r.wgScan = sizedwaitgroup.New(r.options.Rate)
	r.limiter = ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	shouldDiscoverHosts := r.options.shouldDiscoverHosts()
	shouldUseRawPackets := r.options.shouldUseRawPackets()

	if shouldDiscoverHosts && shouldUseRawPackets {
		showHostDiscoveryInfo()
		r.scanner.ListenHandler.Phase.Set(scan.HostDiscovery)
		// shrinks the ips to the minimum amount of cidr
		_, targetsV4, targetsv6, _, err := r.GetTargetIps(r.getPreprocessedIps)
		if err != nil {
			return err
		}

		//获取执行的具体 ip
		ips := r.GetTargetIp(targetsV4, targetsv6)
		if len(ips) == 0 {
			return fmt.Errorf("no valid ipv4 or ipv6 targets were found")
		}
		for _, ip := range ips {
			r.handleHostDiscovery(ip)
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		// check if we should stop here or continue with full scan
		if r.options.OnlyHostDiscovery {
			r.handleOutput(r.scanner.HostDiscoveryResults)
			return nil
		}
	}

	switch {
	case r.options.Stream && !r.options.Passive: // stream active
		showNetworkCapabilities(r.options)
		r.scanner.ListenHandler.Phase.Set(scan.Scan)
		handleStreamIp := func(target string, port *port.Port) bool {
			if r.scanner.ScanResults.HasSkipped(target) {
				return false
			}
			if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(target) >= r.options.PortThreshold {
				hosts, _ := r.scanner.IPRanger.GetHostsByIP(target)
				logx.Infof("Skipping %s %v, Threshold reached ", target, hosts)
				r.scanner.ScanResults.AddSkipped(target)
				return false
			}
			if shouldUseRawPackets {
				r.RawSocketEnumeration(ctx, target, port)
			} else {
				r.wgScan.Add()
				go r.handleHostPort(ctx, target, port)
			}
			return true
		}

		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				logx.Warnf("Couldn't track %s in scan results: %s", target, err)
			}
			if ipStream, err := mapcidr.IPAddressesAsStream(target.Cidr); err == nil {
				for ip := range ipStream {
					for _, port := range r.scanner.Ports {
						if !handleStreamIp(ip, port) {
							break
						}
					}
				}
			} else if target.Ip != "" && target.Port != "" {
				pp, _ := strconv.Atoi(target.Port)
				handleStreamIp(target.Ip, &port.Port{Port: pp, Protocol: protocol.TCP})
			}
		}
		r.wgScan.Wait()
		r.handleOutput(r.scanner.ScanResults)
		return nil
	case r.options.Stream && r.options.Passive: // stream passive
		showNetworkCapabilities(r.options)
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
		r.scanner.ListenHandler.Phase.Set(scan.Scan)
		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				logx.Warnf("Couldn't track %s in scan results: %s", target, err)
			}
			ipStream, _ := mapcidr.IPAddressesAsStream(target.Cidr)
			for ip := range ipStream {
				r.wgScan.Add()
				go func(ip string) {
					defer r.wgScan.Done()

					// obtain ports from shodan idb
					shodanURL := fmt.Sprintf(shodanidb.URL, url.QueryEscape(ip))
					request, err := retryablehttp.NewRequest(http.MethodGet, shodanURL, nil)
					if err != nil {
						logx.Warnf("Couldn't create http request for %s: %s", ip, err)
						return
					}
					r.limiter.Take()
					response, err := httpClient.Do(request)
					if err != nil {
						logx.Warnf("Couldn't retrieve http response for %s: %s", ip, err)
						return
					}
					if response.StatusCode != http.StatusOK {
						logx.Warnf("Couldn't retrieve data for %s, server replied with status code: %d", ip, response.StatusCode)
						return
					}

					// unmarshal the response
					data := &shodanidb.ShodanResponse{}
					if err := json.NewDecoder(response.Body).Decode(data); err != nil {
						logx.Warnf("Couldn't unmarshal json data for %s: %s", ip, err)
						return
					}

					for _, p := range data.Ports {
						pp := &port.Port{Port: p, Protocol: protocol.TCP}
						if r.scanner.OnReceive != nil {
							r.scanner.OnReceive(&result.HostResult{IP: ip, Ports: []*port.Port{pp}})
						}
						r.scanner.ScanResults.AddPort(ip, pp)
					}
				}(ip)
			}
		}
		r.wgScan.Wait()

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput(r.scanner.ScanResults)

		return nil
	default:
		showNetworkCapabilities(r.options)
		ipsCallback := r.getPreprocessedIps
		if shouldDiscoverHosts && shouldUseRawPackets {
			ipsCallback = r.getHostDiscoveryIps
		}

		// shrinks the ips to the minimum amount of cidr
		targets, targetsV4, targetsv6, targetsWithPort, err := r.GetTargetIps(ipsCallback)
		if err != nil {
			return err
		}
		var targetsCount, portsCount uint64
		for _, target := range append(targetsV4, targetsv6...) {
			if target == nil {
				continue
			}
			targetsCount += mapcidr.AddressCountIpnet(target)
		}
		portsCount = uint64(len(r.scanner.Ports))
		r.scanner.ListenHandler.Phase.Set(scan.Scan)
		Range := targetsCount * portsCount

		// Retries are performed regardless of the previous scan results due to network unreliability
		for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
			// Use current time as seed
			currentSeed := time.Now().UnixNano()
			b := blackrock.New(int64(Range), currentSeed)
			for index := int64(0); index < int64(Range); index++ {
				xxx := b.Shuffle(index)
				ipIndex := xxx / int64(portsCount)
				portIndex := int(xxx % int64(portsCount))
				ip := r.PickIP(targets, ipIndex)
				port := r.PickPort(portIndex)
				r.limiter.Take()

				if r.scanner.ScanResults.HasSkipped(ip) {
					continue
				}
				excludedIPs, _ := r.parseExcludedIps(r.options)
				var skipFlag bool
				for _, v := range excludedIPs {
					if v == ip {
						skipFlag = true
					}
				}
				if skipFlag {
					continue
				}
				if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
					hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
					logx.Infof("Skipping %s %v, Threshold reached ", ip, hosts)
					r.scanner.ScanResults.AddSkipped(ip)
					continue
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ctx, ip, port)
				} else {
					r.wgScan.Add()
					go r.handleHostPort(ctx, ip, port)
				}
			}

			// handle the ip:port combination
			for _, targetWithPort := range targetsWithPort {
				ip, p, err := net.SplitHostPort(targetWithPort)
				if err != nil {
					logx.Debugf("Skipping %s: %v", targetWithPort, err)
					continue
				}
				// naive port find
				pp, err := strconv.Atoi(p)
				if err != nil {
					logx.Debugf("Skipping %s, could not cast port %s: %v", targetWithPort, p, err)
					continue
				}
				var portWithMetadata = port.Port{
					Port:     pp,
					Protocol: protocol.TCP,
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ctx, ip, &portWithMetadata)
				} else {
					r.wgScan.Add()
					go r.handleHostPort(ctx, ip, &portWithMetadata)
				}
			}

			r.wgScan.Wait()
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		r.scanner.ListenHandler.Phase.Set(scan.Done)

		// Validate the hosts if the user has asked for second step validation
		if r.options.Verify {
			r.ConnectVerification()
		}

		r.handleOutput(r.scanner.ScanResults)

		return nil
	}
}

func (r *Runner) getHostDiscoveryIps() (ips []*net.IPNet, ipsWithPort []string) {
	for ip := range r.scanner.HostDiscoveryResults.GetIPs() {
		ips = append(ips, iputil.ToCidr(string(ip)))
	}

	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		// ips with port are ignored during host discovery phase
		if cidr := iputil.ToCidr(string(ip)); cidr == nil {
			ipsWithPort = append(ipsWithPort, string(ip))
		}
		return nil
	})

	return
}

func (r *Runner) getPreprocessedIps() (cidrs []*net.IPNet, ipsWithPort []string) {
	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		if cidr := iputil.ToCidr(string(ip)); cidr != nil {
			cidrs = append(cidrs, cidr)
		} else {
			ipsWithPort = append(ipsWithPort, string(ip))
		}

		return nil
	})
	return
}

func (r *Runner) GetTargetIps(ipsCallback func() ([]*net.IPNet, []string)) (targets, targetsV4, targetsv6 []*net.IPNet, targetsWithPort []string, err error) {
	targets, targetsWithPort = ipsCallback()
	// shrinks the ips to the minimum amount of cidr
	targetsV4, targetsv6 = mapcidr.CoalesceCIDRs(targets)
	if len(targetsV4) == 0 && len(targetsv6) == 0 && len(targetsWithPort) == 0 {
		return nil, nil, nil, nil, errors.New("no valid ipv4 or ipv6 targets were found")
	}
	return targets, targetsV4, targetsv6, targetsWithPort, nil
}

func (r *Runner) GetTargetIp(targetsV4, targetsv6 []*net.IPNet) (ips []string) {
	excludedIPsMap := make(map[string]struct{})
	// get excluded ips
	excludedIPs, _ := r.parseExcludedIps(r.options)

	// store exclued ips to a map
	for _, ipString := range excludedIPs {
		excludedIPsMap[ipString] = struct{}{}
	}
	for _, target4 := range targetsV4 {
		ipsV4, _ := mapcidr.IPAddresses(target4.String())
		for _, s := range ipsV4 {
			if _, exists := excludedIPsMap[s]; !exists {
				ips = append(ips, s)
			}

		}
	}

	for _, v6 := range targetsv6 {
		ipsV6, _ := mapcidr.IPAddresses(v6.String())
		for _, s := range ipsV6 {
			if _, exists := excludedIPsMap[s]; !exists {
				ips = append(ips, s)
			}
		}
	}
	return
}

func (r *Runner) ShowScanResultOnExit() {
	r.handleOutput(r.scanner.ScanResults)
}

// Close runner instance
func (r *Runner) Close() {
	_ = r.scanner.IPRanger.Hosts.Close()

	if r.scanner != nil {
		r.scanner.Close()
	}
	if r.limiter != nil {
		r.limiter.Stop()
	}
}

// PickIP randomly
func (r *Runner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return r.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func (r *Runner) PickSubnetIP(network *net.IPNet, index int64) string {
	ipInt, bits, err := mapcidr.IPToInteger(network.IP)
	if err != nil {
		logx.Warnf("%s", err)
		return ""
	}
	subnetIpInt := big.NewInt(0).Add(ipInt, big.NewInt(index))
	ip := mapcidr.IntegerToIP(subnetIpInt, bits)
	return ip.String()
}

func (r *Runner) PickPort(index int) *port.Port {
	return r.scanner.Ports[index]
}

func (r *Runner) ConnectVerification() {
	r.scanner.ListenHandler.Phase.Set(scan.Scan)
	var swg sync.WaitGroup
	limiter := ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	verifiedResult := result.NewResult()

	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		limiter.Take()
		swg.Add(1)
		go func(hostResult *result.HostResult) {
			defer swg.Done()
			results := r.scanner.ConnectVerify(hostResult.IP, hostResult.Ports)
			verifiedResult.SetPorts(hostResult.IP, results)
		}(hostResult)
	}

	r.scanner.ScanResults = verifiedResult

	swg.Wait()
}

func (r *Runner) RawSocketHostDiscovery(ip string) {
	r.handleHostDiscovery(ip)
}

func (r *Runner) RawSocketEnumeration(ctx context.Context, ip string, p *port.Port) {
	select {
	case <-ctx.Done():
		return
	default:
		// performs cdn/waf scan exclusions checks
		if !r.canIScanIfCDN(ip, p) {
			logx.Debugf("Skipping cdn target: %s:%d", ip, p.Port)
			return
		}

		if r.scanner.ScanResults.IPHasPort(ip, p) {
			return
		}

		r.limiter.Take()
		switch p.Protocol {
		case protocol.TCP:
			r.scanner.EnqueueTCP(ip, scan.Syn, p)
		case protocol.UDP:
			r.scanner.EnqueueUDP(ip, p)
		}
	}
}

// check if an ip can be scanned in case CDN/WAF exclusions are enabled
func (r *Runner) canIScanIfCDN(host string, port *port.Port) bool {
	// if CDN ips are not excluded all scans are allowed
	if !r.options.ExcludeCDN {
		return true
	}

	// if exclusion is enabled, but the ip is not part of the CDN/WAF ips range we can scan
	if ok, _, err := r.scanner.CdnCheck(host); err == nil && !ok {
		return true
	}

	// If the cdn is part of the CDN ips range - only ports 80 and 443 are allowed
	return port.Port == 80 || port.Port == 443
}

func (r *Runner) handleHostPort(ctx context.Context, host string, p *port.Port) {
	defer r.wgScan.Done()

	select {
	case <-ctx.Done():
		return
	default:
		// performs cdn scan exclusions checks
		if !r.canIScanIfCDN(host, p) {
			logx.Debugf("Skipping cdn target: %s:%d", host, p.Port)
			return
		}

		if r.scanner.ScanResults.IPHasPort(host, p) {
			return
		}

		r.limiter.Take()
		open, err := r.scanner.ConnectPort(host, p, time.Duration(r.options.Timeout)*time.Millisecond)
		if open && err == nil {
			r.scanner.ScanResults.AddPort(host, p)
			if r.scanner.OnReceive != nil {
				r.scanner.OnReceive(&result.HostResult{IP: host, Ports: []*port.Port{p}})
			}
		}
	}
}

func (r *Runner) handleHostDiscovery(host string) {
	r.limiter.Take()
	// Pings
	// - Icmp Echo Request
	if r.options.IcmpEchoRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpEchoRequest)
	}
	// - Icmp Timestamp Request
	if r.options.IcmpTimestampRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpTimestampRequest)
	}
	// - Icmp Netmask Request
	if r.options.IcmpAddressMaskRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpAddressMaskRequest)
	}
	// ARP scan
	if r.options.ArpPing {
		r.scanner.EnqueueEthernet(host, scan.Arp)
	}
	// Syn Probes
	if len(r.options.TcpSynPingProbes) > 0 {
		ports, _ := parsePortsSlice(r.options.TcpSynPingProbes)
		r.scanner.EnqueueTCP(host, scan.Syn, ports...)
	}
	// Ack Probes
	if len(r.options.TcpAckPingProbes) > 0 {
		ports, _ := parsePortsSlice(r.options.TcpAckPingProbes)
		r.scanner.EnqueueTCP(host, scan.Ack, ports...)
	}
	// IPv6-ND (for now we broadcast ICMPv6 to ff02::1)
	if r.options.IPv6NeighborDiscoveryPing {
		r.scanner.EnqueueICMP("ff02::1", scan.Ndp)
	}
}

func (r *Runner) SetSourceIP(sourceIP string) error {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return errors.New("invalid source ip")
	}

	switch {
	case iputil.IsIPv4(sourceIP):
		r.scanner.SourceIP4 = ip
	case iputil.IsIPv6(sourceIP):
		r.scanner.SourceIP6 = ip
	default:
		return errors.New("invalid ip type")
	}

	return nil
}

func (r *Runner) SetSourcePort(sourcePort string) error {
	isValidPort := iputil.IsPort(sourcePort)
	if !isValidPort {
		return errors.New("invalid source port")
	}

	port, err := strconv.Atoi(sourcePort)
	if err != nil {
		return err
	}

	r.scanner.ListenHandler.Port = port

	return nil
}

func (r *Runner) SetInterface(interfaceName string) error {
	networkInterface, err := net.InterfaceByName(r.options.Interface)
	if err != nil {
		return err
	}

	r.scanner.NetworkInterface = networkInterface
	return nil
}

func (r *Runner) handleOutput(scanResults *result.Result) {

	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}

			if !IpMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
				continue
			}

			// recover hostnames from ip:port combination
			for _, p := range hostResult.Ports {
				ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
				if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
					if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
						// replace bare ip:port with host
						for idx, ipCandidate := range dt {
							if iputil.IsIP(ipCandidate) {
								dt[idx] = otherName
							}
						}
					}
				}
			}

			buffer := bytes.Buffer{}
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostResult.IP
				}
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)
				logx.Verbosef("Found %d ports on host %s (%s)", len(hostResult.Ports), host, hostResult.IP)

				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostResult.IP, Ports: hostResult.Ports, IsCDNIP: isCDNIP, CdnName: cdnName})
				}
			}
		}
	case scanResults.HasIPS():
		for hostIP := range scanResults.GetIPs() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
			if err != nil {
				continue
			}
			if !IpMatchesIpVersions(hostIP, r.options.IPVersion...) {
				continue
			}

			buffer := bytes.Buffer{}
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostIP
				}
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostIP)
				logx.Verbosef("Found alive host %s (%s)", host, hostIP)
				// console output
				if r.options.JSON {
					data := &Result{IP: hostIP, TimeStamp: time.Now().UTC()}
					if r.options.OutputCDN {
						data.IsCDNIP = isCDNIP
						data.CDNName = cdnName
					}
					if host != hostIP {
						data.Host = host
					}
				}
				if r.options.JSON {
					logx.Verbosef("%s", buffer.String())
				} else {
					if r.options.OutputCDN && isCDNIP {
						logx.Verbosef("%s [%s]", host, cdnName)
					} else {
						logx.Verbosef("%s", host)
					}
				}

				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostIP, IsCDNIP: isCDNIP, CdnName: cdnName})
				}
			}
		}
	}
}

func IpMatchesIpVersions(ip string, ipVersions ...string) bool {
	for _, ipVersion := range ipVersions {
		if ipVersion == scan.IPv4 && iputil.IsIPv4(ip) {
			return true
		}
		if ipVersion == scan.IPv6 && iputil.IsIPv6(ip) {
			return true
		}
	}
	return false
}
