package runner

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/iami317/logx"
	readerUtil "github.com/projectdiscovery/utils/reader"
	"io"
	"net"
	"os"
	"strings"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/scan"
	"github.com/projectdiscovery/mapcidr/asn"
	ipUtil "github.com/projectdiscovery/utils/ip"
	"github.com/remeh/sizedwaitgroup"
)

func (r *Runner) Load() error {
	r.scanner.ListenHandler.Phase.Set(scan.Init)

	// merge all target sources into a file
	targetfile, err := r.mergeToFile()
	if err != nil {
		return err
	}
	r.targetsFile = targetfile

	// pre-process all targets (resolves all non fqdn targets to ip address)
	err = r.PreProcessTargets()
	if err != nil {
		logx.Warnf("%s", err)
	}

	return nil
}

func (r *Runner) mergeToFile() (string, error) {
	// merge all targets in a unique file
	tempInput, err := os.CreateTemp("", "stdin-input-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := tempInput.Close(); err != nil {
			logx.Errorf("could not close temp input: %s", err)
		}
	}()

	// target defined via CLI argument
	if len(r.options.Host) > 0 {
		for _, v := range r.options.Host {
			_, _ = fmt.Fprintf(tempInput, "%s", v)
		}
	}

	// Targets from file
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return "", err
		}
		defer func() {
			if err := f.Close(); err != nil {
				logx.Errorf("could not close file %s: %s", r.options.HostsFile, err)
			}
		}()
		if _, err := io.Copy(tempInput, f); err != nil {
			return "", err
		}
	}

	// targets from STDIN
	if r.options.Stdin {
		timeoutReader := readerUtil.TimeoutReader{Reader: os.Stdin, Timeout: r.options.InputReadTimeout}
		if _, err := io.Copy(tempInput, timeoutReader); err != nil {
			return "", err
		}
	}

	// all additional non-named cli arguments are interpreted as targets
	for _, target := range flag.Args() {
		_, _ = fmt.Fprintf(tempInput, "%s", target)
	}

	filename := tempInput.Name()
	return filename, nil
}

func (r *Runner) PreProcessTargets() error {
	wg := sizedwaitgroup.New(r.options.Threads)
	f, err := os.Open(r.targetsFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logx.Errorf("could not close file %s: %s", r.targetsFile, err)
		}
	}()
	s := bufio.NewScanner(f)
	for s.Scan() {
		wg.Add()
		go func(target string) {
			defer wg.Done()
			if err := r.AddTarget(target); err != nil {
				logx.Warnf("%s", err)
			}
		}(s.Text())
	}

	wg.Wait()
	return nil
}

func (r *Runner) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	if asn.IsASN(target) {
		// Get CIDRs for ASN
		cidrs, err := asn.GetCIDRsForASNNum(target)
		if err != nil {
			return err
		}
		for _, cidr := range cidrs {
			if err := r.scanner.IPRanger.AddHostWithMetadata(cidr.String(), "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
				logx.Warnf("%s", err)
			}
		}
		return nil
	}
	if ipUtil.IsCIDR(target) {
		if err := r.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
			logx.Warnf("%s", err)
		}
		return nil
	}
	if ipUtil.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		ip := net.ParseIP(target)
		// convert ip4 expressed as ip6 back to ip4
		if ip.To4() != nil {
			target = ip.To4().String()
		}
		metadata := "ip"
		if r.options.ReversePTR {
			names, err := ipUtil.ToFQDN(target)
			if err != nil {
				logx.Debugf("reverse ptr failed for %s: %s", target, err)
			} else {
				metadata = strings.Trim(names[0], ".")
			}
		}
		err := r.scanner.IPRanger.AddHostWithMetadata(target, metadata)
		if err != nil {
			logx.Warnf("%s", err)
		}
		return nil
	}

	host, port, hasPort := getPort(target)

	targetToResolve := target
	if hasPort {
		targetToResolve = host
	}
	ips, err := r.resolveFQDN(targetToResolve)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		if hasPort {
			if len(r.options.Ports) > 0 {
				if err := r.scanner.IPRanger.AddHostWithMetadata(joinHostPort(ip, ""), target); err != nil {
					logx.Warnf("%s", err)
				}
			} else {
				if err := r.scanner.IPRanger.AddHostWithMetadata(joinHostPort(ip, port), target); err != nil {
					logx.Warnf("%s", err)
				}
			}
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
			logx.Warnf("%s", err)
		}
	}

	return nil
}

func joinHostPort(host, port string) string {
	if port == "" {
		return host
	}

	return net.JoinHostPort(host, port)
}

func (r *Runner) resolveFQDN(target string) ([]string, error) {
	ipsV4, ipsV6, err := r.host2ips(target)
	if err != nil {
		return nil, err
	}

	var (
		initialHosts   []string
		initialHostsV6 []string
		hostIPS        []string
	)
	for _, ip := range ipsV4 {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			logx.Warnf("skipping host %s as ip %s was excluded", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}
	for _, ip := range ipsV6 {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			logx.Warnf("skipping host %s as ip %s was excluded", target, ip)
			continue
		}

		initialHostsV6 = append(initialHostsV6, ip)
	}
	if len(initialHosts) == 0 && len(initialHostsV6) == 0 {
		return []string{}, nil
	}

	// If the user has specified ping probes, perform ping on addresses
	if privileges.IsPrivileged && r.options.Ping && len(initialHosts) > 1 {
		// Scan the hosts found for ping probes
		pingResults, err := scan.PingHosts(initialHosts)
		if err != nil {
			logx.Warnf("could not perform ping scan on %s: %s", target, err)
			return []string{}, err
		}
		for _, result := range pingResults.Hosts {
			if result.Type == scan.HostActive {
				logx.Debugf("ping probe succeed for %s: latency=%s", result.Host, result.Latency)
			} else {
				logx.Debugf("ping probe failed for %s: error=%s", result.Host, result.Error)
			}
		}

		// Get the fastest host in the list of hosts
		fastestHost, err := pingResults.GetFastestHost()
		if err != nil {
			logx.Warnf("no active host found for %s: %s", target, err)
			return []string{}, err
		}
		logx.Infof("fastest host found for target: %s (%s)", fastestHost.Host, fastestHost.Latency)
		hostIPS = append(hostIPS, fastestHost.Host)
	} else if r.options.ScanAllIPS {
		hostIPS = append(initialHosts, initialHostsV6...)
	} else {
		if len(initialHosts) > 0 {
			hostIPS = append(hostIPS, initialHosts[0])
		}
		if len(initialHostsV6) > 0 {
			hostIPS = append(hostIPS, initialHostsV6[0])
		}
	}

	for _, hostIP := range hostIPS {
		if r.scanner.IPRanger.Contains(hostIP) {
			logx.Debugf("using ip %s for host %s enumeration", hostIP, target)
		}
	}

	return hostIPS, nil
}
