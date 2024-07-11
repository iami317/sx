package runner

import (
	"flag"
	"github.com/iami317/logx"
	"net"
	"strings"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/scan"
	"github.com/projectdiscovery/mapcidr/asn"
	iputil "github.com/projectdiscovery/utils/ip"
)

func (r *Runner) Load() error {
	r.scanner.ListenHandler.Phase.Set(scan.Init)
	if r.options.Stream {
		defer close(r.streamChannel)
	}
	// 通过 CLI 参数定义的目标
	if len(r.options.Host) > 0 {
		for _, v := range r.options.Host {
			if err := r.AddTarget(v); err != nil {
				logx.Warnf("%s", err)
			}
		}
	}

	// 所有其他未命名的 CLI 参数都将被解释为目标
	for _, target := range flag.Args() {
		if err := r.AddTarget(target); err != nil {
			logx.Warnf("%s", err)
		}
	}

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
			if r.options.Stream {
				r.streamChannel <- Target{Cidr: cidr.String()}
			} else if err := r.scanner.IPRanger.AddHostWithMetadata(cidr.String(), "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
				logx.Warnf("%s", err)
			}
		}
		return nil
	}
	if iputil.IsCIDR(target) {
		if r.options.Stream {
			r.streamChannel <- Target{Cidr: target}
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
			logx.Warnf("%s", err)
		}
		return nil
	}
	if iputil.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		ip := net.ParseIP(target)
		// convert ip4 expressed as ip6 back to ip4
		if ip.To4() != nil {
			target = ip.To4().String()
		}
		if r.options.Stream {
			r.streamChannel <- Target{Cidr: iputil.ToCidr(target).String()}
		} else {
			metadata := "ip"
			if r.options.ReversePTR {
				names, err := iputil.ToFQDN(target)
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
		if r.options.Stream {
			if hasPort {
				r.streamChannel <- Target{Ip: ip, Port: port}
				if len(r.options.Ports) > 0 {
					r.streamChannel <- Target{Cidr: iputil.ToCidr(ip).String()}
					if err := r.scanner.IPRanger.AddHostWithMetadata(joinHostPort(ip, ""), target); err != nil {
						logx.Warnf("%s", err)
					}
				}
			} else {
				r.streamChannel <- Target{Cidr: iputil.ToCidr(ip).String()}
				if err := r.scanner.IPRanger.AddHostWithMetadata(joinHostPort(ip, port), target); err != nil {
					logx.Warnf("%s", err)
				}
			}
		} else if hasPort {
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
			logx.Warnf("Skipping host %s as ip %s was excluded", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}
	for _, ip := range ipsV6 {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			logx.Warnf("Skipping host %s as ip %s was excluded", target, ip)
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
			logx.Warnf("Could not perform ping scan on %s: %s", target, err)
			return []string{}, err
		}
		for _, result := range pingResults.Hosts {
			if result.Type == scan.HostActive {
				logx.Debugf("Ping probe succeed for %s: latency=%s", result.Host, result.Latency)
			} else {
				logx.Debugf("Ping probe failed for %s: error=%s", result.Host, result.Error)
			}
		}

		// Get the fastest host in the list of hosts
		fastestHost, err := pingResults.GetFastestHost()
		if err != nil {
			logx.Warnf("No active host found for %s: %s", target, err)
			return []string{}, err
		}
		logx.Infof("Fastest host found for target: %s (%s)", fastestHost.Host, fastestHost.Latency)
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
			logx.Debugf("Using ip %s for host %s enumeration", hostIP, target)
		}
	}

	return hostIPS, nil
}
