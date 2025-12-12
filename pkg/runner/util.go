package runner

import (
	"fmt"
	"github.com/iami317/logx"
	"net"

	"github.com/iami317/sx/pkg/scan"
	ipUtil "github.com/projectdiscovery/utils/ip"
	osUtil "github.com/projectdiscovery/utils/os"
	sliceUtil "github.com/projectdiscovery/utils/slice"
)

func (r *Runner) host2ips(target string) (targetIPsV4 []string, targetIPsV6 []string, err error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if !ipUtil.IsIP(target) {
		dnsData, err := r.dnsclient.QueryMultiple(target)
		if err != nil || dnsData == nil {
			logx.Warnf("could not get IP for host: %s", target)
			return nil, nil, err
		}
		if len(r.options.IPVersion) > 0 {
			if sliceUtil.Contains(r.options.IPVersion, scan.IPv4) {
				targetIPsV4 = append(targetIPsV4, dnsData.A...)
			}
			if sliceUtil.Contains(r.options.IPVersion, scan.IPv6) {
				targetIPsV6 = append(targetIPsV6, dnsData.AAAA...)
			}
		} else {
			targetIPsV4 = append(targetIPsV4, dnsData.A...)
		}
		if len(targetIPsV4) == 0 && len(targetIPsV6) == 0 {
			return targetIPsV4, targetIPsV6, fmt.Errorf("no IP addresses found for host: %s", target)
		}
	} else {
		targetIPsV4 = append(targetIPsV6, target)
		logx.Debugf("found %d addresses for %s", len(targetIPsV4), target)
	}

	return
}

func isOSSupported() bool {
	return osUtil.IsLinux() || osUtil.IsOSX()
}

func getPort(target string) (string, string, bool) {
	host, port, err := net.SplitHostPort(target)
	if err == nil && ipUtil.IsPort(port) {
		return host, port, true
	}

	return target, "", false
}
