package runner

import (
	"fmt"
	"github.com/iami317/sx/pkg/scan"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"net"

	iputil "github.com/projectdiscovery/utils/ip"
	osutil "github.com/projectdiscovery/utils/os"
)

// dnsClient, err := retryabledns.New([]string{"8.8.8.8:53", "8.8.4.4:53", "tcp:1.1.1.1"}, 2)
// dnsData, err := dnsClient.Resolve(target)
func (r *Runner) host2ips(target string) (targetIPsV4 []string, targetIPsV6 []string, err error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host for port scanning
	if !iputil.IsIP(target) {
		//dnsData, err := r.dnsClient.QueryMultiple(target)
		//dnsClient, err := retryabledns.New([]string{"8.8.8.8:53", "8.8.4.4:53", "tcp:1.1.1.1"}, 2)

		dnsClient, err := retryabledns.New([]string{
			"udp:8.8.8.8:53",         // Google
			"udp:8.8.4.4:53",         // Google
			"udp:9.9.9.9:53",         // Quad9
			"udp:149.112.112.112:53", // Quad9
			"udp:208.67.222.222:53",  // Open DNS
			"udp:208.67.220.220:53",  // Open DNS
			"udp:1.1.1.1:53",         // Cloudflare
			"udp:1.0.0.1:53",         // Cloudflare
		}, 2)
		dnsData, err := dnsClient.Resolve(target)

		if err != nil || dnsData == nil {
			gologger.Warning().Msgf("Could not get IP for host: %s\n", target)
			return nil, nil, err
		}
		if len(r.options.IPVersion) > 0 {
			if sliceutil.Contains(r.options.IPVersion, scan.IPv4) {
				targetIPsV4 = append(targetIPsV4, dnsData.A...)
			}
			if sliceutil.Contains(r.options.IPVersion, scan.IPv6) {
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
		gologger.Debug().Msgf("Found %d addresses for %s\n", len(targetIPsV4), target)
	}

	return
}

func isOSSupported() bool {
	return osutil.IsLinux() || osutil.IsOSX()
}

func getPort(target string) (string, string, bool) {
	host, port, err := net.SplitHostPort(target)
	if err == nil && iputil.IsPort(port) {
		return host, port, true
	}

	return target, "", false
}
