package scan

import (
	"fmt"
	"net"

	"github.com/iami317/sx/pkg/port"
	"github.com/projectdiscovery/gologger"
)

// ConnectVerify is used to verify if ports are accurate using a connect request
func (s *Scanner) ConnectVerify(host string, ports []*port.Port) []*port.Port {
	var verifiedPorts []*port.Port
	for _, p := range ports {
		target := net.JoinHostPort(host, fmt.Sprint(p.Port))
		conn, err := net.DialTimeout(p.Protocol.String(), target, s.timeout)
		if err != nil {
			continue
		}
		gologger.Debug().Msgf("Validated active port %d on %s\n", p.Port, host)
		_ = conn.Close()
		verifiedPorts = append(verifiedPorts, p)
	}
	return verifiedPorts
}
