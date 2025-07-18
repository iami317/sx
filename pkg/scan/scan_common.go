package scan

import (
	"errors"
	"net"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/routing"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/icmp"
)

const (
	IPv4 = "4"
	IPv6 = "6"
)

var (
	ListenHandlers                                          []*ListenHandler
	NetworkInterface                                        string
	networkInterface                                        *net.Interface
	transportPacketSend, icmpPacketSend, ethernetPacketSend chan *PkgSend
	icmpConn4, icmpConn6                                    *icmp.PacketConn

	PkgRouter routing.Router

	ArpRequestAsync  func(ip string)
	InitScanner      func(s *Scanner) error
	NumberOfHandlers = 1
	tcpsequencer     = NewTCPSequencer()
)

type ListenHandler struct {
	Busy                                   bool
	Phase                                  *Phase
	SourceHW                               net.HardwareAddr
	SourceIp4                              net.IP
	SourceIP6                              net.IP
	Port                                   int
	TcpConn4, UdpConn4, TcpConn6, UdpConn6 *net.IPConn
	TcpChan, UdpChan, HostDiscoveryChan    chan *PkgResult
}

func NewListenHandler() *ListenHandler {
	return &ListenHandler{Phase: &Phase{}}
}

func Acquire(options *Options) (*ListenHandler, error) {
	// always grant to unprivileged scans or connect scan
	if PkgRouter == nil || !privileges.IsPrivileged || options.ScanType == "c" {
		h := NewListenHandler()
		h.Busy = true
		return NewListenHandler(), nil
	}

	for _, listenHandler := range ListenHandlers {
		if !listenHandler.Busy {
			listenHandler.Phase = &Phase{}
			listenHandler.Busy = true
			return listenHandler, nil
		}
	}
	return nil, errors.New("no free handlers")
}

func (l *ListenHandler) Release() {
	l.Busy = false
	l.Phase = nil
}

func init() {
	if r, err := routing.New(); err != nil {
		gologger.Error().Msgf("could not initialize router: %s\n", err)
	} else {
		PkgRouter = r
	}
}

func ToString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}
