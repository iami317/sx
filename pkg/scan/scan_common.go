package scan

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/routing"
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
	mu                                                      sync.Mutex

	pkgRouter routing.Router

	ArpRequestAsync  func(ip string)
	InitScanner      func(s *Scanner) error
	NumberOfHandlers = 10
	tcpsequencer     = NewTCPSequencer()
)

type ListenHandler struct {
	Busy                                   bool
	Phase                                  *Phase
	Port                                   int
	TcpConn4, UdpConn4, TcpConn6, UdpConn6 *net.IPConn
	TcpChan, UdpChan, HostDiscoveryChan    chan *PkgResult
}

func Acquire() (*ListenHandler, error) {
	// always grant to unprivileged scans
	if !privileges.IsPrivileged {
		return &ListenHandler{Phase: &Phase{}}, nil
	}
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		mu.Lock()
		for _, listenHandler := range ListenHandlers {
			if !listenHandler.Busy {
				listenHandler.Phase = &Phase{}
				listenHandler.Busy = true
				mu.Unlock()
				return listenHandler, nil
			}
		}
		mu.Unlock()
		if i < maxRetries-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, errors.New("no free ListenHandler:" + string(len(ListenHandlers)))
}

func (l *ListenHandler) Release() {
	l.Busy = false
	l.Phase = nil
}

func init() {
	if r, err := routing.New(); err != nil {
		panic(err)
	} else {
		pkgRouter = r
	}
}

func ToString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}
