//go:build linux || darwin

package scan

import (
	"errors"
	"github.com/iami317/logx"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	ArpRequestAsync = arpRequestAsync
}

// ArpRequestAsync asynchronous to the target ip address
func arpRequestAsync(ip string) {
	networkInterface, _, sourceIP, err := pkgRouter.Route(net.ParseIP(ip))
	if networkInterface == nil {
		err = errors.New("Could not send ARP Request packet to " + ip + ": no interface with outbound source found")
	}
	if err != nil {
		logx.Debugf("%s", err)
		return
	}
	// network layers
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: sourceIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(ip).To4(),
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		logx.Warnf("%s", err)
		return
	}
	// send the packet out on every interface
	for _, handler := range handlers.EthernetActive {
		err := handler.WritePacketData(buf.Bytes())
		if err != nil {
			logx.Warnf("%s", err)
		}
	}
}
