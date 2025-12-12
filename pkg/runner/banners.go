package runner

import (
	"github.com/iami317/logx"
	"net"
	"strings"

	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/scan"
	osUtil "github.com/projectdiscovery/utils/os"
)

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities(options *Options) {
	var accessLevel, scanType string

	switch {
	case privileges.IsPrivileged && options.ScanType == SynScan:
		accessLevel = "root"
		if osUtil.IsLinux() {
			accessLevel = "CAP_NET_RAW"
		}
		scanType = "SYN"
	default:
		accessLevel = "non root"
		scanType = "CONNECT"
	}

	switch {
	case options.OnlyHostDiscovery:
		scanType = "Host Discovery"
		logx.Debugf("running %s\n", scanType)
	default:
		logx.Debugf("running %s scan with %s privileges\n", scanType, accessLevel)
	}
}

func showHostDiscoveryInfo() {
	logx.Debugf("running host discovery scan\n")
}

func showNetworkInterfaces() error {
	// Interfaces List
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range interfaces {
		addresses, addErr := itf.Addrs()
		if addErr != nil {
			logx.Warnf("could not retrieve addresses for %s: %s\n", itf.Name, addErr)
			continue
		}
		var addrstr []string
		for _, address := range addresses {
			addrstr = append(addrstr, address.String())
		}
		logx.Debugf(
			"Interface %s:\nMAC: %s\nAddresses: %s\nMTU: %d\nFlags: %s\n",
			itf.Name,
			itf.HardwareAddr,
			strings.Join(addrstr, " "),
			itf.MTU, itf.Flags.String(),
		)
	}
	// External ip
	externalIP, err := scan.WhatsMyIP()
	if err != nil {
		logx.Warnf("could not obtain public ip: %s\n", err)
	}
	logx.Debugf("external Ip: %s\n", externalIP)

	return nil
}
