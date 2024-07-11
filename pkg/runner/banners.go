package runner

import (
	"net"
	"strings"

	"github.com/iami317/logx"
	"github.com/iami317/sx/pkg/privileges"
	"github.com/iami317/sx/pkg/scan"
	osutil "github.com/projectdiscovery/utils/os"
)

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities(options *Options) {
	var accessLevel, scanType string

	switch {
	case privileges.IsPrivileged && options.ScanType == SynScan:
		accessLevel = "root"
		if osutil.IsLinux() {
			accessLevel = "CAP_NET_RAW"
		}
		scanType = "SYN"
	case options.Passive:
		accessLevel = "non root"
		scanType = "PASSIVE"
	default:
		accessLevel = "non root"
		scanType = "CONNECT"
	}

	switch {
	case options.OnlyHostDiscovery:
		scanType = "主机发现"
		logx.Verbosef("运行 %s", scanType)
	case options.Passive:
		scanType = "PASSIVE"
		logx.Verbosef("运行 %s 扫描", scanType)
	default:
		logx.Verbosef("运行 %s 扫描-使用 %s 权限", scanType, accessLevel)
	}
}

func showHostDiscoveryInfo() {
	logx.Verbosef("运行主机发现扫描,发送原始数据包")
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
			logx.Warnf("Could not retrieve addresses for %s: %s", itf.Name, addErr)
			continue
		}
		var addrstr []string
		for _, address := range addresses {
			addrstr = append(addrstr, address.String())
		}
		logx.Infof("Interface %s:\nMAC: %s\nAddresses: %s\nMTU: %d\nFlags: %s", itf.Name, itf.HardwareAddr, strings.Join(addrstr, " "), itf.MTU, itf.Flags.String())
	}
	// External ip
	externalIP, err := scan.WhatsMyIP()
	if err != nil {
		logx.Warnf("Could not obtain public ip: %s", err)
	}
	logx.Verbosef("External Ip: %s", externalIP)

	return nil
}
