package port

import (
	"fmt"

	"github.com/iami317/sx/pkg/protocol"
)

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	TLS      bool              `json:"tls"`
}

func (p *Port) String() string {
	return fmt.Sprintf("port:%d-protocol:%d-tls:%v", p.Port, p.Protocol, p.TLS)
}
