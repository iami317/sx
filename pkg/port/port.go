package port

import (
	"fmt"
	"strings"

	"github.com/iami317/sx/pkg/protocol"
)

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	// Deprecated: TLS field will be removed in a future version
	TLS bool `json:"tls"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d", p.Port)
}

func (p *Port) StringWithDetails() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%d", p.Port))
	builder.WriteString(" [")
	builder.WriteString(p.Protocol.String())
	if p.TLS {
		builder.WriteString("/tls")
	}
	builder.WriteString("]")
	return builder.String()
}
