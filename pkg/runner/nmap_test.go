package runner

import (
	"testing"

	"github.com/iami317/sx/pkg/port"
	"github.com/iami317/sx/pkg/protocol"
	"github.com/iami317/sx/pkg/result"
	"github.com/iami317/sx/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestHandleNmap(t *testing.T) {
	// just attempt to start nmap
	var r Runner
	r.options = &Options{}
	// nmap with empty cli shouldn't trigger any error
	res := result.NewResult()
	r.scanner = &scan.Scanner{}
	r.scanner.ScanResults = res
	assert.Nil(t, r.handleNmap())
	// nmap syntax error (this test might fail if nmap is not installed on the box)
	assert.Nil(t, r.handleNmap())
	r.scanner.ScanResults.SetPorts("127.0.0.1", []*port.Port{{Port: 8080, Protocol: protocol.TCP}})
	assert.Nil(t, r.handleNmap())
}
