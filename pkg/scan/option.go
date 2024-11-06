package scan

import (
	"time"

	"github.com/iami317/sx/pkg/result"
)

// Options of the scan
type Options struct {
	Timeout       time.Duration
	Retries       int
	Rate          int
	PortThreshold int
	ExcludeCdn    bool
	OutputCdn     bool
	ExcludedIps   []string
	Proxy         string
	ProxyAuth     string
	Stream        bool
	OnReceive     result.ResultFn
	OnProgress    result.ProgressFn
}
