package runner

import "time"

const (
	DefaultPortTimeoutSynScan     = time.Duration(500) * time.Millisecond
	DefaultPortTimeoutConnectScan = time.Duration(5) * time.Second

	DefaultRateSynScan     = 1000
	DefaultRateConnectScan = 1500

	DefaultRetriesSynScan     = 3
	DefaultRetriesConnectScan = 3

	SynScan             = "s"
	ConnectScan         = "c"
	DefautStatsInterval = 5
)
