package runner

import (
	"fmt"
	"github.com/projectdiscovery/goflags"
	"os"
	"strconv"
	"strings"

	"github.com/iami317/sx/pkg/port"
	"github.com/iami317/sx/pkg/protocol"
	"github.com/pkg/errors"
)

const portListStrParts = 2

// List of default ports
const (
	Full        = "1-65535"
	NmapTop100  = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
	NmapTop1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
)

var Probes = goflags.StringSlice{"7", "9", "13", "21", "22", "23", "25", "26", "37", "53", "79", "80", "81", "88", "106", "110", "111", "113", "119", "135", "139", "143", "144", "179", "199",
	"389", "427", "443", "444", "445",
	"465", "513", "514", "515", "543", "544", "548", "554", "587", "631", "646", "873", "990", "993", "995", "1025", "1026", "1026", "1027", "1028", "1029", "1110", "1433", "1720", "1723",
	"1755", "1900", "2000", "2001", "2049", "2121", "2717", "3000", "3128", "3306", "3389", "3986", "4899", "5000", "5009", "5051", "5060", "5101", "5190", "5357", "5432", "5631", "5666", "5800", "5900", "6000", "6001",
	"6646", "7070", "8000", "8008", "8009", "8080", "8081", "8443", "8888", "9100", "9999", "10000", "32768", "49152", "49153", "49154", "49155", "49156", "49157"}

// ParsePorts parses the list of ports and creates a port map
func ParsePorts(options *Options) ([]*port.Port, error) {
	var portsFileMap, portsCLIMap, topPortsCLIMap, portsConfigList []*port.Port

	// If the user has specfied a ports file, use it
	if options.PortsFile != "" {
		data, err := os.ReadFile(options.PortsFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		ports, err := parsePortsList(string(data))
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		portsFileMap, err = excludePorts(options, ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
	}

	// If the user has specfied top ports, use them as well
	if options.TopPorts != "" {
		switch strings.ToLower(options.TopPorts) {
		case "full": // If the user has specfied full ports, use them
			var err error
			ports, err := parsePortsList(Full)
			if err != nil {
				return nil, fmt.Errorf("could not read ports: %s", err)
			}
			topPortsCLIMap, err = excludePorts(options, ports)
			if err != nil {
				return nil, fmt.Errorf("could not read ports: %s", err)
			}
		case "100": // If the user has specfied 100, use them
			ports, err := parsePortsList(NmapTop100)
			if err != nil {
				return nil, fmt.Errorf("could not read ports: %s", err)
			}
			topPortsCLIMap, err = excludePorts(options, ports)
			if err != nil {
				return nil, fmt.Errorf("could not read ports: %s", err)
			}
		case "1000": // If the user has specfied 1000, use them
			ports, err := parsePortsList(NmapTop1000)
			if err != nil {
				return nil, fmt.Errorf("could not read ports: %s", err)
			}
			topPortsCLIMap, err = excludePorts(options, ports)
			if err != nil {
				return nil, fmt.Errorf("could not read ports: %s", err)
			}
		default:
			return nil, errors.New("invalid top ports option")
		}
	}

	// If the user has specfied ports option, use them too
	if options.Ports != "" {
		// "-" equals to all ports
		if options.Ports == "-" {
			// Parse the custom ports list provided by the user
			options.Ports = "1-65535"
		}
		ports, err := parsePortsList(options.Ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		portsCLIMap, err = excludePorts(options, ports)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
	}

	// merge all the specified ports (meaningless if "all" is used)
	ports := merge(portsFileMap, portsCLIMap, topPortsCLIMap, portsConfigList)

	// By default scan top 100 ports only
	if len(ports) == 0 {
		portsList, err := parsePortsList(NmapTop100)
		if err != nil {
			return nil, fmt.Errorf("could not read ports: %s", err)
		}
		m, err := excludePorts(options, portsList)
		if err != nil {
			return nil, err
		}
		return m, nil
	}

	return ports, nil
}

// excludePorts excludes the list of ports from the exclusion list
func excludePorts(options *Options, ports []*port.Port) ([]*port.Port, error) {
	if options.ExcludePorts == "" {
		return ports, nil
	}

	var filteredPorts []*port.Port

	// Exclude the ports specified by the user in exclusion list
	excludedPortsCLI, err := parsePortsList(options.ExcludePorts)
	if err != nil {
		return nil, fmt.Errorf("could not read exclusion ports: %s", err)
	}

	for _, port := range ports {
		found := false
		for _, excludedPort := range excludedPortsCLI {
			if excludedPort.Port == port.Port && excludedPort.Protocol == port.Protocol {
				found = true
				break
			}
		}
		if !found {
			filteredPorts = append(filteredPorts, port)
		}
	}
	return filteredPorts, nil
}

func parsePortsSlice(ranges []string) ([]*port.Port, error) {
	var ports []*port.Port
	for _, r := range ranges {
		r = strings.TrimSpace(r)

		portProtocol := protocol.TCP
		if strings.HasPrefix(r, "u:") {
			portProtocol = protocol.UDP
			r = strings.TrimPrefix(r, "u:")
		}

		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != portListStrParts {
				return nil, fmt.Errorf("invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[1])
			}

			if p1 > p2 || p2 > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				port := &port.Port{Port: i, Protocol: portProtocol}
				ports = append(ports, port)
			}
		} else {
			portNumber, err := strconv.Atoi(r)
			if err != nil || portNumber > 65535 {
				return nil, fmt.Errorf("invalid port number: '%s'", r)
			}
			port := &port.Port{Port: portNumber, Protocol: portProtocol}
			ports = append(ports, port)
		}
	}

	// dedupe ports
	seen := make(map[string]struct{})
	var dedupedPorts []*port.Port
	for _, port := range ports {
		if _, ok := seen[port.String()]; ok {
			continue
		}
		seen[port.String()] = struct{}{}
		dedupedPorts = append(dedupedPorts, port)
	}

	return dedupedPorts, nil
}

func parsePortsList(data string) ([]*port.Port, error) {
	return parsePortsSlice(strings.Split(data, ","))
}

func merge(slices ...[]*port.Port) []*port.Port {
	var result []*port.Port
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}
