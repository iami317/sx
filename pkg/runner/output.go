package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/iami317/sx/pkg/port"
	"github.com/pkg/errors"
)

// Result contains the result for a host
type Result struct {
	Host      string    `json:"host,omitempty" csv:"host"`
	IP        string    `json:"ip,omitempty" csv:"ip"`
	Port      int       `json:"port,omitempty" csv:"port"`
	Protocol  string    `json:"protocol,omitempty" csv:"protocol"`
	TLS       bool      `json:"tls,omitempty" csv:"tls"`
	IsCDNIP   bool      `json:"cdn,omitempty" csv:"cdn"`
	CDNName   string    `json:"cdn-name,omitempty" csv:"cdn-name"`
	TimeStamp time.Time `json:"timestamp,omitempty" csv:"timestamp"`
}

type jsonResult struct {
	Result
	PortNumber int    `json:"port"`
	Protocol   string `json:"protocol"`
	TLS        bool   `json:"tls"`
}

func (r *Result) JSON() ([]byte, error) {
	data := jsonResult{}
	data.TimeStamp = r.TimeStamp
	if r.Host != r.IP {
		data.Host = r.Host
	}
	data.IP = r.IP
	data.IsCDNIP = r.IsCDNIP
	data.CDNName = r.CDNName
	data.PortNumber = r.Port
	data.Protocol = r.Protocol
	data.TLS = r.TLS

	return json.Marshal(data)
}

var (
	NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")
	headers              = []string{}
)

func (r *Result) CSVHeaders() ([]string, error) {
	ty := reflect.TypeOf(*r)
	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		csvTag := field.Tag.Get("csv")
		if !slices.Contains(headers, csvTag) {
			headers = append(headers, csvTag)
		}
	}
	return headers, nil
}

func (r *Result) CSVFields() ([]string, error) {
	var fields []string
	vl := reflect.ValueOf(*r)
	ty := reflect.TypeOf(*r)
	for i := 0; i < vl.NumField(); i++ {
		field := vl.Field(i)
		csvTag := ty.Field(i).Tag.Get("csv")
		fieldValue := field.Interface()
		if slices.Contains(headers, csvTag) {
			fields = append(fields, fmt.Sprint(fieldValue))
		}
	}
	return fields, nil
}

// WriteHostOutput writes the output list of host ports to an io.Writer
func WriteHostOutput(host string, ports []*port.Port, outputCDN bool, cdnName string, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, p := range ports {
		sb.WriteString(host)
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(p.Port))
		if outputCDN && cdnName != "" {
			sb.WriteString(" [" + cdnName + "]")
		}
		sb.WriteString("")
		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteJSONOutput writes the output list of subdomain in JSON to an io.Writer
func WriteJSONOutput(host, ip string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	data := jsonResult{}
	data.TimeStamp = time.Now().UTC()
	if host != ip {
		data.Host = host
	}
	data.IP = ip
	if outputCDN {
		data.IsCDNIP = isCdn
		data.CDNName = cdnName
	}
	for _, p := range ports {
		data.PortNumber = p.Port
		data.Protocol = p.Protocol.String()
		data.TLS = p.TLS
		if err := encoder.Encode(&data); err != nil {
			return err
		}
	}
	return nil
}
