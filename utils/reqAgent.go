package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"strconv"

	// "crypto/tls"
	"fmt"
	// "net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/wadeking98/gohammer/config"
)

type ReqAgentHttp struct {
	url     string
	method  string
	headers []string
	body    string
}

func NewReqAgentHttp(url string, method string, headers []string, body string) *ReqAgentHttp {
	return &ReqAgentHttp{
		url:     url,
		method:  method,
		headers: headers,
		body:    body,
	}
}

func (req *ReqAgentHttp) GetUrl() string {
	return req.url
}

func (req *ReqAgentHttp) GetMethod() string {
	return req.method
}

func (req *ReqAgentHttp) GetHeaders() []string {
	return req.headers
}

func (req *ReqAgentHttp) GetBody() string {
	return req.body
}

func (req *ReqAgentHttp) Send(positions []string, counter *Counter, args *config.Args) (bool, error) {
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	var transportConfig http.Transport
	// add http proxy if exists
	if args.Proxy != "" {
		proxyUrl, err := url.Parse(args.Proxy)
		if err != nil {
			fmt.Printf("Error: invalid proxy url %s", args.Proxy)
			os.Exit(1)
		}
		transportConfig.Proxy = http.ProxyURL(proxyUrl)
	}

	//disable ssl checking
	transportConfig.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client.Transport = &transportConfig

	// apply positions from wordlist to request template
	procReq := procReqTemplate(req, positions, args)
	reqTemplate, err := http.NewRequest(procReq.method, procReq.url, bytes.NewBuffer([]byte(procReq.body)))
	ctx := context.Background()
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, time.Duration(args.Timeout))
	defer cancel()
	reqTemplate = reqTemplate.WithContext(ctx)
	if err != nil {
		fmt.Println("Error making request")
		os.Exit(1)
	}
	//add headers
	headers := procReq.headers
	for _, header := range headers {
		splitHeaders := strings.Split(header, ": ")
		if len(splitHeaders) >= 2 {
			if strings.EqualFold(splitHeaders[0], "Host") {
				reqTemplate.Host = splitHeaders[1]
			} else if strings.EqualFold(splitHeaders[0], "Content-Length") {
				// adjust content length
				reqTemplate.Header.Set(splitHeaders[0], strconv.Itoa(len(procReq.body)))
			} else {
				reqTemplate.Header.Set(splitHeaders[0], splitHeaders[1])
			}
		}
	}

	start := time.Now()
	resp, err := client.Do(reqTemplate)
	elapsed := int(time.Since(start) / time.Millisecond)
	if elapsed > args.Timeout {
		fmt.Printf("Elapsed: %d    \tTimeout:%d\n", elapsed, args.Timeout)
	}
	r := NewRespFromHttp(resp, elapsed, err)
	// not an error created by 301 without Location header
	if r.Code == 0 && err != nil {
		return false, err
	}

	r.ProcessResp(positions, counter, args)

	return true, nil
}

// ProcReqTemplate applies words from a set of wordlists to a request template
// Returns the parsed request template
func procReqTemplate(reqAgent *ReqAgentHttp, positions []string, args *config.Args) *ReqAgentHttp {
	url := ReplacePosition(reqAgent.url, positions, args.RecursePosition)
	method := ReplacePosition(reqAgent.method, positions, args.RecursePosition)
	var headers []string
	for _, header := range reqAgent.headers {
		headers = append(headers, ReplacePosition(header, positions, args.RecursePosition))
	}
	body := ReplacePosition(reqAgent.body, positions, args.RecursePosition)
	return NewReqAgentHttp(url, method, headers, body)
}
