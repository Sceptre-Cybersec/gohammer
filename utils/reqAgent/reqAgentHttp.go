package reqagent

import (
	"bytes"
	"context"

	// "crypto/tls"
	"fmt"
	// "net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/utils"
)

type ReqAgentHttp struct {
	url     string
	method  string
	headers string
	body    string
}

func NewReqAgentHttp(url string, method string, headers string, body string) *ReqAgentHttp {
	return &ReqAgentHttp{
		url:     url,
		method:  method,
		headers: headers,
		body:    body,
	}
}

func (req *ReqAgentHttp) Send(positions []string, counter *utils.Counter, args *config.Args) (bool, error) {
	// send request using http or https, returns false if request failed
	// client := http.Client{
	// 	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	// 	Timeout:       time.Duration(args.Timeout),
	// 	Transport: &http.Transport{
	// 		ForceAttemptHTTP2:   true,
	// 		MaxIdleConns:        1000,
	// 		MaxIdleConnsPerHost: 500,
	// 		MaxConnsPerHost:     500,
	// 		DialContext: (&net.Dialer{
	// 			Timeout: time.Duration(args.Timeout),
	// 		}).DialContext,
	// 		TLSHandshakeTimeout: time.Duration(args.Timeout),
	// 		TLSClientConfig: &tls.Config{
	// 			InsecureSkipVerify: true,
	// 			Renegotiation:      tls.RenegotiateOnceAsClient,
	// 			ServerName:         "",
	// 		},
	// 	},
	// }
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
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
	headers := strings.Split(procReq.headers, ",")
	for _, header := range headers {
		splitHeaders := strings.Split(header, ": ")
		if len(splitHeaders) >= 2 {
			if splitHeaders[0] == "Host" {
				reqTemplate.Host = splitHeaders[1]
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
	r := utils.NewRespFromHttp(resp, elapsed, err)
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
	url := utils.ReplacePosition(reqAgent.url, positions, args.RecursePosition)
	method := utils.ReplacePosition(reqAgent.method, positions, args.RecursePosition)
	headers := utils.ReplacePosition(reqAgent.headers, positions, args.RecursePosition)
	body := utils.ReplacePosition(reqAgent.body, positions, args.RecursePosition)
	return NewReqAgentHttp(url, method, headers, body)
}
