package request

import (
	"bytes"
	"crypto/tls"
	"net"
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
	"github.com/wadeking98/gohammer/processors/request/transforms"
	"github.com/wadeking98/gohammer/processors/response"
	"github.com/wadeking98/gohammer/utils"
)

type ReqTemplate struct {
	url     string
	method  string
	headers []string
	body    string
}
type ReqAgentHttp struct {
	template      *ReqTemplate
	transformList transforms.TransformList
	client        *http.Client
}

func NewReqTemplate(reqUrl string, method string, headers []string, body string) *ReqTemplate {
	return &ReqTemplate{
		url:     reqUrl,
		method:  method,
		headers: headers,
		body:    body,
	}
}

func NewReqAgentHttp(reqUrl string, method string, headers []string, body string, proxy string, timeout int) *ReqAgentHttp {
	template := NewReqTemplate(reqUrl, method, headers, body)
	client := &http.Client{
		Timeout:       time.Duration(timeout * int(time.Second)),
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 500,
			MaxConnsPerHost:     500,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(timeout * int(time.Second)),
			}).DialContext,
			TLSHandshakeTimeout: time.Duration(timeout * int(time.Second)),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         "",
			},
		},
	}

	var transportConfig http.Transport
	// add http proxy if exists
	if proxy != "" {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			fmt.Printf("Error: invalid proxy url %s", proxy)
			os.Exit(1)
		}
		transportConfig.Proxy = http.ProxyURL(proxyUrl)
	}

	client.Transport = &transportConfig

	transformList := transforms.NewTransformList()
	return &ReqAgentHttp{
		template:      template,
		client:        client,
		transformList: transformList,
	}
}

func (req *ReqAgentHttp) GetUrl() string {
	return req.template.url
}

func (req *ReqAgentHttp) GetMethod() string {
	return req.template.method
}

func (req *ReqAgentHttp) GetHeaders() []string {
	return req.template.headers
}

func (req *ReqAgentHttp) GetBody() string {
	return req.template.body
}

func (req *ReqAgentHttp) Send(positions []string, counter *utils.Counter, args *config.Args) (bool, error) {

	// apply positions from wordlist to request template
	procReq := procReqTemplate(req, positions, args)
	reqTemplate, err := http.NewRequest(procReq.method, procReq.url, bytes.NewBuffer([]byte(procReq.body)))

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
	resp, err := req.client.Do(reqTemplate)
	elapsed := int(time.Since(start) / time.Millisecond)
	if elapsed > args.RequestOptions.Timeout {
		fmt.Printf("Elapsed: %d    \tTimeout:%d\n", elapsed, args.RequestOptions.Timeout)
	}
	r := response.NewRespFromHttp(resp, elapsed, err)
	// not an error created by 301 without Location header
	if r.Code == 0 && err != nil {
		return false, err
	}

	r.ProcessResp(positions, counter, args)

	return true, nil
}

// ProcReqTemplate applies words from a set of wordlists to a request template
// Returns the parsed request template
func procReqTemplate(reqAgent *ReqAgentHttp, positions []string, args *config.Args) *ReqTemplate {
	url := utils.ReplacePosition(reqAgent.GetUrl(), positions, args.RecursionOptions.RecursePosition)
	method := utils.ReplacePosition(reqAgent.GetMethod(), positions, args.RecursionOptions.RecursePosition)
	var headers []string
	for _, header := range reqAgent.GetHeaders() {
		headers = append(headers, utils.ReplacePosition(header, positions, args.RecursionOptions.RecursePosition))
	}
	body := utils.ReplacePosition(reqAgent.GetBody(), positions, args.RecursionOptions.RecursePosition)

	if len(args.TransformOptions.Transforms) > 0 {
		// apply transforms too
		var transformPostions []string
		// process transforms into postions array
		for _, transTemplate := range args.TransformOptions.Transforms {
			transformPostions = append(transformPostions, transforms.ApplyTransforms(transTemplate, reqAgent.transformList, positions, args))
		}
		url = transforms.ReplaceTranformPosition(url, transformPostions)
		method = transforms.ReplaceTranformPosition(method, transformPostions)
		var transformedHeaders []string
		for _, header := range headers {
			transformedHeaders = append(headers, transforms.ReplaceTranformPosition(header, transformPostions))
		}
		headers = transformedHeaders
		body = transforms.ReplaceTranformPosition(body, transformPostions)
	}
	return NewReqTemplate(url, method, headers, body)
}
