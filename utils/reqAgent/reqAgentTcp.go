package reqagent

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/utils"
)

type TcpAddress struct {
	address string
	port    int
	ssl     bool
}

type ReqAgentTcp struct {
	address TcpAddress
	rawReq  string
}

func NewReqAgentTcp(rawReq string, url string) *ReqAgentTcp {
	agent := ReqAgentTcp{
		address: urlToTcpAddress(url),
		rawReq:  rawReq,
	}
	return &agent
}

func (req *ReqAgentTcp) Send(positions []string, counter *utils.Counter, args *config.Args) (bool, error) {
	// send request using raw tcp or tls, returns false if request failed
	var connClient io.ReadWriter
	if req.address.ssl {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		d := net.Dialer{Timeout: time.Duration(args.Timeout)}
		connClientTls, err := tls.DialWithDialer(&d, "tcp", fmt.Sprintf("%s:%d", req.address.address, req.address.port), conf)
		if err != nil {
			return false, err
		}
		defer connClientTls.Close()
		connClient = connClientTls
	} else {
		connClientTcp, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", req.address.address, req.address.port), time.Duration(args.Timeout))
		if err != nil {
			return false, err
		}
		defer connClientTcp.Close()
		connClient = connClientTcp
	}
	// apply wordlist and send
	parsedReq := procTcpReqTemplate(req.rawReq, positions, args.RecursePosition)

	start := time.Now()
	fmt.Fprint(connClient, parsedReq)

	//listen for reply and construct response
	message := ""
	reader := bufio.NewReader(connClient)
	for {
		messageLine, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		message += messageLine
	}
	elapsed := int(time.Since(start) / time.Millisecond)
	r := utils.NewRespFromTcp(message, elapsed)

	if r.Code == 0 {
		return false, nil
	}

	r.ProcessResp(positions, counter, args)
	return true, nil
}

// ProcTcpReqTemplate corrects the Content-Length header when sending http post data
func procTcpReqTemplate(req string, positions []string, recursePos int) string {
	parsedReq := utils.ReplacePosition(req, positions, recursePos)
	contLenRx := regexp.MustCompile(`(?mi)Content-Length: \d+\r\n\r\n(.*)`)
	res := contLenRx.FindStringSubmatch(parsedReq)
	if res != nil {
		postCont := res[1]
		contLen := len(postCont)
		contLenReplRx := regexp.MustCompile(`(?mi)Content-Length: \d+`)
		parsedReq = contLenReplRx.ReplaceAllString(parsedReq, fmt.Sprintf("Content-Length: %d", contLen))
	}
	return parsedReq
}

func urlToTcpAddress(url string) TcpAddress {
	// returns port number and if ssl is being used
	ssl := false
	var port int
	var err error
	var address string

	//get port number
	rxPort, _ := regexp.Compile(`:(\d+)`)
	res := rxPort.FindStringSubmatch(url)
	if res != nil {
		portString := res[1]
		port, err = strconv.Atoi(portString)
		if err != nil {
			fmt.Printf("Error invalid port: %s\n", portString)
			os.Exit(1)
		}
	}

	//get address
	rxAddress, _ := regexp.Compile(`https?://([^:/]+)`)
	addrMatch := rxAddress.FindStringSubmatch(url)
	if addrMatch != nil {
		address = addrMatch[1]
	} else {
		fmt.Printf("Could not parse URL Address %s\n", url)
	}

	//get ssl
	if strings.HasPrefix(url, "https://") {
		ssl = true
		if port == 0 {
			port = 443
		}
	} else if port == 0 {
		port = 80
	}

	return TcpAddress{address: address, port: port, ssl: ssl}
}
