package utils

import (
	"bufio"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var FrontierQ []string = []string{""}
var FrontierLock sync.Mutex

var CounterAvg []int

var Counter int = 0
var CounterPrev int = 0
var counterLock sync.Mutex

var ErrorCounter int = 0
var errorCounterLock sync.Mutex

var TotalJobs int

type Request struct {
	Method  string
	Url     string
	Headers string
	Body    string
}

type TcpAddress struct {
	Address string
	Port    int
	Ssl     bool
}

func replacePosition(str string, positions []string, recursePos int) string {
	r, _ := regexp.Compile(`@(\d+)@`)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Error: position number does not match number of files")
			os.Exit(1)
		}
	}()
	res := r.FindAllStringSubmatch(str, -1)
	for _, match := range res {
		posIdx, err := strconv.Atoi(match[1])
		if err != nil {
			fmt.Println("Error converting position index to integer")
			os.Exit(1)
		}
		baseStr := ""
		if posIdx == recursePos {
			baseStr = FrontierQ[0]
		}
		str = strings.Replace(str, match[0], baseStr+positions[posIdx], -1)
	}
	return str
}

func PrintProgressLoop() {
	for {
		time.Sleep(1 * time.Second)
		CounterAvg = append(CounterAvg, Counter-CounterPrev)
		CounterPrev = Counter
		//use 3 second average
		if len(CounterAvg) > 3 {
			CounterAvg = CounterAvg[1:]
		}
		PrintProgress()
	}
}

func PrintProgress() {
	avg := 0
	sum := 0
	for _, c := range CounterAvg {
		sum += c
	}
	if len(CounterAvg) > 0 {
		avg = sum / len(CounterAvg)
	} else {
		avg = Counter
	}
	fmt.Printf("\rProgress: %d/%d - %d/s - Errors: %d    \t", Counter, TotalJobs, avg, ErrorCounter)
}

func CheckCodeFound(codeNumber int, positions []string, recursePosition int, mc []string) {
	mcFound := false
	code := strconv.Itoa(codeNumber)
	for _, i := range mc {
		if code == i {
			mcFound = true
			break
		}
	}

	if mcFound {
		displayPos := make([]string, len(positions))
		copy(displayPos, positions)
		displayPos[recursePosition] = FrontierQ[0] + positions[recursePosition]
		fmt.Printf("\r%s - %s                                \n", code, displayPos)
		PrintProgress()
	}
}

func GetTcpRespCode(resp string) string {
	respRx := regexp.MustCompile(`HTTP/\S+\s(\d+)`)
	match := respRx.FindStringSubmatch(resp)
	var code string
	if match != nil {
		code = match[1]
	}
	return code
}

func UrlToTcpAddress(url string) TcpAddress {
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

	return TcpAddress{Address: address, Port: port, Ssl: ssl}
}

func CounterInc() {
	counterLock.Lock()
	Counter++
	counterLock.Unlock()
}

func ErrorCounterInc() {
	errorCounterLock.Lock()
	ErrorCounter++
	errorCounterLock.Unlock()
}

func ProcReqTemplate(req Request, positions []string, recursePos int) Request {
	parsedReq := req
	parsedReq.Url = replacePosition(parsedReq.Url, positions, recursePos)
	parsedReq.Method = replacePosition(parsedReq.Method, positions, recursePos)
	parsedReq.Headers = replacePosition(parsedReq.Headers, positions, recursePos)
	parsedReq.Body = replacePosition(parsedReq.Body, positions, recursePos)
	return parsedReq
}

// func AddCarriageReturns(req string) string {
// 	carriageRx := regexp.MustCompile(`\r\n`)
// 	fixedReq := carriageRx.ReplaceAllString(req, "\r\n")
// 	fmt.Println(fixedReq)
// 	return fixedReq
// }

func RemoveTrailingNewline(req string) string {
	fixedReq := req
	// get requests normally end with double CRLF
	if !strings.HasSuffix(req, "\r\n\r\n") && strings.HasSuffix(req, "\r\n") {
		fixedReq = fixedReq[:len(fixedReq)-2]
	}
	return fixedReq
}

func ProcTcpReqTemplate(req string, positions []string, recursePos int) string {
	parsedReq := replacePosition(req, positions, recursePos)
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

func IsRecurseHttp(resp *http.Response, err error) (bool, int) {
	var code int
	if err != nil {
		if strings.HasSuffix(err.Error(), "response missing Location header") {
			rx, _ := regexp.Compile(`(\d+) response missing Location header`)
			res := rx.FindStringSubmatch(err.Error())
			codeString := res[1]
			code, err = strconv.Atoi(codeString)
			if err != nil {
				fmt.Printf("Error converting response code %s to integer\n", codeString)
				return false, 0
			}
		}
	} else {
		code = resp.StatusCode
	}
	recurse := isRecurse(code)
	return recurse, code
}

func IsRecurseTcp(resp string) (bool, int) {
	codeString := GetTcpRespCode(resp)
	code, err := strconv.Atoi(codeString)
	if err != nil {
		fmt.Printf("Error converting response code %s to integer\n", codeString)
		return false, 0
	}
	recurse := isRecurse(code)
	return recurse, code
}

func isRecurse(code int) bool {
	codes := []int{301, 302}
	ret := false
	for _, c := range codes {
		if c == code {
			ret = true
			break
		}
	}
	return ret
}

func SetDif(a, b []string) (diff []string) {
	m := make(map[string]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return
}

func GetNumJobs(fnames []string, brute bool, extensions []string) int {
	var files []*bufio.Scanner
	for _, fname := range fnames {
		f, err := os.Open(fname)
		if err != nil {
			fmt.Printf("Error opening %s", fnames[0])
			os.Exit(1)
		}
		files = append(files, bufio.NewScanner(f))
		defer f.Close()
	}
	// there will always be at least one file
	numJobs := getFileLen(files[0])
	for _, f := range files[1:] {
		len := getFileLen(f)
		if len == 0 {
			fmt.Println("Error: empty file")
			os.Exit(1)
		}
		if brute {
			numJobs *= len
		} else {
			numJobs = int(math.Min(float64(numJobs), float64(len)))
		}
	}
	// extensions will always have at least one element in it (the empty extension: '')
	numJobs *= len(extensions)

	return numJobs
}

func getFileLen(r *bufio.Scanner) int {
	// return the length of the file
	count := 0
	for r.Scan() {
		count++
	}
	return count
}
