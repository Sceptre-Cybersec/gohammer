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

// replacePosition scans a string for the position marker and replaces it with a word
// from the corresponding wordlist
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

// PrintProgressLoop prints the current progress to stdout every second and adds the current request/second to an array
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

// PrintProgress prints the formatted progress string to stdout and computes the request/second average using an array
// populated by PrintProgressLoop
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

// CheckCodeFound determines if a response code is found based on match codes in the param (mc),
// and logs it to stdout if it is found
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

// GetTcpRespCode parses the response code from a raw tcp response.
// Returns the response code as a string
func GetTcpRespCode(resp string) string {
	respRx := regexp.MustCompile(`HTTP/\S+\s(\d+)`)
	match := respRx.FindStringSubmatch(resp)
	var code string
	if match != nil {
		code = match[1]
	}
	return code
}

// Converts a URL to an address for a tcp socket.
// Returns a struct containing the address, port, and if tls is in use
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

// CounterInc increments the request progress counter
func CounterInc() {
	counterLock.Lock()
	Counter++
	counterLock.Unlock()
}

// ErrorCounterInc increments the request error counter whenever a request fails
func ErrorCounterInc() {
	errorCounterLock.Lock()
	ErrorCounter++
	errorCounterLock.Unlock()
}

// ProcReqTemplate applies words from a set of wordlists to a request template
// Returns the parsed request template
func ProcReqTemplate(req Request, positions []string, recursePos int) Request {
	parsedReq := req
	parsedReq.Url = replacePosition(parsedReq.Url, positions, recursePos)
	parsedReq.Method = replacePosition(parsedReq.Method, positions, recursePos)
	parsedReq.Headers = replacePosition(parsedReq.Headers, positions, recursePos)
	parsedReq.Body = replacePosition(parsedReq.Body, positions, recursePos)
	return parsedReq
}

// RemoveTrailingNewLine corrects the request file. Some text editors add a trailing new line to a file after saving.
// This logic removes the new line added by some text editors.
func RemoveTrailingNewline(req string) string {
	fixedReq := req
	// get requests normally end with double CRLF
	if !strings.HasSuffix(req, "\r\n\r\n") && strings.HasSuffix(req, "\r\n") {
		fixedReq = fixedReq[:len(fixedReq)-2]
	}
	return fixedReq
}

// ProcTcpReqTemplate corrects the Content-Length header when sending http post data
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

// IsRecurseHttp determines if a given http response signifies a web directory
// Returns a tuple containing the bool that tells if the response is from a web directory, and the status code of the http response
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

// IsRecurseTcp determines if a given tcp response signifies a web directory
// Returns a tuple containing the boolean that tells if the response is from a web directory, and the status code of the http response
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

// isRecurse determines if the response codes signify a web directory
// Returns true if the response code is from a web directory
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

// SetDif determines the set difference of two arrays
// Returns the resulting difference
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

// GetNumJobs computes the number of jobs based on the file length and number of fuzzing positions
// Returns the total number of jobs
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

// getFileLen computes the length of user provided wordlists
// Returns the length of a given file
func getFileLen(r *bufio.Scanner) int {
	// return the length of the file
	count := 0
	for r.Scan() {
		count++
	}
	return count
}
