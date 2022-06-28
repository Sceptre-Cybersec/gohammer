package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/wadeking98/gohammer/utils"
)

type argStruct struct {
	url              string
	threads          int
	method           string
	reqFile          string
	brute            bool
	headers          string
	files            []string
	mc               string
	fc               string
	timeout          int
	e                string
	data             string
	depth            int
	recursePosition  int
	recurseDelimeter string
	retry            int
}

// sendReqTcp sends an http request using a tcp connection.
// This function is used when sending from a request file.
// Returns true if request succeeds
func sendReqTcp(positions []string, reqTemplate Request, reqFileContent string, tcpConn TcpAddress, timeout int, mc []string, recursePosition int, recurseDelim string) bool {
	// send request using raw tcp or tls, returns false if request failed
	var connClient io.ReadWriter
	if tcpConn.Ssl {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		d := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
		connClientTls, err := tls.DialWithDialer(&d, "tcp", fmt.Sprintf("%s:%d", tcpConn.Address, tcpConn.Port), conf)
		if err != nil {
			ErrorCounterInc()
			return false
		}
		defer connClientTls.Close()
		connClient = connClientTls
	} else {
		connClientTcp, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", tcpConn.Address, tcpConn.Port), time.Duration(timeout*int(time.Second)))
		if err != nil {
			ErrorCounterInc()
			return false
		}
		defer connClientTcp.Close()
		connClient = connClientTcp
	}
	// apply wordlist and send
	parsedReq := ProcTcpReqTemplate(reqFileContent, positions, recursePosition)
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

	recurse, code := IsRecurseTcp(message)
	// not an error created by 301 without Location header
	if code == 0 {
		ErrorCounterInc()
		return false
	}

	applyRecurse(code, recurse, positions, recursePosition, recurseDelim, mc)
	return true
}

// sendReqHttp sends a http request using the built in http library in golang.
// if returns true if the request is successful
func sendReqHttp(positions []string, reqTemplate Request, timeout int, mc []string, recursePosition int, recurseDelim string) bool {
	// send request using http or https, returns false if request failed
	client := http.Client{
		Timeout: time.Duration(timeout * int(time.Second)),
	}
	parsedReq := ProcReqTemplate(reqTemplate, positions, recursePosition)
	req, err := http.NewRequest(parsedReq.Method, parsedReq.Url, bytes.NewBuffer([]byte(parsedReq.Body)))
	if err != nil {
		fmt.Println("Error making request")
		os.Exit(1)
	}
	//add headers
	headers := strings.Split(parsedReq.Headers, ",")
	for _, header := range headers {
		splitHeaders := strings.Split(header, ": ")
		if len(splitHeaders) >= 2 {
			if splitHeaders[0] == "Host" {
				req.Host = splitHeaders[1]
			} else {
				req.Header.Set(splitHeaders[0], splitHeaders[1])
			}
		}
	}
	resp, err := client.Do(req)

	recurse, code := IsRecurseHttp(resp, err)
	// not an error created by 301 without Location header
	if code == 0 && err != nil {
		ErrorCounterInc()
		return false
	}

	applyRecurse(code, recurse, positions, recursePosition, recurseDelim, mc)

	return true
}

// applyRecurse increments the progress counter and adds the directory to the queue if it is a web directory
func applyRecurse(code int, recurse bool, positions []string, recursePosition int, recurseDelim string, mc []string) {
	CounterInc()

	CheckCodeFound(code, positions, recursePosition, mc)
	if recurse {
		FrontierLock.Lock()
		FrontierQ = append(FrontierQ, FrontierQ[0]+positions[recursePosition]+recurseDelim)
		FrontierLock.Unlock()
	}
}

// sendReq is a wrapper function for sendReqHttp and sendReqTcp.
// It will retry failed requests a specified number of times.
func sendReq(positionsChan chan []string, reqTemplate Request, reqFileContent string, tcpConn TcpAddress, timeout int, mc []string, recursePosition int, recurseDelim string, retry int) {

	// while receiving input on channel
	for positions, ok := <-positionsChan; ok; positions, ok = <-positionsChan {
		//retry request x times unless it succeeds
		success := false
		r := retry
		for ; r > 0 && !success; r-- {
			//request file is not set, use standard http mode
			if reqFileContent == "" {
				success = sendReqHttp(positions, reqTemplate, timeout, mc, recursePosition, recurseDelim)
			} else { //send reqFile over tcp socket
				success = sendReqTcp(positions, reqTemplate, reqFileContent, tcpConn, timeout, mc, recursePosition, recurseDelim)
			}
		}

	}
}

// procExtensions adds use specified file extensions onto fuzzing data and then sends the modified data
// to the request channel which is picked up by the sendReq methods
func procExtensions(currString []string, extensions []string, reqChan chan []string) {
	if len(extensions) <= 0 {
		reqChan <- currString
	}
	//append extensions to all fuzzing positions
	for _, ext := range extensions {
		var extCurrString []string
		for _, position := range currString {
			extCurrString = append(extCurrString, position+ext)
		}
		reqChan <- extCurrString
	}
}

// procFiles opens user supplied wordlists and adds words from each wordlist to user specified positions
func procFiles(fnames []string, currString []string, reqChan chan []string, brute bool, extensions []string) {
	if brute { //use recursive strategy
		//send string to channel
		if len(fnames) <= 0 {
			procExtensions(currString, extensions, reqChan)
			return
		}

		f, err := os.Open(fnames[0])
		if err != nil {
			fmt.Printf("Error opening %s", fnames[0])
			os.Exit(1)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			newString := append(currString, scanner.Text())
			procFiles(fnames[1:], newString, reqChan, brute, extensions)
		}
	} else { // read all files line by line
		var files []*os.File
		var scanners []*bufio.Scanner
		for _, fname := range fnames { //open all files
			f, err := os.Open(fname)
			if err != nil {
				fmt.Printf("Error opening %s", fname)
				os.Exit(1)
			}
			files = append(files, f)
			scanner := bufio.NewScanner(f)
			scanner.Split(bufio.ScanLines)
			scanners = append(scanners, scanner)
		}

		defer func(files []*os.File) { //close all files
			for _, f := range files {
				f.Close()
			}
		}(files)

		EOF := false
		for !EOF {
			var currLine []string
			for i := 0; i < len(scanners); i++ {
				scanner := scanners[i]
				scanner.Scan()
				content := scanner.Text()
				EOF = content == ""
				currLine = append(currLine, content)
			}
			// send line to requests
			if !EOF {
				procExtensions(currLine, extensions, reqChan)
			}
		}
	}
}

// recurseFuzz starts the main fuzzing logic, it starts sendReq threads listening on a request channel and
// calls procFiles to start sending data over the channels
func recurseFuzz(threads int, timeout int, files []string, brute bool, reqTemplate Request, reqFileContent string, tcpConn TcpAddress, mc []string, depth int, recursePos int, recurseDelim string, extensions []string, retry int) {
	for i := 0; i <= depth && len(FrontierQ) > 0; i++ { // iteratively search web directories
		reqChan := make(chan []string)
		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sendReq(reqChan, reqTemplate, reqFileContent, tcpConn, timeout, mc, recursePos, recurseDelim, retry)
			}()
		}

		procFiles(files, nil, reqChan, brute, extensions)
		close(reqChan)
		wg.Wait()
		FrontierLock.Lock()
		FrontierQ = FrontierQ[1:]
		FrontierLock.Unlock()
	}
}

// parseArgs processes and packs command line arguments into a struct
func parseArgs(args []string) argStruct {
	var progArgs argStruct
	flag.Usage = func() {
		fmt.Println()
		fmt.Println("Usage: gohammer [options] wordlist1 wordlist2 ...")
		fmt.Println()
		fmt.Println("Request Options:")
		fmt.Println("-u\tThe URL of the website to fuzz [Default:'http://127.0.0.1/']")
		fmt.Println("-d\tThe data to provide in the request")
		fmt.Println("-f\tThe request template file to use (Usually a request file saved from BurpSuite)")
		fmt.Println("-H\tComma seperated list of headers: 'Header1: value1,Header2: value2'")
		fmt.Println("-to\tThe timeout for each web request [Default:5]")
		fmt.Println("-method\tThe type of http request: Usually GET, or POST [Default:'GET']")
		fmt.Println()
		fmt.Println("General Options:")
		fmt.Println("-t\tThe number of concurrent threads [Default:10]")
		fmt.Println("-retry\tThe number of times to retry a failed request before giving up [Default:3]")
		fmt.Println()
		fmt.Println("Recursion Options:")
		fmt.Println("-rd\tThe recursion depth of the search [Default:0]")
		fmt.Println("-rp\tThe position to recurse on [Default:0]")
		fmt.Println("-rdl\tThe string to append to the base string when recursing [Default:'/']")
		fmt.Println()
		fmt.Println("Filter Options:")
		fmt.Println("-mc\tThe http response codes to match [Default:'200,204,301,302,307,401,403,405,500']")
		fmt.Println("-fc\tThe http response codes to filter")
		fmt.Println()
		fmt.Println("Wordlist Options:")
		fmt.Println("-brute\tWhether or not to use wordlists for brute forcing. If false, runs through all wordlists line by line. [Default:true]")
		fmt.Println("-e\tThe comma separated file extensions to fuzz with. Example: '.txt,.php,.html'")
		fmt.Println()
		fmt.Println()
		fmt.Println("Example Usage:")
		fmt.Println("gohammer -u http://127.0.0.1/@0@ -t 32 -e .txt,.html,.php /home/me/myWordlist.txt")
		fmt.Println("gohammer -u https://some.site.com/ -method POST -d '{\"user\":\"@0@\", \"password\":\"@1@\"}' -t 32 /home/me/usernames.txt /home/me/passwords.txt")
		fmt.Println("gohammer -u https://some.site.com/ -f /home/me/Desktop/burpReq.txt -t 32 /home/me/usernames.txt /home/me/passwords.txt")
	}

	flag.StringVar(&(progArgs.url), "u", "http://127.0.0.1/", "")
	flag.StringVar(&(progArgs.data), "d", "", "")
	flag.IntVar(&(progArgs.threads), "t", 10, "")
	flag.StringVar(&(progArgs.reqFile), "f", "", "")
	flag.IntVar(&(progArgs.depth), "rd", 0, "")
	flag.IntVar(&(progArgs.recursePosition), "rp", 0, "")
	flag.StringVar(&(progArgs.recurseDelimeter), "rdl", "/", "")
	flag.StringVar(&(progArgs.headers), "H", "", "")
	flag.StringVar(&(progArgs.method), "method", "GET", "")
	flag.BoolVar(&(progArgs.brute), "brute", true, "")
	flag.IntVar(&(progArgs.timeout), "to", 5, "")
	flag.StringVar(&(progArgs.mc), "mc", "200,204,301,302,307,401,403,405,500", "")
	flag.StringVar(&(progArgs.fc), "fc", "", "")
	flag.StringVar(&(progArgs.e), "e", "", "")
	flag.IntVar(&(progArgs.retry), "retry", 3, "")
	flag.Parse()
	progArgs.files = flag.Args()
	return progArgs
}

// banner prints the title banner
func banner() {
	fmt.Println("+----------------------------------------+")
	fmt.Println("|GOHAMMER 🔨 - A Web Fuzzer Written in GO|")
	fmt.Println("+----------------------------------------+")
}

func main() {
	banner()

	args := parseArgs(os.Args)

	//load request file contents
	var tcpConn TcpAddress
	reqFileContent := ""
	if args.reqFile != "" {
		fileBytes, err := ioutil.ReadFile(args.reqFile)
		if err != nil {
			fmt.Printf("Error: couldn't open %s\n", args.reqFile)
			os.Exit(1)
		}
		reqFileContent = RemoveTrailingNewline(string(fileBytes))
		tcpConn = UrlToTcpAddress(args.url)
	}

	// create request template from command line args
	reqTemplate := Request{
		Url:     args.url,
		Method:  args.method,
		Headers: args.headers,
		Body:    args.data,
	}
	// apply filter codes
	mc := SetDif(strings.Split(args.mc, ","), strings.Split(args.fc, ","))
	// parse user supplied extensions
	extensions := strings.Split(args.e, ",")
	// if no extensions then "" gets added anyway
	if args.e != "" {
		//add blank extension
		extensions = append(extensions, "")
	}
	TotalJobs = GetNumJobs(args.files, args.brute, extensions)
	go PrintProgressLoop()
	recurseFuzz(args.threads, args.timeout, args.files, args.brute, reqTemplate, reqFileContent, tcpConn, mc, args.depth, args.recursePosition, args.recurseDelimeter, extensions, args.retry)
	PrintProgress()
	fmt.Println()
}
