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

	"github.com/wadeking98/gohammer/config"
	. "github.com/wadeking98/gohammer/utils"
)

// sendReqTcp sends an http request using a tcp connection.
// This function is used when sending from a request file.
// Returns true if request succeeds
func sendReqTcp(positions []string, reqTemplate Request, reqFileContent string, tcpConn TcpAddress, args config.Args) bool {
	// send request using raw tcp or tls, returns false if request failed
	var connClient io.ReadWriter
	if tcpConn.Ssl {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		d := net.Dialer{Timeout: time.Duration(args.Timeout) * time.Second}
		connClientTls, err := tls.DialWithDialer(&d, "tcp", fmt.Sprintf("%s:%d", tcpConn.Address, tcpConn.Port), conf)
		if err != nil {
			ErrorCounterInc()
			return false
		}
		defer connClientTls.Close()
		connClient = connClientTls
	} else {
		connClientTcp, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", tcpConn.Address, tcpConn.Port), time.Duration(args.Timeout*int(time.Second)))
		if err != nil {
			ErrorCounterInc()
			return false
		}
		defer connClientTcp.Close()
		connClient = connClientTcp
	}
	// apply wordlist and send
	parsedReq := ProcTcpReqTemplate(reqFileContent, positions, args.RecursePosition)
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

	respBodyText := TcpRespToRespBody(message)
	processResp(code, recurse, positions, respBodyText, args)
	return true
}

// sendReqHttp sends a http request using the built in http library in golang.
// if returns true if the request is successful
func sendReqHttp(positions []string, reqTemplate Request, args config.Args) bool {
	// send request using http or https, returns false if request failed
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       time.Duration(args.Timeout * int(time.Second)),
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 500,
			MaxConnsPerHost:     500,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(args.Timeout * int(time.Second)),
			}).DialContext,
			TLSHandshakeTimeout: time.Duration(args.Timeout * int(time.Second)),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         "",
			},
		},
	}
	parsedReq := ProcReqTemplate(reqTemplate, positions, args.RecursePosition)
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

	var respBodyText []byte
	if resp != nil {
		respBodyText, _ = ioutil.ReadAll(resp.Body)
	}

	processResp(code, recurse, positions, string(respBodyText), args)

	return true
}

// processResp increments the progress counter and adds the directory to the queue if it is a web directory
func processResp(code int, recurse bool, positions []string, resp string, args config.Args) {
	CounterInc()

	sizes := SizeRespBody(resp)
	passed := CheckFound(code, sizes, args)

	if passed {
		displayPos := make([]string, len(positions))
		copy(displayPos, positions)
		displayPos[args.RecursePosition] = FrontierQ[0] + positions[args.RecursePosition]
		fmt.Printf("\r%d - %s    Size:%d    Words:%d    Lines:%d                        \n", code, displayPos, sizes[0], sizes[1], sizes[2])
		PrintProgress()
	}

	if recurse {
		FrontierLock.Lock()
		FrontierQ = append(FrontierQ, FrontierQ[0]+positions[args.RecursePosition]+args.RecurseDelimeter)
		FrontierLock.Unlock()
	}
}

// sendReq is a wrapper function for sendReqHttp and sendReqTcp.
// It will retry failed requests a specified number of times.
func sendReq(positionsChan chan []string, reqTemplate Request, reqFileContent string, tcpConn TcpAddress, args config.Args) {

	// while receiving input on channel
	for positions, ok := <-positionsChan; ok; positions, ok = <-positionsChan {
		//retry request x times unless it succeeds
		success := false
		r := args.Retry
		for ; r > 0 && !success; r-- {
			//request file is not set, use standard http mode
			if reqFileContent == "" {
				success = sendReqHttp(positions, reqTemplate, args)
			} else { //send reqFile over tcp socket
				success = sendReqTcp(positions, reqTemplate, reqFileContent, tcpConn, args)
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
func recurseFuzz(reqTemplate Request, reqFileContent string, tcpConn TcpAddress, args config.Args) {
	for i := 0; i <= args.Depth && len(FrontierQ) > 0; i++ { // iteratively search web directories
		reqChan := make(chan []string)
		var wg sync.WaitGroup
		for i := 0; i < args.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sendReq(reqChan, reqTemplate, reqFileContent, tcpConn, args)
			}()
		}

		procFiles(args.Files, nil, reqChan, args.Brute, args.E)
		close(reqChan)
		wg.Wait()
		FrontierLock.Lock()
		FrontierQ = FrontierQ[1:]
		FrontierLock.Unlock()
	}
}

// parseArgs processes and packs command line arguments into a struct
func parseArgs(args []string) config.Args {
	var progArgs config.Args
	flag.Usage = func() {
		fmt.Println()
		fmt.Println("Usage: gohammer [options] wordlist1 wordlist2 ...")
		fmt.Println()
		fmt.Println("Request Options:")
		fmt.Println("-u\tThe URL of the website to fuzz [Default:'http://127.0.0.1/']")
		fmt.Println("-d\tThe data to provide in the request")
		fmt.Println("-f\tThe request template file to use (Usually a request file saved from BurpSuite)")
		fmt.Println("-H\tList of headers, one per flag: -H 'Header1: value1' -H 'Header2: value2'")
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
		fmt.Println("-fs\tFilter http response by size")
		fmt.Println("-fw\tFilter http response by number of words")
		fmt.Println("-fl\tFilter http response by number of lines")
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

	flag.StringVar(&(progArgs.Url), "u", "http://127.0.0.1/", "")
	flag.StringVar(&(progArgs.Data), "d", "", "")
	flag.IntVar(&(progArgs.Threads), "t", 10, "")
	flag.StringVar(&(progArgs.ReqFile), "f", "", "")
	flag.IntVar(&(progArgs.Depth), "rd", 0, "")
	flag.IntVar(&(progArgs.RecursePosition), "rp", 0, "")
	flag.StringVar(&(progArgs.RecurseDelimeter), "rdl", "/", "")
	flag.Var(&(progArgs.Headers), "H", "")
	flag.StringVar(&(progArgs.Method), "method", "GET", "")
	flag.BoolVar(&(progArgs.Brute), "brute", true, "")
	flag.IntVar(&(progArgs.Timeout), "to", 5, "")
	flag.Var(&(progArgs.Mc), "mc", "")
	flag.Var(&(progArgs.Fc), "fc", "")
	flag.Var(&(progArgs.Fs), "fs", "")
	flag.Var(&(progArgs.Fw), "fw", "")
	flag.Var(&(progArgs.Fl), "fl", "")
	flag.Var(&(progArgs.E), "e", "")
	flag.IntVar(&(progArgs.Retry), "retry", 3, "")
	flag.Parse()
	progArgs.Files = flag.Args()
	return progArgs
}

func loadDefaults(args *config.Args) {
	if len(args.Mc) <= 0 {
		args.Mc.Set("200,204,301,302,303,307,308,401,403,405,500")
	}
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
	loadDefaults(&args)

	//load request file contents
	var tcpConn TcpAddress
	reqFileContent := ""
	if args.ReqFile != "" {
		fileBytes, err := ioutil.ReadFile(args.ReqFile)
		if err != nil {
			fmt.Printf("Error: couldn't open %s\n", args.ReqFile)
			os.Exit(1)
		}
		reqFileContent = RemoveTrailingNewline(string(fileBytes))
		tcpConn = UrlToTcpAddress(args.Url)
	}

	// create request template from command line args
	reqTemplate := Request{
		Url:     args.Url,
		Method:  args.Method,
		Headers: strings.Join(args.Headers, ","),
		Body:    args.Data,
	}
	// apply filter codes
	args.Mc = SetDif(args.Mc, args.Fc)
	// parse user supplied extensions
	// if no extensions then "" gets added anyway
	if len(args.E) <= 0 {
		//add blank extension
		args.E = append(args.E, "")
	}
	TotalJobs = GetNumJobs(args.Files, args.Brute, args.E)
	go PrintProgressLoop()
	recurseFuzz(reqTemplate, reqFileContent, tcpConn, args)
	PrintProgress()
	fmt.Println()
}
