package main

import (
	"bufio"
	"bytes"
	"flag"
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

type argStruct struct {
	url              string
	threads          int
	method           string
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
}

type request struct {
	method  string
	url     string
	headers string
	body    string
}

var frontierQ []string = []string{""}
var frontierLock sync.Mutex

var counter int = 0
var counterLock sync.Mutex

var totalJobs int

func setDif(a, b []string) (diff []string) {
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

func isRecurse(resp *http.Response, err error) (bool, int) {
	codes := []int{301, 302}
	recurse := false
	var code int
	if err != nil {
		if strings.HasSuffix(err.Error(), "response missing Location header") {
			rx, _ := regexp.Compile(`(\d+) response missing Location header`)
			res := rx.FindAllStringSubmatch(err.Error(), -1)
			codeString := res[0][1]
			code, err = strconv.Atoi(codeString)
			if err != nil {
				fmt.Printf("Error converting response code %s to integer\n", codeString)
				os.Exit(1)
			}
		}
	} else {
		code = resp.StatusCode
	}
	for _, c := range codes {
		if c == code {
			recurse = true
		}
	}
	return recurse, code
}

func sendReq(positionsChan chan []string, reqTemplate request, timeout int, mc []string, recursePosition int, recurseDelim string) {
	client := http.Client{
		Timeout: time.Duration(timeout * int(time.Second)),
	}
	// while receiving input on channel
	for positions, ok := <-positionsChan; ok; positions, ok = <-positionsChan {
		parsedReq := procReqTemplate(reqTemplate, positions, recursePosition)
		req, err := http.NewRequest(parsedReq.method, parsedReq.url, bytes.NewBuffer([]byte(parsedReq.body)))
		if err != nil {
			fmt.Println("Error making request")
			os.Exit(1)
		}
		//add headers
		headers := strings.Split(parsedReq.headers, ",")
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

		counterLock.Lock()
		counter++
		counterLock.Unlock()

		recurse, code := isRecurse(resp, err)
		if code == 0 && err != nil {
			fmt.Println(err)
			continue
		}

		mcFound := false
		for _, i := range mc {
			if strconv.Itoa(code) == i {
				mcFound = true
			}
		}

		if mcFound {
			displayPos := make([]string, len(positions))
			copy(displayPos, positions)
			displayPos[recursePosition] = frontierQ[0] + positions[recursePosition]
			fmt.Printf("\r%d - %s                                 \n", code, displayPos)
			printProgress()
		}
		if recurse {
			frontierLock.Lock()
			frontierQ = append(frontierQ, frontierQ[0]+positions[recursePosition]+recurseDelim)
			frontierLock.Unlock()
		}
	}
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
			baseStr = frontierQ[0]
		}
		str = strings.Replace(str, match[0], baseStr+positions[posIdx], -1)
	}
	return str
}

func procReqTemplate(req request, positions []string, recursePos int) request {
	parsedReq := req
	parsedReq.url = replacePosition(parsedReq.url, positions, recursePos)
	parsedReq.method = replacePosition(parsedReq.method, positions, recursePos)
	parsedReq.headers = replacePosition(parsedReq.headers, positions, recursePos)
	parsedReq.body = replacePosition(parsedReq.body, positions, recursePos)
	return parsedReq
}

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

func getNumJobs(fnames []string, brute bool, extensions []string) int {
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

func recurseFuzz(threads int, timeout int, files []string, brute bool, reqTemplate request, mc []string, depth int, recursePos int, recurseDelim string, extensions []string) {
	for i := 0; i <= depth && len(frontierQ) > 0; i++ { // iteratively search web directories
		reqChan := make(chan []string)
		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sendReq(reqChan, reqTemplate, timeout, mc, recursePos, recurseDelim)
			}()
		}

		procFiles(files, nil, reqChan, brute, extensions)
		close(reqChan)
		wg.Wait()
		frontierLock.Lock()
		frontierQ = frontierQ[1:]
		frontierLock.Unlock()
	}
}

func printProgressLoop() {
	for {
		time.Sleep(1 * time.Second)
		printProgress()
	}
}

func printProgress() {
	fmt.Printf("\rProgress: %d/%d", counter, totalJobs)
}

func parseArgs(args []string) argStruct {
	var progArgs argStruct
	flag.StringVar(&(progArgs.url), "u", "http://127.0.0.1/", "The Url of the website to fuzz")
	flag.StringVar(&(progArgs.data), "d", "", "The data to provide in the request (Usually post)")
	flag.IntVar(&(progArgs.threads), "t", 10, "The number of concurrect threads")
	flag.IntVar(&(progArgs.depth), "rd", 0, "The recursion depth of the search")
	flag.IntVar(&(progArgs.recursePosition), "rp", 0, "The position to recurse on")
	flag.StringVar(&(progArgs.recurseDelimeter), "rdl", "/", "The string to append to the base string when recursing")
	flag.StringVar(&(progArgs.headers), "H", "", "Comma seperated list of headers: 'Header1: value1,Header2: value2'")
	flag.StringVar(&(progArgs.method), "method", "GET", "The type of http request: GET, or POST")
	flag.BoolVar(&(progArgs.brute), "brute", true, "Whether or not to use wordlists for brute forcing. If false, runs through all wordlists line by line.")
	flag.IntVar(&(progArgs.timeout), "to", 10, "The timeout for each web request")
	flag.StringVar(&(progArgs.mc), "mc", "200,204,301,302,307,401,403,405,500", "The http response codes to match")
	flag.StringVar(&(progArgs.fc), "fc", "", "The http response codes to filter")
	flag.StringVar(&(progArgs.e), "e", "", "The comma separated file extensions to fuzz with. Example: '.txt,.php,.html'")
	flag.Parse()
	progArgs.files = flag.Args()
	return progArgs
}

func main() {
	fmt.Println("+-------------------------------------+")
	fmt.Println("|GOHAMMER - A Web Fuzzer Written in GO|")
	fmt.Println("+-------------------------------------+")

	args := parseArgs(os.Args)

	reqTemplate := request{
		url:     args.url,
		method:  args.method,
		headers: args.headers,
		body:    args.data,
	}
	mc := setDif(strings.Split(args.mc, ","), strings.Split(args.fc, ","))
	extensions := strings.Split(args.e, ",")
	extensions = append(extensions, "") //add blank extensions
	totalJobs = getNumJobs(args.files, args.brute, extensions)
	go printProgressLoop()
	recurseFuzz(args.threads, args.timeout, args.files, args.brute, reqTemplate, mc, args.depth, args.recursePosition, args.recurseDelimeter, extensions)
	printProgress()
	fmt.Println()
}
