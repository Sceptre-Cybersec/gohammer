package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type argStruct struct {
	url     string
	threads int
	method  string
	brute   bool
	headers string
	files   []string
	timeout int
}

type request struct {
	method  string
	url     string
	headers string
	body    io.Reader
}

func sendReq(positionsChan chan []string, reqTemplate request, timeout int) {
	client := http.Client{
		Timeout: time.Duration(timeout * int(time.Second)),
	}
	// while receiving input on channel
	for positions, ok := <-positionsChan; ok; positions, ok = <-positionsChan {
		parsedReq := procReqTemplate(reqTemplate, positions)
		req, err := http.NewRequest(parsedReq.method, parsedReq.url, parsedReq.body)
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
		client.Do(req)
	}
}

func replacePosition(str string, positions []string) string {
	r, _ := regexp.Compile(`@(\d+)@`)

	res := r.FindAllStringSubmatch(str, -1)
	if len(res) > 0 {
		for _, match := range res {
			posIdx, err := strconv.Atoi(match[1])
			if err != nil {
				fmt.Println("Error converting position index to string")
			}
			str = strings.Replace(str, match[0], positions[posIdx], -1)
		}
	}
	return str
}

func procReqTemplate(req request, positions []string) request {
	parsedReq := req
	parsedReq.url = replacePosition(parsedReq.url, positions)
	parsedReq.method = replacePosition(parsedReq.method, positions)
	parsedReq.headers = replacePosition(parsedReq.headers, positions)
	return parsedReq
}

func procFiles(fnames []string, currString []string, reqChan chan []string) {

	//send string to channel
	if len(fnames) <= 0 {
		fmt.Println(currString)
		reqChan <- currString
		return
	}

	f, err := os.Open(fnames[0])
	if err != nil {
		fmt.Printf("Error opening %s", fnames[0])
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		newString := append(currString, scanner.Text())
		procFiles(fnames[1:], newString, reqChan)
	}
}

func parseArgs(args []string) argStruct {
	var progArgs argStruct
	flag.StringVar(&(progArgs.url), "u", "http://127.0.0.1/", "The Url of the website to fuzz")
	flag.IntVar(&(progArgs.threads), "t", 10, "The number of concurrect threads")
	flag.StringVar(&(progArgs.headers), "H", "", "Comma seperated list of headers")
	flag.StringVar(&(progArgs.method), "method", "GET", "The type of http request: GET, or POST")
	flag.BoolVar(&(progArgs.brute), "brute", true, "Whether or not to use wordlists for brute forcing. If false, runs through all wordlists line by line.")
	flag.IntVar(&(progArgs.timeout), "to", 10, "The timeout for each web request")
	flag.Parse()
	progArgs.files = flag.Args()
	return progArgs
}

func main() {
	var wg sync.WaitGroup
	reqChan := make(chan []string)
	args := parseArgs(os.Args)

	reqTemplate := request{
		url:     args.url,
		method:  args.method,
		headers: args.headers,
	}

	for i := 0; i < args.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReq(reqChan, reqTemplate, args.timeout)
		}()
	}

	procFiles(args.files, nil, reqChan)
	close(reqChan)
	wg.Wait()
}
