package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
)

type argStruct struct {
	url     string
	threads int
	method  string
	brute   bool
	files   []string
}

func sendReq(reqChan chan []string, url string, method string) {
	// while receiving input on channel
	for reqData, ok := <-reqChan; ok; reqData, ok = <-reqChan {
		if method == "POST" {
			var buff io.Reader
			http.Post(fmt.Sprintf(url+"%s", reqData), "text/html", buff)
		} else {
			http.Get(fmt.Sprintf(url+"%s", reqData))
		}
	}
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
	flag.StringVar(&(progArgs.method), "method", "GET", "The type of http request: GET, or POST")
	flag.BoolVar(&(progArgs.brute), "brute", true, "Whether or not to use wordlists for brute forcing. If false, runs through all wordlists line by line.")
	flag.Parse()
	progArgs.files = flag.Args()

	return progArgs
}

func main() {
	var wg sync.WaitGroup
	reqChan := make(chan []string)
	args := parseArgs(os.Args)

	for i := 0; i < args.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReq(reqChan, args.url, args.method)
		}()
	}

	procFiles(args.files, nil, reqChan)
	close(reqChan)
	wg.Wait()
}
