package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/utils"
	reqagent "github.com/wadeking98/gohammer/utils/reqAgent"
)

func sendReq(positionsChan chan []string, agent reqagent.ReqAgent, counter *utils.Counter, args *config.Args) {
	// while receiving input on channel
	for positions, ok := <-positionsChan; ok; positions, ok = <-positionsChan {
		// just need a shallow copy since we are only copying timeout
		tempArgs := *args

		//retry request x times unless it succeeds
		success := false
		r := args.Retry
		var err error
		var status bool

		//request retry section
		index := 1
		for ; r >= 0 && !success; r-- {
			// scale the timeout based on retry requests, starts with
			if tempArgs.Retry > 0 {
				tempArgs.Timeout = index * args.Timeout / tempArgs.Retry
			}
			status, err = agent.Send(positions, counter, &tempArgs)
			success = success || status
			index = index + 1
		}
		// fmt.Println(index)
		if !success {
			counter.ErrorCounterInc()
			fmt.Println(err.Error())
		} else {
			counter.CounterInc()
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
func recurseFuzz(agent reqagent.ReqAgent, counter *utils.Counter, args *config.Args) {
	for i := 0; len(utils.FrontierQ) > 0; i++ { // iteratively search web directories
		if len(utils.FrontierQ[0])-1 > args.Depth && args.Depth > 0 {
			if args.Depth > 1 { //if recursion is on then display message
				fmt.Printf("\r\033[KSkipping Recursion Job Due to Depth Exceeded on: %s\n", strings.Join(utils.FrontierQ[0], ""))
			}
		} else {
			if i > 0 {
				// fmt.Print("\r\033[K\n")
				fmt.Printf("\r\033[KStarting Recursion Job on: %s\n", strings.Join(utils.FrontierQ[0], ""))
				counter.Reset()
			}
			reqChan := make(chan []string)
			var wg sync.WaitGroup
			for i := 0; i < args.Threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sendReq(reqChan, agent, counter, args)
				}()
			}
			procFiles(args.Files, nil, reqChan, args.Brute, args.E)
			close(reqChan)
			wg.Wait()
		}
		utils.FrontierLock.Lock()
		utils.FrontierQ = utils.FrontierQ[1:]
		utils.FrontierLock.Unlock()
	}
}

// parseArgs processes and packs command line arguments into a struct
func parseArgs(args []string) *config.Args {
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
		fmt.Println("-rd\tThe recursion depth of the search. Set to 0 for unlimited recursion [Default:1]")
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
	flag.IntVar(&(progArgs.Depth), "rd", 1, "")
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
	return &progArgs
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
	loadDefaults(args)

	//load request file contents
	reqFileContent := ""
	if args.ReqFile != "" {
		fileBytes, err := ioutil.ReadFile(args.ReqFile)
		if err != nil {
			fmt.Printf("Error: couldn't open %s\n", args.ReqFile)
			os.Exit(1)
		}
		reqFileContent = utils.RemoveTrailingNewline(string(fileBytes))
	}
	args.Timeout = args.Timeout * int(time.Second)
	// apply filter codes
	args.Mc = utils.SetDif(args.Mc, args.Fc)
	// parse user supplied extensions
	// if no extensions then "" gets added anyway
	if len(args.E) <= 0 {
		//add blank extension
		args.E = append(args.E, "")
	}
	utils.TotalJobs = utils.GetNumJobs(args.Files, args.Brute, args.E)

	var agent reqagent.ReqAgent
	if reqFileContent != "" { // initialize as tcp or http agent
		agent = reqagent.NewReqAgentTcp(reqFileContent, args.Url)
	} else {
		agent = reqagent.NewReqAgentHttp(args.Url, args.Method, strings.Join(args.Headers, ","), args.Data)
	}

	counter := utils.NewCounter()
	go utils.PrintProgressLoop(counter)
	recurseFuzz(agent, counter, args)
	utils.PrintProgress(counter)
	fmt.Println()
}
