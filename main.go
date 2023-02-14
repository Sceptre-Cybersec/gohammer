package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/processors/request"
	"github.com/wadeking98/gohammer/utils"
)

func sendReq(positionsChan chan []string, agent *request.ReqAgentHttp, counter *utils.Counter, args *config.Args) {
	positions, ok := <-positionsChan
	// while receiving input on channel
	for ok {

		//retry request x times unless it succeeds
		success := false
		r := args.GeneralOptions.Retry
		var status bool

		//request retry section
		index := 1
		var err error
		for ; r >= 0 && !success; r-- {
			status, err = agent.Send(positions, counter, args)
			success = success || status
			index = index + 1
		}
		if !success {
			counter.ErrorCounterInc()
			args.OutputOptions.Logger.Println(err.Error())
		} else {
			counter.CounterInc()
			// TODO add error logging here
		}
		positions, ok = <-positionsChan
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
func procFiles(currString []string, reqChan chan []string, args *config.Args, index int) {
	fnames := args.WordlistOptions.Files[index:]
	if !args.WordlistOptions.NoBrute { //use recursive strategy
		//send string to channel
		if len(fnames) <= 0 {
			procExtensions(currString, args.WordlistOptions.Extensions, reqChan)
			return
		}

		f, err := os.Open(fnames[0])
		if err != nil {
			args.OutputOptions.Logger.Printf("Error opening %s\n", fnames[0])
			os.Exit(1)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			newString := append(currString, scanner.Text())
			procFiles(newString, reqChan, args, index+1)
		}
	} else { // read all files line by line
		var files []*os.File
		var scanners []*bufio.Scanner
		for _, fname := range fnames { //open all files
			f, err := os.Open(fname)
			if err != nil {
				args.OutputOptions.Logger.Printf("Error opening %s\n", fname)
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
				procExtensions(currLine, args.WordlistOptions.Extensions, reqChan)
			}
		}
	}
}

// recurseFuzz starts the main fuzzing logic, it starts sendReq threads listening on a request channel and
// calls procFiles to start sending data over the channels
func recurseFuzz(agent *request.ReqAgentHttp, counter *utils.Counter, args *config.Args) {
	for i := 0; len(utils.FrontierQ) > 0; i++ { // iteratively search web directories
		if len(utils.FrontierQ[0]) > args.RecursionOptions.Depth && args.RecursionOptions.Depth > 0 {
			if args.RecursionOptions.Depth > 1 { //if recursion is on then display message
				args.OutputOptions.Logger.Printf("\r\033[KSkipping Recursion Job Due to Depth Exceeded on: %s\n", strings.Join(utils.FrontierQ[0], ""))
			}
		} else {
			if i > 0 {
				// log.Print("\r\033[K\n")
				args.OutputOptions.Logger.Printf("\r\033[KStarting Recursion Job on: %s\n", strings.Join(utils.FrontierQ[0], ""))
				counter.Reset()
			}
			reqChan := make(chan []string, 1000)
			var wg sync.WaitGroup
			for i := 0; i < args.GeneralOptions.Threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sendReq(reqChan, agent, counter, args)
				}()
			}
			if args.GeneralOptions.Dos {
				for { //infinite loop for denial of service
					procFiles(nil, reqChan, args, 0)
				}
			} else {
				procFiles(nil, reqChan, args, 0)
			}
			close(reqChan)
			wg.Wait()
		}
		utils.FrontierLock.Lock()
		utils.FrontierQ = utils.FrontierQ[1:]
		utils.FrontierLock.Unlock()
	}
}

// parseArgs processes and packs command line arguments into a struct
func parseArgs(args []string, log *utils.Logger) *config.Args {
	var progArgs config.Args
	flag.Usage = func() {
		log.Println("")
		log.Println("Usage: gohammer [options] wordlist1 wordlist2 ...")
		log.Println("")
		log.Println("Request Options:")
		log.Println("-u\tThe URL of the website to fuzz [Default:'http://127.0.0.1/']")
		log.Println("-d\tThe data to provide in the request")
		log.Println("-f\tThe request template file to use (Usually a request file saved from BurpSuite)")
		log.Println("-H\tList of headers, one per flag: -H 'Header1: value1' -H 'Header2: value2'")
		log.Println("-to\tThe timeout for each web request [Default:5]")
		log.Println("-method\tThe type of http request: Usually GET, or POST [Default:'GET']")
		log.Println("-proxy\tThe proxy to send the requests through: Example http://127.0.0.1:8080 [Default: no proxy]")
		log.Println("")
		log.Println("General Options:")
		log.Println("-t\tThe number of concurrent threads [Default:10]")
		log.Println("-retry\tThe number of times to retry a failed request before giving up [Default:3]")
		log.Println("-dos\tRun a denial of service attack (for stress testing) [Default:false]")
		log.Println("")
		log.Println("Recursion Options:")
		log.Println("-rd\tThe recursion depth of the search. Set to 0 for unlimited recursion, 1 for no recursion [Default:1]")
		log.Println("-rp\tThe position to recurse on [Default:0]")
		log.Println("-rdl\tThe string to append to the base string when recursing [Default:'/']")
		log.Println("-rc\tResponse codes to recurse on [Default:'301,302,303,307,308']")
		log.Println("")
		log.Println("Filter Options:")
		log.Println("-mc\tThe http response codes to match [Default:'200,204,301,302,307,401,403,405,500']")
		log.Println("-ms\tMatch http response by size")
		log.Println("-mw\tMatch http response by number of words")
		log.Println("-ml\tMatch http response by number of lines")
		log.Println("-mr\tMatch http response by regular expression in response body")
		log.Println("-mt\tMatch responses that take longer than or equal to the specified time in miliseconds")
		log.Println("-fc\tThe http response codes to filter")
		log.Println("-fs\tFilter http response by size")
		log.Println("-fw\tFilter http response by number of words")
		log.Println("-fl\tFilter http response by number of lines")
		log.Println("-fr\tFilter http response by regular expression in response body")
		log.Println("-ft\tFilter responses that take longer than or equal to the specified time in miliseconds")
		log.Println("")
		log.Println("Capture Options:")
		log.Println("-capture\tThe regular expression used to capture data from the response. Data is saved into cap.txt by default")
		log.Println("-capture-group\tThe regular expression group to capture 0 is the whole match and 1 is the first group, 2 is the second, etc")
		log.Println("-capture-file\tThe file to save the captured data [Default: 'cap.txt']")
		log.Println("")
		log.Println("Wordlist Options:")
		log.Println("-brute\tWhether or not to use wordlists for brute forcing. If false, runs through all wordlists line by line. [Default:true]")
		log.Println("-e\tThe comma separated file extensions to fuzz with. Example: '.txt,.php,.html'")
		log.Println("")
		log.Println("Transforms: Transforms are a versitile tool that allows you to use functions to mutate your wordlists on the fly")
		log.Println("-transform\tThe transform string to apply to your wordlist. To use multiple transforms, supply the flag multiple times: -transform <transform1> -transform <transform2> ...")
		log.Println("Transform Syntax:")
		log.Println("\t\t" + `For transforms there are two object types, functions and strings. A function is any string followed by opening and closing brackets,
		a string is anything else, (usually the argument to a function). For example, in the transform 'b64Encode(test)' b64Encode is the function and test is
		the string. Note that quotes are not used to define a string. Once a transform is defined it can be referenced in a similar way to a wordlist: @t0@, @t1@, @t2@, etc.
		Escape characters are supported but only needed for commas and braces: \, \( \)`)
		log.Println("")
		log.Println("Example Transforms: b64Encode(@0@:@1@), concat(urlEncode(b64Encode(test1)),@0@,urlEncode(@0@))")
		log.Println("")
		log.Println("Transform Functions:")
		log.Println("\tb64Encode(string): takes a single string and returns a base 64 encoding of the string")
		log.Println("\tb64Decode(string): takes a single base64 encoded string and returns the decoded string")
		log.Println("\turlEncode(string): takes a single string and encodes unsafe url characters")
		log.Println("\turlDecode(string): takes a single url encoded string and returns the decoded string")
		log.Println("\t" + `concat(string, string, string, ...): takes any number of strings and returns all the strings joined together. Note that
		concat is only needed when joinging the output of a function to another function, or to a string. It is not needed to join two strings`)
		log.Println("")
		log.Println("Example Usage:")
		log.Println("")
		log.Println("Standard Usage:")
		log.Println("gohammer -u http://127.0.0.1/@0@ -t 32 -e .txt,.html,.php /home/me/myWordlist.txt")
		log.Println("")
		log.Println("POST with data:")
		log.Println("gohammer -u https://some.site.com/ -method POST -d '{\"user\":\"@0@\", \"password\":\"@1@\"}' -t 32 /home/me/usernames.txt /home/me/passwords.txt")
		log.Println("")
		log.Println("Request from File:")
		log.Println("gohammer -u https://some.site.com/ -f /home/me/Desktop/burpReq.txt -t 32 /home/me/usernames.txt /home/me/passwords.txt")
		log.Println("")
		log.Println("Transform Usage (HTTP Basic Auth):")
		log.Println("gohammer -u https://some.site.com/ -H 'Authorization: @t0@' -transform 'b64Encode(@0@:@1@)' -t 32 /home/me/usernames.txt /home/me/passwords.txt")
	}
	// Request Options
	flag.StringVar(&(progArgs.RequestOptions.Url), "u", "http://127.0.0.1/", "")
	flag.StringVar(&(progArgs.RequestOptions.Data), "d", "", "")
	flag.StringVar(&(progArgs.RequestOptions.Proxy), "proxy", "", "")
	flag.StringVar(&(progArgs.RequestOptions.ReqFile), "f", "", "")
	flag.StringVar(&(progArgs.RequestOptions.Method), "method", "GET", "")
	flag.IntVar(&(progArgs.RequestOptions.Timeout), "to", 15, "")
	flag.Var(&(progArgs.RequestOptions.Headers), "H", "")

	// General Options
	flag.IntVar(&(progArgs.GeneralOptions.Threads), "t", 10, "")
	flag.IntVar(&(progArgs.GeneralOptions.Retry), "retry", 3, "")
	flag.BoolVar(&(progArgs.GeneralOptions.Dos), "dos", false, "")

	// Recursion Options
	flag.IntVar(&(progArgs.RecursionOptions.Depth), "rd", 1, "")
	flag.IntVar(&(progArgs.RecursionOptions.RecursePosition), "rp", 0, "")
	flag.StringVar(&(progArgs.RecursionOptions.RecurseDelimeter), "rdl", "/", "")
	flag.Var(&(progArgs.RecursionOptions.RecurseCode), "rc", "")

	// Wordlist Options
	flag.BoolVar(&(progArgs.WordlistOptions.NoBrute), "no-brute", false, "")
	flag.Var(&(progArgs.WordlistOptions.Extensions), "e", "")

	// Filter Options
	flag.Var(&(progArgs.FilterOptions.Mc), "mc", "")
	flag.Var(&(progArgs.FilterOptions.Ms), "ms", "")
	flag.Var(&(progArgs.FilterOptions.Mw), "mw", "")
	flag.Var(&(progArgs.FilterOptions.Ml), "ml", "")
	flag.StringVar(&(progArgs.FilterOptions.Mr), "mr", "", "")
	flag.IntVar(&(progArgs.FilterOptions.Mt), "mt", 0, "")
	flag.Var(&(progArgs.FilterOptions.Fc), "fc", "")
	flag.Var(&(progArgs.FilterOptions.Fs), "fs", "")
	flag.Var(&(progArgs.FilterOptions.Fw), "fw", "")
	flag.Var(&(progArgs.FilterOptions.Fl), "fl", "")
	flag.StringVar(&(progArgs.FilterOptions.Fr), "fr", "", "")
	flag.IntVar(&(progArgs.FilterOptions.Ft), "ft", 0, "")

	// Capture Options
	flag.StringVar(&(progArgs.CaptureOptions.Cap), "capture", "", "")
	flag.IntVar(&(progArgs.CaptureOptions.CapGroup), "capture-group", 0, "")
	flag.StringVar(&(progArgs.CaptureOptions.CapFile), "capture-file", "cap.txt", "")

	// Transform Options
	flag.Var(&(progArgs.TransformOptions.Transforms), "transform", "")

	flag.Parse()
	progArgs.WordlistOptions.Files = flag.Args()
	return &progArgs
}

func loadDefaults(args *config.Args) {
	if len(args.FilterOptions.Mc) <= 0 {
		args.FilterOptions.Mc.Set("200,204,301,302,303,307,308,400,401,403,405,500")
	}

	if len(args.RecursionOptions.RecurseCode) <= 0 {
		args.RecursionOptions.RecurseCode.Set("301,302,303,307,308")
	}
}

// banner prints the title banner
func banner(log *utils.Logger) {
	log.Println("+----------------------------------------+")
	log.Println("|GOHAMMER 🔨 - A Web Fuzzer Written in GO|")
	log.Println("+----------------------------------------+")
}

func main() {

	initLogger := utils.NewLogger(utils.INFO, os.Stdout)
	banner(initLogger)
	args := parseArgs(os.Args, initLogger)
	loadDefaults(args)

	log := utils.NewLogger(utils.INFO, os.Stdout)
	args.OutputOptions.Logger = log

	if len(args.WordlistOptions.Files) <= 0 && !args.GeneralOptions.Dos {
		log.Println("Please specify a wordlist unless you are using DOS mode")
		os.Exit(1)
	}

	//load request file contents
	reqFileContent := ""
	if args.RequestOptions.ReqFile != "" {
		fileBytes, err := ioutil.ReadFile(args.RequestOptions.ReqFile)
		if err != nil {
			log.Printf("Error: couldn't open %s\n", args.RequestOptions.ReqFile)
			os.Exit(1)
		}
		reqFileContent = utils.RemoveTrailingNewline(string(fileBytes))
	}
	args.RequestOptions.Timeout = args.RequestOptions.Timeout * int(time.Second)
	// apply filter codes
	args.FilterOptions.Mc = utils.SetDif(args.FilterOptions.Mc, args.FilterOptions.Fc)

	//add blank extension
	args.WordlistOptions.Extensions = append(args.WordlistOptions.Extensions, "")

	if !args.GeneralOptions.Dos {
		utils.TotalJobs = utils.GetNumJobs(args.WordlistOptions.Files, args.WordlistOptions.NoBrute, args.WordlistOptions.Extensions, log)
	}

	var agent *request.ReqAgentHttp
	if reqFileContent != "" { // initialize as http agent
		if strings.HasSuffix(args.RequestOptions.Url, "/") {
			args.RequestOptions.Url = args.RequestOptions.Url[:len(args.RequestOptions.Url)-1]
		}
		agent = request.FileToRequestAgent(reqFileContent, args.RequestOptions.Url, args.RequestOptions.Proxy, args.RequestOptions.Timeout)
	} else {
		agent = request.NewReqAgentHttp(args.RequestOptions.Url, args.RequestOptions.Method, args.RequestOptions.Headers, args.RequestOptions.Data, args.RequestOptions.Proxy, args.RequestOptions.Timeout)
	}

	counter := utils.NewCounter()
	go utils.PrintProgressLoop(counter, args.GeneralOptions.Dos, log)
	recurseFuzz(agent, counter, args)
	utils.PrintProgress(counter, args.GeneralOptions.Dos, log)
	log.Println("")
}
