package main

import (
	"bufio"
	"flag"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Sceptre-Cybersec/gohammer/config"
	"github.com/Sceptre-Cybersec/gohammer/processors/request"
	"github.com/Sceptre-Cybersec/gohammer/processors/response"
	"github.com/Sceptre-Cybersec/gohammer/utils"
)

func sendReq(positionsChan chan []string, agents []*request.ReqAgentHttp, counter *utils.Counter, args *config.Args) {
	positions, ok := <-positionsChan
	// while receiving input on channel
	for ok {
		previousResponses := []response.Resp{}

		// send each request in order
		for agent_idx, agent := range agents {
			//retry request x times unless it succeeds
			success := false
			r := args.GeneralOptions.Retry
			var status bool
			//request retry section
			index := 1
			var err error
			for ; r >= 0 && !success; r-- {
				utils.ReqLock.RLock()
				status, err = agent.Send(positions, counter, args, &previousResponses)
				utils.ReqLock.RUnlock()
				success = success || status
				index = index + 1
				if !success {
					time.Sleep(time.Duration((1000 / args.RequestOptions.Rate) * float64(time.Millisecond)))
				}
			}
			if !success {
				counter.ErrorCounterInc()
				if err != nil {
					args.OutputOptions.Logger.Println(err.Error())
				}
			} else if agent_idx >= len(agents)-1 {
				counter.CounterInc()
				// TODO add error logging here
			}
		}
		positions, ok = <-positionsChan
	}
}

// procExtensions adds use specified file extensions onto fuzzing data and then sends the modified data
// to the request channel which is picked up by the sendReq methods
func procExtensions(currString []string, extensions []string, reqChan chan []string, rateLimit float64) {
	if len(extensions) <= 0 {
		reqChan <- currString
	}
	//append extensions to all fuzzing positions
	for _, ext := range extensions {
		var extCurrString []string
		for _, position := range currString {
			extCurrString = append(extCurrString, position+ext)
		}
		if rateLimit > 0 {
			time.Sleep(time.Duration((1000 / rateLimit) * float64(time.Millisecond)))
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
			procExtensions(currString, args.WordlistOptions.Extensions, reqChan, args.RequestOptions.Rate)
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
				procExtensions(currLine, args.WordlistOptions.Extensions, reqChan, args.RequestOptions.Rate)
			}
		}
	}
}

// recurseFuzz starts the main fuzzing logic, it starts sendReq threads listening on a request channel and
// calls procFiles to start sending data over the channels
func recurseFuzz(agents []*request.ReqAgentHttp, counter *utils.Counter, args *config.Args) {
	// rateLimitMs := 1000 / args.RequestOptions.Rate
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
					sendReq(reqChan, agents, counter, args)
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
func parseArgs(_ []string, log *utils.Logger) *config.Args {
	var progArgs config.Args
	flag.Usage = func() {
		log.Println("")
		log.Println("Usage: gohammer [options] wordlist1 wordlist2 ...")
		log.Println("")
		log.Println("Request Options:")
		log.Println("-u\tThe URL of the website to fuzz [Default:'http://127.0.0.1/']")
		log.Println("-d\tThe data to provide in the request")
		log.Println("-f\tThe request template file to use. If multiple are supplied, requests are sent in sequence. (Usually a request file saved from BurpSuite)")
		log.Println("-H\tList of headers, one per flag: -H 'Header1: value1' -H 'Header2: value2'")
		log.Println("-rH\tList of headers to remove, one per flag: -rH 'Connection', -rH 'Accept-Encoding' [Default 'Connection' and 'Accept-Encoding']")
		log.Println("-to\tThe timeout for each web request [Default:5]")
		log.Println("-method\tThe type of http request: Usually GET, or POST [Default:'GET']")
		log.Println("-proxy\tThe proxy to send the requests through: Example http://127.0.0.1:8080 [Default: no proxy]")
		log.Println("-rate\tThe rate limit to apply to the requests in req/s [Default: no limit]")
		log.Println("")
		log.Println("General Options:")
		log.Println("-t\tThe number of concurrent threads [Default:10]")
		log.Println("-retry\tThe number of times to retry a failed request before giving up [Default:3]")
		log.Println("-dos\tRun a denial of service attack (for stress testing). This will repeat any provided wordlist indefinitely. [Default:false]")
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
		log.Println("Error Filter Options:")
		log.Println("-emc\tThe http response codes to match")
		log.Println("-ems\tMatch http response by size")
		log.Println("-emw\tMatch http response by number of words")
		log.Println("-eml\tMatch http response by number of lines")
		log.Println("-emr\tMatch http response by regular expression in response body")
		log.Println("-emt\tMatch responses that take longer than or equal to the specified time in miliseconds")
		log.Println("-efc\tThe http response codes to filter")
		log.Println("-efs\tFilter http response by size")
		log.Println("-efw\tFilter http response by number of words")
		log.Println("-efl\tFilter http response by number of lines")
		log.Println("-efr\tFilter http response by regular expression in response body")
		log.Println("-eft\tFilter responses that take longer than or equal to the specified time in miliseconds")
		log.Println("")
		log.Println("Trigger Filter Options:")
		log.Println("-tmc\tThe http response codes to match")
		log.Println("-tms\tMatch http response by size")
		log.Println("-tmw\tMatch http response by number of words")
		log.Println("-tml\tMatch http response by number of lines")
		log.Println("-tmr\tMatch http response by regular expression in response body")
		log.Println("-tmt\tMatch responses that take longer than or equal to the specified time in miliseconds")
		log.Println("-tfc\tThe http response codes to filter")
		log.Println("-tfs\tFilter http response by size")
		log.Println("-tfw\tFilter http response by number of words")
		log.Println("-tfl\tFilter http response by number of lines")
		log.Println("-tfr\tFilter http response by regular expression in response body")
		log.Println("-tft\tFilter responses that take longer than or equal to the specified time in miliseconds")
		log.Println("-ontrigger\tExecute an OS command once triggered. The HTTP response will be in the RES env variable")
		log.Println("-trigger-requeue\tEnsures that a request that activated a trigger is re-sent up to the number of times specified in -retry")
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
		log.Println("\thexEncode(string): takes a single string and returns a hex string representing the bytes in the string")
		log.Println("\thexDecode(string): takes a single hex string, decodes it and returns the ascii characters as a string")
		log.Println("\turlEncode(string): takes a single string and encodes unsafe url characters")
		log.Println("\turlDecode(string): takes a single url encoded string and returns the decoded string")
		log.Println("\t" + `concat(string, string, string, ...): takes any number of strings and returns all the strings joined together. Note that
		concat is only needed when joinging the output of a function to another function, or to a string. It is not needed to join two strings`)
		log.Println("\trandStr([int,[int]]): generates a random string of letters and numbers. Optionally specify an minimum and maximum length. Default is 10, 65")
		log.Println("\trandInt([int,[int]]): generates a random integer. Optionally specify an minimum and maximum int. Default is 0, MAX_INT64")
		log.Println("\trandBytes([int,[int]]): generates a random string of bytes. Optionally specify an minimum and maximum length. Default is 10, 1024")
		log.Println("\tregex(string, string, [int]): runs a regular expression and returns the specified capture group. Note that special characters still need to be escaped unless you use a string literal `my-string`.")
		log.Println("\tprevResponse(int): returns the content of a previous response when using multiple request files. An index of 0 selects the response from the first request file.")
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
		log.Println("Use CSRF token:")
		log.Println("gohammer -u https://some.site.com/ -f get-csrf-req.txt -f do-request.txt -transform 'regex(prevResponse(0),`X-Csrf-Token: (.*)`,1)' -t 32 /home/me/usernames.txt /home/me/passwords.txt")
	}
	// Request Options
	flag.StringVar(&(progArgs.RequestOptions.Url), "u", "http://127.0.0.1/", "")
	flag.StringVar(&(progArgs.RequestOptions.Data), "d", "", "")
	flag.StringVar(&(progArgs.RequestOptions.Proxy), "proxy", "", "")
	flag.Float64Var(&(progArgs.RequestOptions.Rate), "rate", 0, "")
	flag.Var(&(progArgs.RequestOptions.ReqFile), "f", "")
	flag.StringVar(&(progArgs.RequestOptions.Method), "method", "GET", "")
	flag.IntVar(&(progArgs.RequestOptions.Timeout), "to", 15, "")
	flag.Var(&(progArgs.RequestOptions.Headers), "H", "")
	flag.Var(&(progArgs.RequestOptions.RemoveHeaders), "rH", "")

	// General Options
	flag.IntVar(&(progArgs.GeneralOptions.Threads), "t", 10, "")
	flag.IntVar(&(progArgs.GeneralOptions.Retry), "retry", 3, "")
	flag.BoolVar(&(progArgs.GeneralOptions.Dos), "dos", false, "")

	// Recursion Options
	flag.IntVar(&(progArgs.RecursionOptions.Depth), "rd", 1, "")
	flag.IntVar(&(progArgs.RecursionOptions.RecursePosition), "rp", 0, "")
	flag.StringVar(&(progArgs.RecursionOptions.RecurseDelimiter), "rdl", "/", "")
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

	// Error Filter Options
	flag.Var(&(progArgs.ErrorFilterOptions.Mc), "emc", "")
	flag.Var(&(progArgs.ErrorFilterOptions.Ms), "ems", "")
	flag.Var(&(progArgs.ErrorFilterOptions.Mw), "emw", "")
	flag.Var(&(progArgs.ErrorFilterOptions.Ml), "eml", "")
	flag.StringVar(&(progArgs.ErrorFilterOptions.Mr), "emr", "", "")
	flag.IntVar(&(progArgs.ErrorFilterOptions.Mt), "emt", 0, "")
	flag.Var(&(progArgs.ErrorFilterOptions.Fc), "efc", "")
	flag.Var(&(progArgs.ErrorFilterOptions.Fs), "efs", "")
	flag.Var(&(progArgs.ErrorFilterOptions.Fw), "efw", "")
	flag.Var(&(progArgs.ErrorFilterOptions.Fl), "efl", "")
	flag.StringVar(&(progArgs.ErrorFilterOptions.Fr), "efr", "", "")
	flag.IntVar(&(progArgs.ErrorFilterOptions.Ft), "eft", 0, "")

	// Trigger Filter Options
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Mc), "tmc", "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Ms), "tms", "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Mw), "tmw", "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Ml), "tml", "")
	flag.StringVar(&(progArgs.TriggerFilterOptions.Filters.Mr), "tmr", "", "")
	flag.IntVar(&(progArgs.TriggerFilterOptions.Filters.Mt), "tmt", 0, "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Fc), "tfc", "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Fs), "tfs", "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Fw), "tfw", "")
	flag.Var(&(progArgs.TriggerFilterOptions.Filters.Fl), "tfl", "")
	flag.StringVar(&(progArgs.TriggerFilterOptions.Filters.Fr), "tfr", "", "")
	flag.IntVar(&(progArgs.TriggerFilterOptions.Filters.Ft), "tft", 0, "")
	flag.StringVar(&(progArgs.TriggerFilterOptions.Filters.Fr), "ontrigger", "", "")
	flag.BoolVar(&(progArgs.TriggerFilterOptions.Requeue), "trigger-requeue", false, "")

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

	if len(args.RequestOptions.RemoveHeaders) <= 0 {
		args.RequestOptions.RemoveHeaders.Set("Connection")
		args.RequestOptions.RemoveHeaders.Set("Accept-Encoding")
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

	if len(args.WordlistOptions.Files) <= 0 {
		args.GeneralOptions.Dos = true
	}

	//load request file contents
	var reqFileContents []string
	for _, reqFile := range args.RequestOptions.ReqFile {
		fileBytes, err := os.ReadFile(reqFile)
		if err != nil {
			log.Printf("Error: couldn't open %s\n", args.RequestOptions.ReqFile)
			os.Exit(1)
		}
		reqFileContents = append(reqFileContents, utils.RemoveTrailingNewline(string(fileBytes)))
	}

	args.RequestOptions.Timeout = args.RequestOptions.Timeout * int(time.Second)
	// apply filter codes
	args.FilterOptions.Mc = utils.SetDif(args.FilterOptions.Mc, args.FilterOptions.Fc)

	//add blank extension
	args.WordlistOptions.Extensions = append(args.WordlistOptions.Extensions, "")

	if !args.GeneralOptions.Dos {
		utils.TotalJobs = utils.GetNumJobs(args.WordlistOptions.Files, args.WordlistOptions.NoBrute, args.WordlistOptions.Extensions, log)
	}

	var agents []*request.ReqAgentHttp
	if len(reqFileContents) > 0 { // initialize as http agent
		args.RequestOptions.Url = strings.TrimSuffix(args.RequestOptions.Url, "/")
		for _, reqFileContent := range reqFileContents {
			agent := request.FileToRequestAgent(reqFileContent, args.RequestOptions.Url, args.RequestOptions.Proxy, args.RequestOptions.Timeout, args.RequestOptions.RemoveHeaders)
			agents = append(agents, agent)
		}

	} else {
		agent := request.NewReqAgentHttp(args.RequestOptions.Url, args.RequestOptions.Method, args.RequestOptions.Headers, args.RequestOptions.Data, args.RequestOptions.Proxy, args.RequestOptions.Timeout)
		agents = append(agents, agent)
	}

	counter := utils.NewCounter()
	go utils.PrintProgressLoop(counter, args.GeneralOptions.Dos, log)
	recurseFuzz(agents, counter, args)
	utils.PrintProgress(counter, args.GeneralOptions.Dos, log)
	log.Println("")
}
