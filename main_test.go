package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/processors/request"
	"github.com/wadeking98/gohammer/processors/request/transforms"
	"github.com/wadeking98/gohammer/utils"
)

var httpChan chan string = make(chan string)
var urlChan chan string = make(chan string)
var bodyChan chan string = make(chan string)

func reqHandle(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.String(), "/recurse") {
		urlChan <- r.URL.String()
		w.WriteHeader(301)
	} else if strings.HasPrefix(r.URL.String(), "/allCodes") {
		w.WriteHeader(404)
	} else if strings.HasPrefix(r.URL.String(), "/headers") {
		urlChan <- r.URL.String()
		httpChan <- r.Host
		httpChan <- r.Header["Content-Type"][0]
		fmt.Fprint(w, "OK")
	} else {
		body, err := ioutil.ReadAll(r.Body)
		if err == nil && strings.HasPrefix(r.URL.String(), "/data") {
			bodyChan <- string(body)
		}
		urlChan <- r.URL.String()
		fmt.Fprint(w, "OK")
	}
}
func TestSetup(t *testing.T) {
	fmt.Println("Starting web server")

	http.HandleFunc("/", reqHandle)
	go func() {
		err := http.ListenAndServe(":8888", nil)
		if err != nil {
			fmt.Println("Setup Failed")
		}
	}()
	time.Sleep(time.Duration(0.25 * float64(time.Second)))
}

func TestSendReq(t *testing.T) {
	reqChan := make(chan []string)
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/headers/@0@@1@", "POST", []string{"Content-Type: @0@", "Host: @0@@1@"}, "", "", 5)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{200}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/a.txt", "tests/b.txt"}
	args.WordlistOptions.NoBrute = true
	args.WordlistOptions.Extensions = []string{""}
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	go sendReq(reqChan, agent, counter, &args)
	reqChan <- []string{"a", "b"}
	close(reqChan)
	urlResp := <-urlChan
	if urlResp != "/headers/ab" {
		t.Fatal("URL Fuzzing Failed")
	}
	hostResp := <-httpChan
	if hostResp != "ab" {
		t.Fatal("Host Fuzzing Failed")
	}
	headerResp := <-httpChan
	if headerResp != "a" {
		t.Fatal("Header Fuzzing Failed")
	}

}

func TestBrute(t *testing.T) {
	reqChan := make(chan []string)
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/@0@@1@", "POST", []string{"Content-Type: @0@", "Host: @0@@1@"}, "", "", 5)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{200}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/a.txt", "tests/b.txt"}
	args.WordlistOptions.NoBrute = true
	args.WordlistOptions.Extensions = []string{""}
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	go sendReq(reqChan, agent, counter, &args)

	go sendReq(reqChan, agent, counter, &args)
	procFiles(nil, reqChan, &args, 0)
	close(reqChan)
	resp := []string{<-urlChan, <-urlChan}
	test1 := false
	test2 := false
	for _, r := range resp {
		if r == "/ac" {
			test1 = true
		} else if r == "/bd" {
			test2 = true
		}
	}
	if !(test1 && test2) {
		t.Fatal("non brute force mode failed")
	}
}

func TestExtensions(t *testing.T) {
	reqChan := make(chan []string)
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/@0@_@1@", "GET", []string{"Content-Type: @0@", "Host: @0@@1@"}, "", "", 5)
	counter := utils.NewCounter()
	for i := 0; i < 4; i++ {
		var args config.Args
		args.RequestOptions.Timeout = 10 * int(time.Second)
		args.FilterOptions.Mc = []int{200}
		args.RecursionOptions.RecursePosition = 0
		args.RecursionOptions.RecurseDelimeter = ""
		args.GeneralOptions.Retry = 0
		args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
		go sendReq(reqChan, agent, counter, &args)
	}

	var args config.Args
	args.WordlistOptions.Files = []string{"tests/a.txt", "tests/b.txt"}
	args.WordlistOptions.NoBrute = true
	args.WordlistOptions.Extensions = []string{".txt", ".php"}
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	procFiles(nil, reqChan, &args, 0)
	close(reqChan)
	tests := []string{"/a.php_c.php", "/a.txt_c.txt", "/b.txt_d.txt", "/b.php_d.php"}
	numPassed := 0
	for i := 0; i < len(tests); i++ {
		feedback := <-urlChan
		passed := false
		for _, test := range tests {
			if test == feedback {
				passed = true
				numPassed++
			}
		}
		if !passed {
			t.Fatal("Extension Check Failed")
		}
	}
}

func TestPostData(t *testing.T) {
	reqChan := make(chan []string)
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/data", "POST", []string{}, "test=hello@0@", "", 5)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{200}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/oneChar.txt"}
	args.WordlistOptions.Extensions = []string{""}
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	go sendReq(reqChan, agent, counter, &args)
	procFiles(nil, reqChan, &args, 0)
	close(reqChan)
	resp := <-bodyChan
	<-urlChan

	if resp != "test=helloc" {
		t.Fatal("invalid post data")
	}
}

func TestRecursion(t *testing.T) {
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/recurse/@0@", "GET", []string{}, "", "", 5)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{200, 301}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/oneChar.txt"}
	args.WordlistOptions.NoBrute = false
	args.GeneralOptions.Threads = 1
	args.WordlistOptions.Extensions = []string{""}
	args.RecursionOptions.Depth = 3
	args.GeneralOptions.Retry = 0
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	go recurseFuzz(agent, counter, &args)
	url1 := <-urlChan
	url2 := <-urlChan
	url3 := <-urlChan
	if url1 != "/recurse/c" || url2 != "/recurse/c/c" || url3 != "/recurse/c/c/c" {
		t.Fatalf("recursion failed %s %s %s\n", url1, url2, url3)
	}
}

func TestNumJobs(t *testing.T) {
	log := utils.NewLogger(utils.NONE, os.Stdout)
	numJobsBrute := utils.GetNumJobs([]string{"tests/a.txt", "tests/b.txt", "tests/c.txt"}, false, []string{"", ".txt"}, log)
	numJobs := utils.GetNumJobs([]string{"tests/a.txt", "tests/b.txt", "tests/c.txt"}, true, []string{"", ".txt"}, log)
	if numJobs != 4 && numJobsBrute != 16 {
		t.Fatal("Incorrect number of jobs")
	}
}

func TestFileToReq(t *testing.T) {
	fileBytes, err := ioutil.ReadFile("tests/reqPost.txt")
	if err != nil {
		fmt.Println("Error: couldn't open file")
	}
	reqFileContent := string(fileBytes)

	agent := request.FileToRequestAgent(reqFileContent, "http://127.0.0.1:8888", "", 5)
	if agent.GetUrl() != "http://127.0.0.1:8888/data/@0@" || len(agent.GetHeaders()) != 16 || agent.GetMethod() != "POST" || agent.GetBody() != "test=hello@0@" {
		fmt.Printf("URL: {%s}\n", agent.GetUrl())
		fmt.Printf("Headers: {%d}\n", len(agent.GetHeaders()))
		fmt.Printf("Method: {%s}\n", agent.GetMethod())
		fmt.Printf("Body: {%s}\n", agent.GetBody())
		t.Fatal("Failed converting file to request")
	}
}

func TestFilePost(t *testing.T) {
	// reset frontierQ
	utils.FrontierQ = [][]string{{""}}
	fileBytes, err := ioutil.ReadFile("tests/reqFilePost.txt")
	if err != nil {
		fmt.Println("Error: couldn't open file")
	}
	reqFileContent := utils.RemoveTrailingNewline(string(fileBytes))

	agent := request.FileToRequestAgent(reqFileContent, "http://127.0.0.1:8888", "", 5)

	reqChan := make(chan []string)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{200}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/oneChar.txt"}
	args.WordlistOptions.Extensions = []string{""}
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	go sendReq(reqChan, agent, counter, &args)
	procFiles(nil, reqChan, &args, 0)
	close(reqChan)
	resp := <-bodyChan
	<-urlChan
	if resp != "test=helloc" {
		t.Fatal("invalid post data")
	}
}
func TestTransforms(t *testing.T) {
	transformList := transforms.NewTransformList()
	var args config.Args
	args.RecursionOptions.RecursePosition = 0
	outp := transforms.ApplyTransforms("concat(b64Decode(b64Encode(@0@\\,test1)),test\\))", transformList, []string{"test)"}, &args)
	if outp != "test),test1test)" {
		t.Fatal("invalid transform output")
	}
}

func TestTransformRequests(t *testing.T) {
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/@t0@", "GET", []string{}, "", "", 5)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{200}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/oneChar.txt"}
	args.WordlistOptions.Extensions = []string{""}
	args.TransformOptions.Transforms = []string{"urlEncode(concat(b64Encode(@0@:test!),\\,,b64Encode(@0@:hello)))"}
	args.OutputOptions.Logger = utils.NewLogger(utils.NONE, os.Stdout)
	reqChan := make(chan []string)
	go sendReq(reqChan, agent, counter, &args)
	procFiles(nil, reqChan, &args, 0)
	close(reqChan)
	resp := <-urlChan
	if resp != "/Yzp0ZXN0IQ%3D%3D%2CYzpoZWxsbw%3D%3D" {
		t.Fatal("Unexpected Transform output")
	}
}

func TestMCAll(t *testing.T) {
	buf := new(bytes.Buffer)
	agent := request.NewReqAgentHttp("http://127.0.0.1:8888/allCodes/@0@", "GET", []string{}, "", "", 5)
	counter := utils.NewCounter()
	var args config.Args
	args.RequestOptions.Timeout = 10 * int(time.Second)
	args.FilterOptions.Mc = []int{-1}
	args.RecursionOptions.RecursePosition = 0
	args.RecursionOptions.RecurseDelimeter = "/"
	args.GeneralOptions.Retry = 0
	args.WordlistOptions.Files = []string{"tests/oneChar.txt"}
	args.WordlistOptions.Extensions = []string{""}
	args.OutputOptions.Logger = utils.NewLogger(utils.TESTING, buf)
	reqChan := make(chan []string)
	go sendReq(reqChan, agent, counter, &args)
	procFiles(nil, reqChan, &args, 0)
	close(reqChan)
	time.Sleep(time.Duration(0.25 * float64(time.Second)))
	out, _ := buf.ReadString(byte(0))
	if !strings.Contains(out, "Passed all filters: true") {
		t.Fatal("Match all codes failed")
	}
}
