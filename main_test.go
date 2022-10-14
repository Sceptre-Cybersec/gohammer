package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/utils"
)

var httpChan chan string = make(chan string)
var urlChan chan string = make(chan string)
var bodyChan chan string = make(chan string)

func reqHandle(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.String(), "/recurse") {
		urlChan <- r.URL.String()
		w.WriteHeader(301)
	} else {
		body, err := ioutil.ReadAll(r.Body)
		if err == nil && strings.HasPrefix(r.URL.String(), "/data") {
			bodyChan <- string(body)
		}
		urlChan <- r.URL.String()
		httpChan <- r.Host
		httpChan <- r.Header["Content-Type"][0]
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
	time.Sleep(1 * time.Second)
}

func TestSendReq(t *testing.T) {
	reqChan := make(chan []string)
	agent := utils.NewReqAgentHttp("http://127.0.0.1:8888/@0@@1@", "POST", "Content-Type: @0@§Host: @0@@1@", "")
	counter := utils.NewCounter()
	go sendReq(reqChan, agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, RecurseDelimeter: "", Retry: 0})
	reqChan <- []string{"a", "b"}
	close(reqChan)
	urlResp := <-urlChan
	if urlResp != "/ab" {
		t.Fatal("URL Fuzzing Failed")
	}
	hostResp := <-httpChan
	if hostResp != "ab" {
		fmt.Println(hostResp)
		t.Fatal("Host Fuzzing Failed")
	}
	headerResp := <-httpChan
	if headerResp != "a" {
		t.Fatal("Header Fuzzing Failed")
	}

}

// func TestProcReqTemplate(t *testing.T) {
// 	agent := reqagent.NewReqAgentHttp("http://127.0.0.1:8888/@0@@1@", "GET@0@", "Content-Type: @0@,Host: @0@@1@", "")
// 	counter := utils.NewCounter()

// 	parsed := ProcReqTemplate(Request{"GET@0@", "http://127.0.0.1/@0@@1@", "Content-Type: @0@,Host: @0@@1@", ""}, []string{"a", "b"}, 0)
// 	if parsed.Method != "GETa" {
// 		t.Fatal("Method Fuzzing Failed")
// 	}
// 	if parsed.Url != "http://127.0.0.1/ab" {
// 		t.Fatal("URL Fuzzing Failed")
// 	}
// 	if parsed.Headers != "Content-Type: a,Host: ab" {
// 		t.Fatal("Header Fuzzing Failed")
// 	}
// }

func TestBrute(t *testing.T) {
	reqChan := make(chan []string)
	agent := utils.NewReqAgentHttp("http://127.0.0.1:8888/@0@@1@", "POST", "Content-Type: @0@§Host: @0@@1@", "")
	counter := utils.NewCounter()
	go sendReq(reqChan, agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, RecurseDelimeter: "", Retry: 0})

	go sendReq(reqChan, agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, RecurseDelimeter: "", Retry: 0})
	procFiles(nil, reqChan, &config.Args{Files: []string{"tests/a.txt", "tests/b.txt"}, E: []string{}, NoBrute: true}, 0)
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
	agent := utils.NewReqAgentHttp("http://127.0.0.1:8888/@0@_@1@", "GET", "Content-Type: @0@§Host: @0@@1@", "")
	counter := utils.NewCounter()
	for i := 0; i < 4; i++ {
		go sendReq(reqChan, agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, RecurseDelimeter: "", Retry: 0})
	}

	procFiles(nil, reqChan, &config.Args{Files: []string{"tests/a.txt", "tests/b.txt"}, NoBrute: true, E: []string{".txt", ".php"}}, 0)
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
	agent := utils.NewReqAgentHttp("http://127.0.0.1:8888/data", "POST", "", "test=hello@0@")
	counter := utils.NewCounter()
	go sendReq(reqChan, agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, RecurseDelimeter: "/", Retry: 0})
	procFiles(nil, reqChan, &config.Args{Files: []string{"tests/oneChar.txt"}, E: []string{""}}, 0)
	close(reqChan)
	resp := <-bodyChan
	<-urlChan

	if resp != "test=helloc" {
		t.Fatal("invalid post data")
	}
}

func TestRecursion(t *testing.T) {
	agent := utils.NewReqAgentHttp("http://127.0.0.1:8888/recurse/@0@", "GET", "", "")
	counter := utils.NewCounter()
	go recurseFuzz(agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200, 301}, RecursePosition: 0, NoBrute: false, Files: []string{"tests/oneChar.txt"}, Threads: 1, Depth: 3, RecurseDelimeter: "/", Retry: 0})
	url1 := <-urlChan
	url2 := <-urlChan
	url3 := <-urlChan
	time.Sleep(1 * time.Second)
	if url1 != "/recurse/c" || url2 != "/recurse/c/c" || url3 != "/recurse/c/c/c" {
		t.Fatalf("recursion failed %s %s %s\n", url1, url2, url3)
	}
}

// func TestNumJobs(t *testing.T) {
// 	numJobsBrute := GetNumJobs([]string{"tests/a.txt", "tests/b.txt", "tests/c.txt"}, true, []string{"", ".txt"})
// 	numJobs := GetNumJobs([]string{"tests/a.txt", "tests/b.txt", "tests/c.txt"}, true, []string{"", ".txt"})
// 	if numJobs != 4 && numJobsBrute != 16 {
// 		t.Fatal("Incorrect number of jobs")
// 	}
// }

// func TestUrlToTcp(t *testing.T) {
// 	address := UrlToTcpAddress("https://regex101.com/")
// 	if address.Port != 443 || !address.Ssl || address.Address != "regex101.com" {
// 		t.Fatal("Incorrect URL Parsing")
// 	}

// 	address = UrlToTcpAddress("https://127.0.0.1:8888/")
// 	if address.Port != 8888 || !address.Ssl || address.Address != "127.0.0.1" {
// 		t.Fatal("Incorrect URL Parsing")
// 	}

// 	address = UrlToTcpAddress("http://0.0.0.0:8888/")
// 	if address.Port != 8888 || address.Ssl || address.Address != "0.0.0.0" {
// 		t.Fatal("Incorrect URL Parsing")
// 	}

// 	address = UrlToTcpAddress("http://localhost/")
// 	if address.Port != 80 || address.Ssl || address.Address != "localhost" {
// 		t.Fatal("Incorrect URL Parsing")
// 	}
// }

// func TestReqFile(t *testing.T) {
// 	fileBytes, err := ioutil.ReadFile("tests/req.txt")
// 	if err != nil {
// 		fmt.Println("Error: couldn't open file")
// 	}
// 	reqFileContent := string(fileBytes)
// 	agent := reqagent.NewReqAgentTcp(reqFileContent, "http://127.0.0.1:8888/")
// 	counter := utils.NewCounter()
// 	//reset frontier
// 	utils.FrontierQ = [][]string{{""}}
// 	go recurseFuzz(agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, Depth: 2, RecurseDelimeter: "/", Retry: 5, Threads: 1, Files: []string{"tests/oneChar.txt"}})
// 	url := <-urlChan
// 	fmt.Println(url)
// 	if url != "/tcp/c" {
// 		t.Fatal("Tcp Socket Request Failed")
// 	}

// 	fileBytes, err = ioutil.ReadFile("tests/reqPost.txt")
// 	if err != nil {
// 		fmt.Println("Error: couldn't open file")
// 	}
// 	reqFileContent = utils.RemoveTrailingNewline(string(fileBytes))
// 	agent2 := reqagent.NewReqAgentTcp(reqFileContent, "http://127.0.0.1:8888/")
// 	counter2 := utils.NewCounter()
// 	go recurseFuzz(agent2, counter2, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, Depth: 2, RecurseDelimeter: "/", Retry: 5, Threads: 1, Files: []string{"tests/oneChar.txt"}})
// 	body := <-bodyChan
// 	url = <-urlChan
// 	if url != "/data/c" {
// 		t.Fatal("Tcp Socket Post Request Failed")
// 	}
// 	if body != "test=helloc" {
// 		t.Fatal("invalid post data")
// 	}
// }

// func TestRecursionTcp(t *testing.T) {
// 	fileBytes, err := ioutil.ReadFile("tests/reqRecurse.txt")
// 	if err != nil {
// 		fmt.Println("Error: couldn't open file")
// 	}
// 	reqFileContent := string(fileBytes)
// 	agent := reqagent.NewReqAgentTcp(reqFileContent, "http://127.0.0.1:8888/")
// 	counter := utils.NewCounter()
// 	go recurseFuzz(agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200, 301}, RecursePosition: 0, Depth: 3, RecurseDelimeter: "/", Retry: 5, Threads: 1, Files: []string{"tests/oneChar.txt"}})
// 	time.Sleep(1 * time.Second)
// 	url1 := <-urlChan
// 	url2 := <-urlChan
// 	url3 := <-urlChan
// 	if url1 != "/recurse/c" || url2 != "/recurse/c/c" || url3 != "/recurse/c/c/c" {
// 		t.Fatalf("recursion failed %s %s %s\n", url1, url2, url3)
// 	}
// }

func TestFileToReq(t *testing.T) {
	fileBytes, err := ioutil.ReadFile("tests/reqPost.txt")
	if err != nil {
		fmt.Println("Error: couldn't open file")
	}
	reqFileContent := string(fileBytes)

	agent := utils.FileToRequestAgent(reqFileContent, "http://127.0.0.1:8888")
	if agent.GetUrl() != "http://127.0.0.1:8888/data/@0@" || len(agent.GetHeaders()) != 517 || agent.GetMethod() != "POST" || agent.GetBody() != "test=hello@0@" {
		fmt.Printf("URL: {%s}\n", agent.GetUrl())
		fmt.Printf("Headers: {%d}\n", len(agent.GetHeaders()))
		fmt.Printf("Method: {%s}\n", agent.GetMethod())
		fmt.Printf("Body: {%s}\n", agent.GetBody())
		t.Fatal("Failed converting file to request")
	}
}

func TestFilePost(t *testing.T) {
	fileBytes, err := ioutil.ReadFile("tests/reqFilePost.txt")
	if err != nil {
		fmt.Println("Error: couldn't open file")
	}
	reqFileContent := utils.RemoveTrailingNewline(string(fileBytes))

	agent := utils.FileToRequestAgent(reqFileContent, "http://127.0.0.1:8888")

	reqChan := make(chan []string)
	counter := utils.NewCounter()
	go sendReq(reqChan, agent, counter, &config.Args{Timeout: 10 * int(time.Second), Mc: []int{200}, RecursePosition: 0, RecurseDelimeter: "/", Retry: 0})
	procFiles(nil, reqChan, &config.Args{Files: []string{"tests/oneChar.txt"}, E: []string{""}}, 0)
	close(reqChan)
	resp := <-bodyChan
	<-urlChan
	fmt.Println(resp)
	if resp != "test=helloc" {
		t.Fatal("invalid post data")
	}
}
