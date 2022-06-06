package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
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
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			fmt.Println("Setup Failed")
		}
	}()
	time.Sleep(1 * time.Second)
}

func TestSendReq(t *testing.T) {
	reqChan := make(chan []string)
	go sendReq(reqChan, request{method: "POST", url: "http://127.0.0.1:8080/@0@@1@", headers: "Content-Type: @0@,Host: @0@@1@"}, 10, []string{"200"}, 0, "")
	reqChan <- []string{"a", "b"}
	close(reqChan)
	urlResp := <-urlChan
	if urlResp != "/ab" {
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

func TestProcReqTemplate(t *testing.T) {
	parsed := procReqTemplate(request{"GET@0@", "http://127.0.0.1/@0@@1@", "Content-Type: @0@,Host: @0@@1@", ""}, []string{"a", "b"}, 0)
	if parsed.method != "GETa" {
		t.Fatal("Method Fuzzing Failed")
	}
	if parsed.url != "http://127.0.0.1/ab" {
		t.Fatal("URL Fuzzing Failed")
	}
	if parsed.headers != "Content-Type: a,Host: ab" {
		t.Fatal("Header Fuzzing Failed")
	}
}

func TestBrute(t *testing.T) {
	reqChan := make(chan []string)
	go sendReq(reqChan, request{method: "POST", url: "http://127.0.0.1:8080/@0@@1@"}, 10, []string{"200"}, 0, "")

	go sendReq(reqChan, request{method: "POST", url: "http://127.0.0.1:8080/@0@@1@"}, 10, []string{"200"}, 0, "")
	procFiles([]string{"a.txt", "b.txt"}, nil, reqChan, false, []string{})
	close(reqChan)
	resp := []string{<-urlChan, <-urlChan}
	test1 := false
	test2 := false
	// fmt.Println(resp)
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
	for i := 0; i < 4; i++ {
		go sendReq(reqChan, request{method: "POST", url: "http://127.0.0.1:8080/@0@_@1@"}, 10, []string{"200"}, 0, "")
	}

	procFiles([]string{"a.txt", "b.txt"}, nil, reqChan, false, []string{".txt", ".php"})
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
	go sendReq(reqChan, request{method: "POST", url: "http://127.0.0.1:8080/data", body: "test=hello@0@"}, 10, []string{"200"}, 0, "")
	procFiles([]string{"oneChar.txt"}, nil, reqChan, false, []string{""})
	close(reqChan)
	resp := <-bodyChan
	<-urlChan

	if resp != "test=helloc" {
		t.Fatal("invalid post data")
	}
}

func TestRecursion(t *testing.T) {
	go recurseFuzz(1, 5, []string{"oneChar.txt"}, false, request{method: "GET", url: "http://127.0.0.1:8080/recurse/@0@"}, []string{"200", "301"}, 2, 0, "/", nil)
	url1 := <-urlChan
	url2 := <-urlChan
	url3 := <-urlChan
	time.Sleep(1 * time.Second)
	if url1 != "/recurse/c" || url2 != "/recurse/c/c" || url3 != "/recurse/c/c/c" {
		t.Fatalf("recursion failed %s %s %s\n", url1, url2, url3)
	}
}
