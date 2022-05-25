package main

import (
	"fmt"
	"net/http"
	"testing"
)

var httpChan chan string = make(chan string)

func reqHandle(w http.ResponseWriter, r *http.Request) {
	httpChan <- r.URL.String()
	httpChan <- r.Host
	httpChan <- r.Header["Content-Type"][0]
	fmt.Fprint(w, "OK")
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
}

func TestSendReq(t *testing.T) {
	reqChan := make(chan []string)
	go sendReq(reqChan, request{method: "POST", url: "http://127.0.0.1:8080/@0@@1@", headers: "Content-Type: @0@,Host: @0@@1@"}, 10, []string{"200"})
	reqChan <- []string{"a", "b"}
	urlResp := <-httpChan
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
	parsed := procReqTemplate(request{"GET@0@", "http://127.0.0.1/@0@@1@", "Content-Type: @0@,Host: @0@@1@", nil}, []string{"a", "b"})
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
