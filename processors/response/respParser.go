package response

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/Sceptre-Cybersec/gohammer/config"
	"github.com/Sceptre-Cybersec/gohammer/utils"
)

type Resp struct {
	Code    int
	Time    int
	Body    string
	Headers []string
	Err     error
	Size    int
	Words   int
	Lines   int
}

// NewRespFromTcp builds a new response object from a tcp response message
func NewRespFromTcp(rawResp string, respTime int) *Resp {
	r := Resp{
		Code: getTcpRespCode(rawResp),
		Time: respTime,
		Body: tcpRespToRespBody(rawResp),
	}
	r.Size, r.Words, r.Lines = sizeRespBody(r.Body)
	return &r
}

// NewRespFromHttp builds a new response object from a http response
func NewRespFromHttp(resp *http.Response, respTime int, err error) *Resp {
	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
	}
	// parse code from error message
	if err != nil {
		if strings.HasSuffix(err.Error(), "response missing Location header") {
			rx := regexp.MustCompile(`(\d+) response missing Location header`)
			res := rx.FindStringSubmatch(err.Error())
			codeString := res[1]
			code, convErr := strconv.Atoi(codeString)
			if convErr != nil {
				fmt.Printf("Error converting response code %s to integer\n", codeString)
			} else {
				statusCode = code
			}
		}
	}

	r := Resp{
		Code:    statusCode,
		Time:    respTime,
		Body:    httpRespToRespBody(resp),
		Headers: httpRespToHeaders(resp),
		Err:     err,
	}
	r.Size, r.Words, r.Lines = sizeRespBody(r.Body)
	return &r
}

func (r *Resp) ToString() string {
	res := strconv.FormatInt(int64(r.Code), 10)
	for _, header := range r.Headers {
		res = res + "\n" + header
	}
	res = res + "\n\n" + r.Body
	return res
}

// IsRecurse determines if a value response code corresponds to a web folder
func (r *Resp) IsRecurse(codes []int) bool {
	ret := false
	for _, c := range codes {
		if c == r.Code {
			ret = true
			break
		}
	}
	return ret
}

func (resp *Resp) ProcessResp(positions []string, counter *utils.Counter, args *config.Args) (bool, error) {
	// process errors
	errorFilter := NewFilter(resp)
	errorFound := errorFilter.ApplyFilters(&args.ErrorFilterOptions)
	if errorFound {
		return false, error(nil)
	}
	// process triggers
	triggerFilter := NewFilter(resp)
	triggerPassed := triggerFilter.ApplyFilters(&args.TriggerFilterOptions.Filters)
	if triggerPassed {
		if args.TriggerFilterOptions.OnTrigger != "" {
			go func() { // The parent function is currently holding the read lock
				// we need to run this in a thread so we don't hold the read lock and ask for the write lock at the same time
				utils.ReqLock.Lock()
				os.Setenv("RES", resp.Body)
				cmd := exec.Command("sh", "-c", args.TriggerFilterOptions.OnTrigger)
				var out bytes.Buffer
				cmd.Stdout = &out
				if runtime.GOOS == "windows" {
					cmd = exec.Command("cmd", "/c", args.TriggerFilterOptions.OnTrigger)
				}
				cmd.Run()
				utils.ReqLock.Unlock()
				args.OutputOptions.Logger.Test("Executed command output: " + out.String())
			}()
		}
		// retry the request as if it were an error
		if args.TriggerFilterOptions.Requeue {
			return false, error(nil)
		}
	}

	filter := NewFilter(resp)
	passed := filter.ApplyFilters(&args.FilterOptions)
	if passed {
		args.OutputOptions.Logger.Test("Passed all filters: " + strconv.FormatBool(passed))
		if len(positions) > 0 {
			displayPos := make([]string, len(positions))
			copy(displayPos, positions)
			displayPos[args.RecursionOptions.RecursePosition] = strings.Join(utils.FrontierQ[0], "") + positions[args.RecursionOptions.RecursePosition]
			args.OutputOptions.Logger.Println(respLineFormatter(resp.Code, resp.Size, resp.Words, resp.Lines, resp.Time, displayPos, 12))
		}
		utils.PrintProgress(counter, args.GeneralOptions.Dos, args.OutputOptions.Logger)
	}

	if args.CaptureOptions.Cap != "" {
		cap := NewCapture(resp, args)
		cap.ApplyCapture()
	}

	if resp.IsRecurse(args.RecursionOptions.RecurseCode) {
		utils.FrontierLock.Lock()
		// add current position to base string of Frontier[0] and add it to the frontier
		utils.FrontierQ = append(utils.FrontierQ, append(utils.FrontierQ[0], positions[args.RecursionOptions.RecursePosition]+args.RecursionOptions.RecurseDelimiter))
		utils.FrontierLock.Unlock()
	}

	return true, nil
}

// formats each column into equal width
func respLineFormatter(code int, size int, words int, lines int, time int, display []string, colWidth int) string {
	cols := [4]string{fmt.Sprintf("Size:%d", size), fmt.Sprintf("Words:%d", words), fmt.Sprintf("Lines:%d", lines), fmt.Sprintf("Time:%dms", time)}
	resp := fmt.Sprintf("\r\033[K%d - ", code)
	for _, col := range cols {
		currLen := len([]rune(col))
		remainingLength := colWidth - currLen
		if remainingLength > 0 {
			col += strings.Repeat(" ", remainingLength)
		} else {
			col += " "
		}
		resp += col
	}
	return fmt.Sprintf("%s- %s", resp, display)
}

// sizeRespBody fetches the size, words, and lines of each request
func sizeRespBody(resp string) (int, int, int) {
	return len(strings.Split(resp, "")), len(strings.Split(resp, " ")), len(strings.Split(resp, "\n"))
}

// httpRespToRespBody takes the http response body and converts it to a string
func httpRespToRespBody(resp *http.Response) string {
	var respBodyText []byte
	if resp != nil {
		respBodyText, _ = io.ReadAll(resp.Body)
	}
	return string(respBodyText)
}

func httpRespToHeaders(resp *http.Response) []string {
	headers := []string{}
	for k, v := range resp.Header {
		for _, val := range v {
			headers = append(headers, fmt.Sprintf("%s: %s", k, val))
		}
	}
	return headers
}

// tcpRespToRespBody grabs the response body from the raw tcp response
func tcpRespToRespBody(resp string) string {
	rx := regexp.MustCompile(`(?msi)\r\n\r\n(.*)`)
	matched := rx.FindStringSubmatch(resp)
	if len(matched) <= 1 {
		return ""
	}
	return matched[1]
}

// getTcpRespCode parses the response code from a raw tcp response.
// Returns the response code as a string
func getTcpRespCode(resp string) int {
	respRx := regexp.MustCompile(`HTTP/\S+\s(\d+)`)
	match := respRx.FindStringSubmatch(resp)
	var code string
	if match != nil {
		code = match[1]
	}
	intCode, err := strconv.Atoi(code)
	if err != nil {
		fmt.Printf("Error converting response code %s to int in getTcpRespCode(...)", code)
		return 0
	}
	return intCode
}
