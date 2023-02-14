package response

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/wadeking98/gohammer/config"
	"github.com/wadeking98/gohammer/utils"
)

type Resp struct {
	Code  int
	Time  int
	Body  string
	Err   error
	Size  int
	Words int
	Lines int
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
		Code: statusCode,
		Time: respTime,
		Body: httpRespToRespBody(resp),
		Err:  err,
	}
	r.Size, r.Words, r.Lines = sizeRespBody(r.Body)
	return &r
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

func (resp *Resp) ProcessResp(positions []string, counter *utils.Counter, args *config.Args) {

	filter := NewFilter(resp, args)
	passed := filter.ApplyFilters(args)
	if passed && len(positions) > 0 {
		displayPos := make([]string, len(positions))
		copy(displayPos, positions)
		displayPos[args.RecursionOptions.RecursePosition] = strings.Join(utils.FrontierQ[0], "") + positions[args.RecursionOptions.RecursePosition]
		args.OutputOptions.Logger.Println(respLineFormatter(resp.Code, resp.Size, resp.Words, resp.Lines, resp.Time, displayPos, 12))
		utils.PrintProgress(counter, args.GeneralOptions.Dos, args.OutputOptions.Logger)
	}

	if args.CaptureOptions.Cap != "" {
		cap := NewCapture(resp, args)
		cap.ApplyCapture()
	}

	if resp.IsRecurse(args.RecursionOptions.RecurseCode) {
		utils.FrontierLock.Lock()
		// add current position to base string of Frontier[0] and add it to the frontier
		utils.FrontierQ = append(utils.FrontierQ, append(utils.FrontierQ[0], positions[args.RecursionOptions.RecursePosition]+args.RecursionOptions.RecurseDelimeter))
		utils.FrontierLock.Unlock()
	}
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
		respBodyText, _ = ioutil.ReadAll(resp.Body)
	}
	return string(respBodyText)
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
