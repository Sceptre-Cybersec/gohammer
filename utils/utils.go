package utils

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var FrontierQ [][]string = [][]string{{""}}
var FrontierLock sync.Mutex // this lock it used to ensure the FrontierQ doesn't get corrupted
var ReqLock sync.RWMutex    // this lock is used to pause the sending of requests

var TotalJobs int

// replacePosition scans a string for the position marker and replaces it with a word
// from the corresponding wordlist
func ReplacePosition(str string, positions []string, recursePos int, log *Logger) string {
	r := regexp.MustCompile(`@(\d+)@`)
	res := r.FindAllStringSubmatch(str, -1)
	for _, match := range res {
		posIdx, err := strconv.Atoi(match[1])
		if err != nil {
			log.Println("Error converting position index to integer")
			os.Exit(1)
		}
		baseStr := ""
		if posIdx == recursePos && len(FrontierQ) > 0 {
			baseStr = strings.Join(FrontierQ[0], "")
		}
		if len(positions) > posIdx {
			str = strings.Replace(str, match[0], baseStr+positions[posIdx], -1)
		}
	}
	return str
}

// PrintProgressLoop prints the current progress to stdout every second and adds the current request/second to an array
func PrintProgressLoop(counter *Counter, dos bool, log *Logger) {
	for {
		time.Sleep(1 * time.Second)
		counter.UpdateAvg()
		PrintProgress(counter, dos, log)
	}
}

// PrintProgress prints the formatted progress string to stdout and computes the request/second average using an array
// populated by PrintProgressLoop
func PrintProgress(counter *Counter, dos bool, log *Logger) {
	avg := counter.GetCountAvg()
	var progressString string
	if !dos {
		progressString = fmt.Sprintf("\r\033[KProgress: %d/%d - %d/s - Errors: %d", counter.GetCountNum(), TotalJobs, avg, counter.GetErrorNum())
	} else {
		progressString = fmt.Sprintf("\r\033[KProgress: %d - %d/s - Errors: %d", counter.GetCountNum(), avg, counter.GetErrorNum())
	}
	log.Print(progressString)
}

// RemoveTrailingNewLine corrects the request file. Some text editors add a trailing new line to a file after saving.
// This logic removes the new line added by some text editors.
func RemoveTrailingNewline(req string) string {
	fixedReq := req
	// get requests normally end with double CRLF
	if !strings.HasSuffix(req, "\r\n\r\n") && strings.HasSuffix(req, "\r\n") {
		fixedReq = fixedReq[:len(fixedReq)-2]
	}
	return fixedReq
}

// SetDif determines the set difference of two arrays
// Returns the resulting difference
func SetDif(a, b []int) (diff []int) {
	m := make(map[int]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return
}

// GetNumJobs computes the number of jobs based on the file length and number of fuzzing positions
// Returns the total number of jobs
func GetNumJobs(fnames []string, noBrute bool, extensions []string, log *Logger) int {
	var files []*bufio.Scanner
	for _, fname := range fnames {
		f, err := os.Open(fname)
		if err != nil {
			log.Printf("Error opening %s\n", fnames[0])
			os.Exit(1)
		}
		files = append(files, bufio.NewScanner(f))
		defer f.Close()
	}
	// there will always be at least one file
	numJobs := getFileLen(files[0])
	for _, f := range files[1:] {
		len := getFileLen(f)
		if len == 0 {
			log.Println("Error: empty file")
			os.Exit(1)
		}
		if !noBrute {
			numJobs *= len
		} else {
			numJobs = int(math.Min(float64(numJobs), float64(len)))
		}
	}
	// extensions will always have at least one element in it (the empty extension: '')
	numJobs *= len(extensions)
	return numJobs
}

// getFileLen computes the length of user provided wordlists
// Returns the length of a given file
func getFileLen(r *bufio.Scanner) int {
	// return the length of the file
	count := 0
	for r.Scan() {
		count++
	}
	return count
}
