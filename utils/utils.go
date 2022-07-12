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
var FrontierLock sync.Mutex

var TotalJobs int

// replacePosition scans a string for the position marker and replaces it with a word
// from the corresponding wordlist
func ReplacePosition(str string, positions []string, recursePos int) string {
	r, _ := regexp.Compile(`@(\d+)@`)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Error: position number does not match number of files")
			os.Exit(1)
		}
	}()
	res := r.FindAllStringSubmatch(str, -1)
	for _, match := range res {
		posIdx, err := strconv.Atoi(match[1])
		if err != nil {
			fmt.Println("Error converting position index to integer")
			os.Exit(1)
		}
		baseStr := ""
		if posIdx == recursePos {
			baseStr = strings.Join(FrontierQ[0], "")
		}
		str = strings.Replace(str, match[0], baseStr+positions[posIdx], -1)
	}
	return str
}

// PrintProgressLoop prints the current progress to stdout every second and adds the current request/second to an array
func PrintProgressLoop(counter *Counter) {
	for {
		time.Sleep(1 * time.Second)
		counter.UpdateAvg()
		PrintProgress(counter)
	}
}

// PrintProgress prints the formatted progress string to stdout and computes the request/second average using an array
// populated by PrintProgressLoop
func PrintProgress(counter *Counter) {
	avg := counter.GetCountAvg()
	fmt.Printf("\r\033[KProgress: %d/%d - %d/s - Errors: %d", counter.GetCountNum(), TotalJobs, avg, counter.GetErrorNum())
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
func GetNumJobs(fnames []string, brute bool, extensions []string) int {
	var files []*bufio.Scanner
	for _, fname := range fnames {
		f, err := os.Open(fname)
		if err != nil {
			fmt.Printf("Error opening %s", fnames[0])
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
			fmt.Println("Error: empty file")
			os.Exit(1)
		}
		if brute {
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
