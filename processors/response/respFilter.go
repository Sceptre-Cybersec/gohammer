package response

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/wadeking98/gohammer/config"
)

type Filter struct {
	response *Resp
	filters  []func(*Resp, *config.Args) bool
}

func NewFilter(resp *Resp, conf *config.Args) *Filter {
	f := Filter{
		response: resp,
		filters:  []func(*Resp, *config.Args) bool{passedCodeFound, passedLengthFilter, passedLengthMatch, passedTimeFilter, passedRegexFilter, passedRegexMatch},
	}
	return &f
}

// ApplyFilters runs through all response filters and returns true is they all pass
func (f *Filter) ApplyFilters(args *config.Args) bool {
	passed := true
	for _, fn := range f.filters {
		passed = passed && fn(f.response, args)
		if !passed {
			break
		}
	}
	args.OutputOptions.Logger.Test("Passed all filters: " + strconv.FormatBool(passed))
	return passed
}

// passedTimeFilter determines if a request fails based on the time it took to reply
func passedTimeFilter(resp *Resp, args *config.Args) bool {
	passed := true
	if args.FilterOptions.Ft != 0 {
		passed = resp.Time < args.FilterOptions.Ft
	} else if args.FilterOptions.Mt != 0 {
		passed = resp.Time >= args.FilterOptions.Mt
	}
	return passed
}

// passedCodeFound determines if a response code is found based on match codes in the param (mc),
// and logs it to stdout if it is found
func passedCodeFound(resp *Resp, args *config.Args) bool {
	mcFound := false
	//check if use supplied all codes
	if len(args.FilterOptions.Mc) > 0 && args.FilterOptions.Mc[0] == -1 {
		return true
	}
	//else scan through accepted response codes
	for _, i := range args.FilterOptions.Mc {
		if resp.Code == i {
			mcFound = true
			break
		}
	}
	return mcFound
}

// passedRegexFilter returns true if the regex doesn't match the request body
func passedRegexFilter(resp *Resp, args *config.Args) bool {
	passed := true
	if args.FilterOptions.Fr != "" {
		filterRegex, err := regexp.Compile(args.FilterOptions.Fr)
		if err != nil {
			fmt.Println("Error: Invalid filter regular expression. Please use Golang style regular expressions")
			os.Exit(1)
		}
		matchFound := filterRegex.MatchString(resp.Body)
		passed = !matchFound
	}
	return passed
}

// passedRegexMatch returns true if the regex matches the request body
func passedRegexMatch(resp *Resp, args *config.Args) bool {
	passed := true
	if args.FilterOptions.Mr != "" {
		filterRegex, err := regexp.Compile(args.FilterOptions.Mr)
		if err != nil {
			fmt.Println("Error: Invalid filter regular expression. Please use Golang style regular expressions")
			os.Exit(1)
		}
		matchFound := filterRegex.MatchString(resp.Body)
		passed = matchFound
	}
	return passed
}

// passedLengthFilter takes the response sizes (chars, words, lines) respectively as an array and returns true if none of the
// length filters captures a response length
func passedLengthFilter(resp *Resp, args *config.Args) bool {
	filterPassed := true
	filters := [][]int{args.FilterOptions.Fs, args.FilterOptions.Fw, args.FilterOptions.Fl}
	sizes := []int{resp.Size, resp.Words, resp.Lines}
	for i, s := range sizes { //apply length filter to chars, words, lines
		filterPassed = !lenFilterSearch(s, filters[i])
		if !filterPassed {
			break
		}
	}

	return filterPassed
}

// passedLengthMatch takes the response sizes (chars, words, lines) respectively as an array and returns false if none of the
// length filters captures a response length
func passedLengthMatch(resp *Resp, args *config.Args) bool {
	filterPassed := true
	filters := [][]int{args.FilterOptions.Ms, args.FilterOptions.Mw, args.FilterOptions.Ml}
	sizes := []int{resp.Size, resp.Words, resp.Lines}
	for i, s := range sizes { //apply length matcher to chars, words
		// we only care if the user has specified matchers
		filterPassed = len(filters[i]) <= 0 || lenFilterSearch(s, filters[i])
		if !filterPassed {
			break
		}
	}

	return filterPassed
}

//lenFilterSearch returns true if the length is in the array of lengths
func lenFilterSearch(length int, lengths []int) bool {
	ret := false
	if len(lengths) > 0 {
		for _, s := range lengths {
			if s == length {
				ret = true
				break
			}
		}
	}
	return ret
}
