package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return ""
}
func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type multiSplitStringFlag []string

func (m *multiSplitStringFlag) String() string {
	return ""
}
func (m *multiSplitStringFlag) Set(value string) error {
	flagSet := strings.Split(value, ",")
	if len(flagSet) > 0 {
		*m = append(*m, flagSet...)
	}
	return nil
}

type multiSplitIntFlag []int

func (m *multiSplitIntFlag) String() string {
	return ""
}
func (m *multiSplitIntFlag) Set(value string) error {
	flagSet := strings.Split(value, ",")
	var flagIntSet []int
	for _, s := range flagSet {
		i, err := strconv.Atoi(s)
		if err != nil {
			fmt.Printf("Error converting number: %s to int in command line arguments\n", s)
			os.Exit(1)
		}
		flagIntSet = append(flagIntSet, i)
	}
	if len(flagIntSet) > 0 {
		*m = append(*m, flagIntSet...)
	}
	return nil
}

type RequestOptions struct {
	Url     string
	Proxy   string
	Method  string
	ReqFile string
	Headers multiStringFlag
	Timeout int
	Data    string
}

type GeneralOptions struct {
	Threads int
	Retry   int
	Dos     bool
}

type RecursionOptions struct {
	Depth            int
	RecursePosition  int
	RecurseDelimeter string
}

type WordlistOptions struct {
	NoBrute    bool
	Extensions multiSplitStringFlag
	Files      []string
}

type FilterOptions struct {
	Mc multiSplitIntFlag
	Ms multiSplitIntFlag
	Mw multiSplitIntFlag
	Ml multiSplitIntFlag
	Mt int
	Mr string
	Fc multiSplitIntFlag
	Fs multiSplitIntFlag
	Fw multiSplitIntFlag
	Fl multiSplitIntFlag
	Ft int
	Fr string
}

type CaptureOptions struct {
	Cap      string
	CapGroup int
	CapFile  string
}

type TransformOptions struct {
	Transforms multiStringFlag
}

type Args struct {
	RequestOptions   RequestOptions
	GeneralOptions   GeneralOptions
	RecursionOptions RecursionOptions
	WordlistOptions  WordlistOptions
	FilterOptions    FilterOptions
	CaptureOptions   CaptureOptions
	TransformOptions TransformOptions
}
