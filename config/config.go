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

type Args struct {
	Url              string
	Threads          int
	Method           string
	ReqFile          string
	Brute            bool
	Headers          multiStringFlag
	Files            []string
	Mc               multiSplitIntFlag
	Fc               multiSplitIntFlag
	Fs               multiSplitIntFlag
	Fw               multiSplitIntFlag
	Fl               multiSplitIntFlag
	Timeout          int
	E                multiSplitStringFlag
	Data             string
	Depth            int
	RecursePosition  int
	RecurseDelimeter string
	Retry            int
}
