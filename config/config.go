package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/wadeking98/gohammer/utils"
)

func splitMultiInt(value string) ([]int, error) {
	multiArr := []int{}
	flagSet := strings.Split(value, ",")
	var flagIntSet []int
	for _, s := range flagSet {
		i, err := strconv.Atoi(s)
		if err != nil {
			fmt.Printf("Error converting number: %s to int in command line arguments\n", s)
			return []int{}, err
		}
		flagIntSet = append(flagIntSet, i)
	}
	if len(flagIntSet) > 0 {
		multiArr = append(multiArr, flagIntSet...)
	}
	return multiArr, nil
}

func splitMultiString(value string) ([]string, error) {
	multiArr := []string{}
	flagSet := strings.Split(value, ",")
	if len(flagSet) > 0 {
		multiArr = append(multiArr, flagSet...)
	}
	return multiArr, nil
}

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
	splitStrings, err := splitMultiString(value)
	*m = append(*m, splitStrings...)
	return err
}

type multiSplitIntFlagOrAll []int

func (m *multiSplitIntFlagOrAll) Set(value string) error {
	setVal := value
	if value == "all" {
		setVal = "-1"
	}
	splitInts, err := splitMultiInt(setVal)
	*m = append(*m, splitInts...)
	return err
}

func (m *multiSplitIntFlagOrAll) String() string {
	return ""
}

type multiSplitIntFlag []int

func (m *multiSplitIntFlag) String() string {
	return ""
}
func (m *multiSplitIntFlag) Set(value string) error {
	splitInts, err := splitMultiInt(value)
	*m = append(*m, splitInts...)
	return err
}

type RequestOptions struct {
	Url           string
	Proxy         string
	Rate          int
	Method        string
	ReqFile       string
	Headers       multiStringFlag
	RemoveHeaders multiStringFlag
	Timeout       int
	Data          string
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
	RecurseCode      multiSplitIntFlag
}

type WordlistOptions struct {
	NoBrute    bool
	Extensions multiSplitStringFlag
	Files      []string
}

type FilterOptions struct {
	Mc multiSplitIntFlagOrAll
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
	Ec multiSplitIntFlag
}

type CaptureOptions struct {
	Cap      string
	CapGroup int
	CapFile  string
}

type TransformOptions struct {
	Transforms multiStringFlag
}

type OutputOptions struct {
	Logger *utils.Logger
}

type Args struct {
	RequestOptions   RequestOptions
	GeneralOptions   GeneralOptions
	RecursionOptions RecursionOptions
	WordlistOptions  WordlistOptions
	FilterOptions    FilterOptions
	CaptureOptions   CaptureOptions
	TransformOptions TransformOptions
	OutputOptions    OutputOptions
}
