package transforms

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type TransformList map[string]func(TransformContext) string

func NewTransformList() TransformList {
	t := TransformList{
		"b64Encode":    b64Encode,
		"b64Decode":    b64Decode,
		"hexEncode":    hexEncode,
		"hexDecode":    hexDecode,
		"urlEncode":    urlEncode,
		"urlDecode":    urlDecode,
		"concat":       concat,
		"randStr":      randStr,
		"randInt":      randInt,
		"randBytes":    randBytes,
		"regex":        regex,
		"prevResponse": prevResponse,
	}
	return t
}

func strToInt(str string) (int64, error) {
	i, err := strconv.ParseInt(str, 10, 64)
	return i, err
}

// parse a range from string input:
// @param high, low default range
func parseRangeFromInput(high int64, low int64, input ...string) (int64, error) {
	cleanedInput := []int64{}
	var strMaxLen int64 = max(high, low)
	var strMinLen int64 = min(high, low)
	for i, inp := range input {
		inp = strings.ReplaceAll(inp, " ", "")
		if i >= 2 || inp == "" {
			break
		}
		parsedInt, err := strToInt(inp)
		if err != nil {
			return 0, err
		}
		cleanedInput = append(cleanedInput, parsedInt)
	}
	if len(cleanedInput) > 0 {
		strMaxLen = slices.Max(cleanedInput)
		strMinLen = slices.Min(cleanedInput)
	}

	// make a random number from minLen to maxLen
	number, err := rand.Int(rand.Reader, big.NewInt((strMaxLen-strMinLen)+1))
	if err != nil {
		return 0, err
	}
	number = big.NewInt(strMinLen + number.Int64())
	return number.Int64(), nil
}

func prevResponse(context TransformContext) string {
	input := context.Args
	responses := context.PreviousResponses
	if len(input) < 1 {
		fmt.Println("Error: invalid arguments, need prevResponse(<id_starting_at_0>)")
		return ""
	}
	rspIdx, err := strconv.Atoi(input[0])
	if err != nil {
		fmt.Printf("Error: could not convert %s to int (%s)", input[0], err.Error())
		return ""
	}
	rsp := responses[rspIdx]
	return rsp.ToString()
}

func regex(context TransformContext) string {
	input := context.Args
	if len(input) < 2 {
		fmt.Println("Error: invalid arguments, need regex(<test_string>,<regex>,[<match_group>])")
		return ""
	}
	matchGroupRaw := "0"
	if len(input) >= 3 {
		matchGroupRaw = input[2]
	}
	matchGroup, err := strconv.Atoi(matchGroupRaw)
	if err != nil {
		fmt.Printf("Error: error parsing match group (%s)\n", err.Error())
		return ""
	}

	re, err := regexp.Compile(input[1])
	if err != nil {
		fmt.Printf("Error: invalid regex (%s) please ensure that the regex is valid and special characters are escaped.\n", err.Error())
	}
	matches := re.FindAllStringSubmatch(input[0], -1)
	if len(matches) <= 0 {
		return ""
	}
	match := matches[0]
	if matchGroup >= len(match) {
		fmt.Printf("Error: match group %d out of bounds\n", matchGroup)
		return ""
	}

	return match[matchGroup]
}

func randStr(context TransformContext) string {
	input := context.Args
	codeAlphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	codeAlphabet += "abcdefghijklmnopqrstuvwxyz"
	codeAlphabet += "0123456789"
	length, err := parseRangeFromInput(65, 10, input...)
	if err != nil {
		fmt.Printf("Error: error parsing input (%s)\n", err.Error())
		return ""
	}
	retString := ""
	for range length {
		randAlphaIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeAlphabet))))
		if err != nil {
			fmt.Printf("Error: error generating random numbers (%s)\n", err.Error())
			return ""
		}
		retString += string(codeAlphabet[randAlphaIdx.Int64()])
	}
	return retString
}

func randBytes(context TransformContext) string {
	input := context.Args
	length, err := parseRangeFromInput(10, 1024, input...)
	if err != nil {
		fmt.Printf("Error: error parsing input (%s)\n", err.Error())
		return ""
	}
	buf := make([]byte, length)
	_, err = rand.Read(buf)
	if err != nil {
		fmt.Printf("Error: error generating random bytes (%s)\n", err.Error())
		return ""
	}
	return string(buf)
}

func randInt(context TransformContext) string {
	input := context.Args
	cleanedInput := []int64{}
	var strMaxLen int64 = math.MaxInt64 - 1
	var strMinLen int64 = 0
	for i, inp := range input {
		inp = strings.ReplaceAll(inp, " ", "")
		if i >= 2 || inp == "" {
			break
		}
		parsedInt, err := strToInt(inp)
		if err != nil {
			fmt.Println(err.Error())
			return ""
		}
		cleanedInput = append(cleanedInput, parsedInt)
	}
	if len(cleanedInput) > 0 {
		strMaxLen = slices.Max(cleanedInput)
		if len(cleanedInput) > 1 {
			strMinLen = slices.Min(cleanedInput)
		}
	}
	number, err := rand.Int(rand.Reader, big.NewInt((strMaxLen-strMinLen)+1))
	if err != nil {
		fmt.Printf("Error: error generating random numbers (%s)\n", err.Error())
		return ""
	}
	number = big.NewInt(number.Int64() + strMinLen)
	return number.String()
}

func hexEncode(context TransformContext) string {
	input := context.Args
	return hex.EncodeToString([]byte(input[0]))
}

func hexDecode(context TransformContext) string {
	input := context.Args
	byt, err := hex.DecodeString(input[0])
	if err != nil {
		fmt.Printf("Error: cannot decode hex string %s\n", input)
		return ""
	}
	return string(byt)
}

func b64Encode(context TransformContext) string {
	input := context.Args
	return b64.StdEncoding.EncodeToString([]byte(input[0]))
}

func b64Decode(context TransformContext) string {
	input := context.Args
	output, err := b64.StdEncoding.DecodeString(input[0])
	if err != nil {
		fmt.Printf("Error: cannot decode b46 string %s\n", input)
		return ""
	}
	return string(output)
}

func urlEncode(context TransformContext) string {
	input := context.Args
	return url.QueryEscape(input[0])
}

func urlDecode(context TransformContext) string {
	input := context.Args
	output, err := url.QueryUnescape(input[0])
	if err != nil {
		fmt.Printf("Error: cannot decode url string %s\n", input)
		return ""
	}
	return string(output)
}

func concat(context TransformContext) string {
	input := context.Args
	output := ""
	for _, str := range input {
		output += str
	}
	return output
}
