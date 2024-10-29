package transforms

import (
	"crypto/rand"
	b64 "encoding/base64"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type TransformList map[string]func(...string) string

func NewTransformList() TransformList {
	t := TransformList{
		"b64Encode": b64Encode,
		"b64Decode": b64Decode,
		"urlEncode": urlEncode,
		"urlDecode": urlDecode,
		"concat":    concat,
		"randStr":   randStr,
		"randInt":   randInt,
		"randBytes": randBytes,
	}
	return t
}

func strToInt(str string) (int64, error) {
	i, err := strconv.ParseInt(str, 10, 64)
	return i, err
}

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

func randStr(input ...string) string {
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

func randBytes(input ...string) string {
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

func randInt(input ...string) string {
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

func b64Encode(input ...string) string {
	return b64.StdEncoding.EncodeToString([]byte(input[0]))
}

func b64Decode(input ...string) string {
	output, err := b64.StdEncoding.DecodeString(input[0])
	if err != nil {
		fmt.Printf("Error: cannot decode b46 string %s", input)
		return ""
	}
	return string(output)
}

func urlEncode(input ...string) string {
	return url.QueryEscape(input[0])
}

func urlDecode(input ...string) string {
	output, err := url.QueryUnescape(input[0])
	if err != nil {
		fmt.Printf("Error: cannot decode url string %s", input)
		return ""
	}
	return string(output)
}

func concat(input ...string) string {
	output := ""
	for _, str := range input {
		output += str
	}
	return output
}
