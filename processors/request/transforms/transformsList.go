package transforms

import (
	b64 "encoding/base64"
	"fmt"
	"net/url"
)

type TransformList map[string]func(...string) string

func NewTransformList() TransformList {
	t := TransformList{
		"b64Encode": b64Encode,
		"b64Decode": b64Decode,
		"urlEncode": urlEncode,
		"urlDecode": urlDecode,
	}
	return t
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
