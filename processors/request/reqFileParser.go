package request

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func FileToRequestAgent(reqContent string, urlBase string, proxy string, timeout int, removeHeaders []string) *ReqAgentHttp {
	getMethod := regexp.MustCompile(`\S+`)
	method := getMethod.FindString(reqContent)

	getURL := regexp.MustCompile(`\S+\s(\S+)`)
	pathGroups := getURL.FindStringSubmatch(reqContent)
	if len(pathGroups) <= 1 {
		fmt.Println("Error parsing url path from request file")
		os.Exit(1)
	}
	path := urlBase + pathGroups[1]

	getContent := regexp.MustCompile(`(?s)(?:\r\n\r\n|\n\n)(.*)`)
	bodyGroups := getContent.FindStringSubmatch(reqContent)
	body := ""
	if len(bodyGroups) > 1 {
		body = bodyGroups[1]
	}

	//remove any newlines at end of body
	removeNewlines := regexp.MustCompile(`(?s)(?:\n|\r)*\z`)
	body = removeNewlines.ReplaceAllString(body, "")

	// remove the body content
	parsedReqFile := getContent.ReplaceAllString(reqContent, "")

	getHeaders := regexp.MustCompile(`[\w-]+:\s.*`)
	headersArr := getHeaders.FindAllString(parsedReqFile, -1)
	// remove newlines from headers
	var cleanedHeaders []string
	stripNL := regexp.MustCompile(`\r|\n`)
	for _, header := range headersArr {

		//skip headers if they're in the removal list
		cleanHeader := stripNL.ReplaceAllString(header, "")
		skip := false
		for _, removeHeader := range removeHeaders {
			if strings.HasPrefix(cleanHeader, removeHeader) {
				skip = true
				break
			}
		}
		if !skip {
			cleanedHeaders = append(cleanedHeaders, cleanHeader)
		}
	}
	req := NewReqAgentHttp(path, method, cleanedHeaders, body, proxy, timeout)

	return req

}
