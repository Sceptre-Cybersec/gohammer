package request

import (
	"fmt"
	"os"
	"regexp"
)

func FileToRequestAgent(reqContent string, urlBase string, proxy string, timeout int) *ReqAgentHttp {
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

	// remove the body content
	parsedReqFile := getContent.ReplaceAllString(reqContent, "")

	getHeaders := regexp.MustCompile(`[\w-]+:\s.*`)
	headersArr := getHeaders.FindAllString(parsedReqFile, -1)
	// remove newlines from headers
	var cleanedHeaders []string
	stripNL := regexp.MustCompile(`\r|\n`)
	for _, header := range headersArr {
		cleanedHeaders = append(cleanedHeaders, stripNL.ReplaceAllString(header, ""))
	}

	req := NewReqAgentHttp(path, method, cleanedHeaders, body, proxy, timeout)

	return req

}
