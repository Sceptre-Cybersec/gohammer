package response

import (
	"fmt"
	"os"
	"regexp"

	"gohammer/config"
)

type Capture struct {
	response  *Resp
	capString string
	capGroup  int
	capFile   string
}

func NewCapture(resp *Resp, conf *config.Args) *Capture {
	c := Capture{
		response:  resp,
		capString: conf.CaptureOptions.Cap,
		capGroup:  conf.CaptureOptions.CapGroup,
		capFile:   conf.CaptureOptions.CapFile,
	}
	return &c
}

func (c *Capture) ApplyCapture() {
	re, err := regexp.Compile(c.capString)
	if err != nil {
		fmt.Printf("Error: invalid capture regex: %s", c.capString)
		os.Exit(1)
	}
	body := c.response.Body
	matches := re.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > c.capGroup {
			matchString := match[c.capGroup] + "\n"
			f, err := os.OpenFile("cap.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Println(err.Error())
				fmt.Println("Error creating capture file")
				os.Exit(1)
			}
			defer f.Close()

			f.WriteString(matchString)
		}
	}
}
