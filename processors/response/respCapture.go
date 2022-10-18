package response

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/wadeking98/gohammer/config"
)

type Capture struct {
	response  *Resp
	capString string
}

func NewCapture(resp *Resp, conf *config.Args) *Capture {
	c := Capture{
		response:  resp,
		capString: conf.CaptureOptions.Cap,
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
	matches := re.FindAllString(body, -1)
	if matches != nil {
		matchString := strings.Join(matches, "\n") + "\n"
		f, err := os.OpenFile("cap.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Println("Error creating capture file")
			os.Exit(1)
		}
		defer f.Close()

		f.WriteString(matchString)
	}
}
