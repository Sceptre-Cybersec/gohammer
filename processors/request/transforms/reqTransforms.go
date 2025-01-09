package transforms

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"gohammer/config"
	"gohammer/processors/response"
	"gohammer/utils"
)

type TransformContext struct {
	PreviousResponses []response.Resp
	Args              []string
}

// ApplyTransforms takes a list of transform templates and applies the functions included in the transforms
// Transform templates take the following form and accept fuzzing parameters and functions, Function(arg1), Function1(Function2(@0@:@1@)), @0@(test)
func ApplyTransforms(transfromTemplates string, transforms TransformList, positions []string, conf *config.Args, previousResponses *[]response.Resp) string {
	funcName, args := getFuncAndArgs(transfromTemplates)
	if funcName == "" {
		outp := normalize(transfromTemplates)
		return utils.ReplacePosition(outp, positions, conf.RecursionOptions.RecursePosition, conf.OutputOptions.Logger)
	} else if funcName != "" && len(args) > 0 {
		var argList []string
		for _, arg := range args {
			argList = append(argList, ApplyTransforms(arg, transforms, positions, conf, previousResponses))
		}
		context := TransformContext{
			Args:              argList,
			PreviousResponses: *previousResponses,
		}
		parsedFuncName := utils.ReplacePosition(funcName, positions, conf.RecursionOptions.RecursePosition, conf.OutputOptions.Logger)
		transFunc := transforms[parsedFuncName]
		if transFunc != nil {
			return transFunc(context)
		} else {
			conf.OutputOptions.Logger.Printf("Error: Invalid translation function %s\n", parsedFuncName)
		}
	}
	return ""
}

// ReplaceTransforms scans the specified string for transform positions (Ex: @t0@) and replaces them with the
// corresponding position from the positions array
func ReplaceTranformPosition(str string, positions []string, log *utils.Logger) string {
	r := regexp.MustCompile(`@t(\d+)@`)
	res := r.FindAllStringSubmatch(str, -1)
	for _, match := range res {
		posIdx, err := strconv.Atoi(match[1])
		if err != nil {
			log.Println("Error converting position index to integer")
			os.Exit(1)
		}
		if len(positions) > posIdx {
			str = strings.Replace(str, match[0], positions[posIdx], -1)
		}
	}
	return str
}

func normalize(input string) string {
	normalizer := regexp.MustCompile(`\\(.)`)
	input = normalizer.ReplaceAllString(input, `$1`)
	return input
}

// returns the function name at index 0 and returns the arguments
func getFuncAndArgs(input string) (string, []string) {
	transParser := regexp.MustCompile(`(\w+)\((.*)\)`)
	matches := transParser.FindAllStringSubmatch(input, -1)
	funcName := ""
	argsRaw := ""
	if len(matches) > 0 {
		match := matches[0]
		funcName = match[1]
		argsRaw = match[2]
	}

	args := splitArgs(argsRaw)
	return funcName, args
}

func splitArgs(input string) []string {

	bracketStack := 0
	// need this so user can escape brackets \( and \)
	prevChar := ""
	var argList []string
	lastSplitPos := 0

	for pos, char := range input {
		// update stack
		if string(char) == "(" && prevChar != "\\" {
			bracketStack++
		} else if string(char) == ")" && prevChar != "\\" {
			bracketStack--
		}

		// grab arguments
		if bracketStack == 0 && string(char) == "," && prevChar != "\\" {
			argList = append(argList, input[lastSplitPos:pos])
			lastSplitPos = pos + 1
		}

		prevChar = string(char)
	}
	argList = append(argList, string(input[lastSplitPos:]))

	return argList
}
