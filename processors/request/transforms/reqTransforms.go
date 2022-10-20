package transforms

import "regexp"

// ApplyTransforms takes a list of transform templates and applies the functions included in the transforms
// Transform templates take the following form and accept fuzzing parameters, Function("arg1"), Function1(Function2("@0@:@1@"))
func ApplyTransforms(transfromTemplates []string) string {
	transParser := regexp.MustCompile(`\w+\((.*)\)`)
	return ""
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

	// regex used to

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
			bracketStack++
		}

		// grab arguments
		if bracketStack == 0 && string(char) == "," {
			argList = append(argList, input[lastSplitPos:pos])
			lastSplitPos = pos + 1
		}

		prevChar = string(char)
	}
	argList = append(argList, input[lastSplitPos:len(input)])

	return argList
}
