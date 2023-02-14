package utils

import (
	"fmt"
	"io"
)

type LogLevel int

const (
	NONE    LogLevel = 0
	INFO             = 1
	DEBUG            = 2
	TESTING          = 3
)

type Logger struct {
	Level   LogLevel
	Channel io.Writer
}

func NewLogger(level LogLevel, channel io.Writer) *Logger {
	log := new(Logger)
	log.Level = level
	log.Channel = channel
	return log
}

func (l *Logger) Test(str string) {
	if l.Level == TESTING {
		fmt.Fprintln(l.Channel, str)
	}
}

func (l *Logger) Debug(str string) {
	if l.Level == DEBUG {
		fmt.Fprintln(l.Channel, str)
	}
}

func (l *Logger) Println(str string) {
	// fmt.Println("HERE")
	if l.Level != NONE {
		fmt.Fprintln(l.Channel, str)
	}
}

func (l *Logger) Print(str string) {
	// fmt.Println("HERE")
	if l.Level != NONE {
		fmt.Fprint(l.Channel, str)
	}
}

func (l *Logger) Printf(str string, a ...any) {
	if l.Level != NONE {
		fmt.Fprintf(l.Channel, str, a...)
	}
}
