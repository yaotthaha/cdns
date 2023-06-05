package log

import (
	"fmt"
	"io"
	"os"
	"strings"
)

var DefaultSimpleLogger Logger

func init() {
	DefaultSimpleLogger = NewLogger()
	DefaultSimpleLogger.(*SimpleLogger).SetDebug(true)
}

type SimpleLogger struct {
	output     io.Writer
	formatFunc func(level, s string) string
	debug      bool
}

func NewLogger() *SimpleLogger {
	s := &SimpleLogger{
		output:     os.Stdout,
		formatFunc: defaultFormatFunc,
	}
	return s
}

func (s *SimpleLogger) SetOutput(w io.Writer) {
	if w != nil {
		s.output = w
	} else {
		s.output = io.Discard
	}
}

func (s *SimpleLogger) SetFormatFunc(f func(level, s string) string) {
	if f != nil {
		s.formatFunc = f
	}
}

func (s *SimpleLogger) SetDebug(debug bool) {
	s.debug = debug
}

func (s *SimpleLogger) print(level, str string) {
	str = strings.TrimSpace(str)
	fmt.Fprintln(s.output, s.formatFunc(level, str))
}

func (s *SimpleLogger) Print(level Level, any ...any) {
	if level == Debug && !s.debug {
		return
	}
	s.print(string(level), fmt.Sprint(any...))
}

func (s *SimpleLogger) Info(a ...any) {
	s.print(string(Info), fmt.Sprint(a...))
}

func (s *SimpleLogger) Warn(a ...any) {
	s.print(string(Warn), fmt.Sprint(a...))
}

func (s *SimpleLogger) Error(a ...any) {
	s.print(string(Error), fmt.Sprint(a...))
}

func (s *SimpleLogger) Debug(a ...any) {
	if s.debug {
		s.print(string(Debug), fmt.Sprint(a...))
	}
}

func (s *SimpleLogger) Fatal(a ...any) {
	s.print(string(Fatal), fmt.Sprint(a...))
}
