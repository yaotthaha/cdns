package log

import "fmt"

type tagLogger struct {
	tag string
	Logger
}

func NewTagLogger(rootLogger Logger, tag string) Logger {
	return &tagLogger{
		tag:    tag,
		Logger: rootLogger,
	}
}

func (t *tagLogger) Print(level Level, a ...any) {
	t.Logger.Print(level, fmt.Sprintf("[%s] %s", t.tag, fmt.Sprint(a...)))
}

func (t *tagLogger) Info(a ...any) {
	t.Print(Info, a...)
}

func (t *tagLogger) Warn(a ...any) {
	t.Print(Warn, a...)
}

func (t *tagLogger) Error(a ...any) {
	t.Print(Error, a...)
}

func (t *tagLogger) Debug(a ...any) {
	t.Print(Debug, a...)
}

func (t *tagLogger) Fatal(a ...any) {
	t.Print(Fatal, a...)
}
