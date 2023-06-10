package log

import (
	"context"
	"fmt"
	"time"
)

type Logger interface {
	Info(...any)
	Warn(...any)
	Error(...any)
	Debug(...any)
	Fatal(...any)
	Print(Level, ...any)
}

type Level string

const (
	Info  Level = "Info"
	Warn  Level = "Warn"
	Error Level = "Error"
	Debug Level = "Debug"
	Fatal Level = "Fatal"
)

func DefaultFormatFunc(level, s string) string {
	return fmt.Sprintf("[%s] [%s] %s", time.Now().Format(time.DateTime), level, s)
}

func DisableTimestampFormatFunc(level, s string) string {
	return fmt.Sprintf("[%s] %s", level, s)
}

type ContextLogger interface {
	Logger
	InfoContext(context.Context, ...any)
	WarnContext(context.Context, ...any)
	ErrorContext(context.Context, ...any)
	DebugContext(context.Context, ...any)
	FatalContext(context.Context, ...any)
	PrintContext(context.Context, Level, ...any)
}
