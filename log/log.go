package log

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
)

type Logger interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
	Debug(a ...any)
	Fatal(a ...any)
	Print(level Level, a ...any)
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
	InfoContext(ctx context.Context, a ...any)
	WarnContext(ctx context.Context, a ...any)
	ErrorContext(ctx context.Context, a ...any)
	DebugContext(ctx context.Context, a ...any)
	FatalContext(ctx context.Context, a ...any)
	PrintContext(ctx context.Context, level Level, a ...any)
}

type ColorLogger interface {
	EnableColor() bool
}

type SetColorLogger interface {
	SetColor(color.Attribute)
}
