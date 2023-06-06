package log

import (
	"context"
	"fmt"
)

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

type tagContextLogger struct {
	tag string
	ContextLogger
}

func NewTagContextLogger(rootLogger ContextLogger, tag string) ContextLogger {
	return &tagContextLogger{
		tag:           tag,
		ContextLogger: rootLogger,
	}
}

func (t *tagContextLogger) Print(level Level, a ...any) {
	t.ContextLogger.Print(level, fmt.Sprintf("[%s] %s", t.tag, fmt.Sprint(a...)))
}

func (t *tagContextLogger) Info(a ...any) {
	t.Print(Info, a...)
}

func (t *tagContextLogger) Warn(a ...any) {
	t.Print(Warn, a...)
}

func (t *tagContextLogger) Error(a ...any) {
	t.Print(Error, a...)
}

func (t *tagContextLogger) Debug(a ...any) {
	t.Print(Debug, a...)
}

func (t *tagContextLogger) Fatal(a ...any) {
	t.Print(Fatal, a...)
}

func (t *tagContextLogger) FatalContext(ctx context.Context, a ...any) {
	t.PrintContext(ctx, Fatal, a...)
}

func (t *tagContextLogger) InfoContext(ctx context.Context, a ...any) {
	t.PrintContext(ctx, Info, a...)
}

func (t *tagContextLogger) WarnContext(ctx context.Context, a ...any) {
	t.PrintContext(ctx, Warn, a...)
}

func (t *tagContextLogger) ErrorContext(ctx context.Context, a ...any) {
	t.PrintContext(ctx, Error, a...)
}

func (t *tagContextLogger) DebugContext(ctx context.Context, a ...any) {
	t.PrintContext(ctx, Debug, a...)
}

func (t *tagContextLogger) PrintContext(ctx context.Context, level Level, a ...any) {
	t.ContextLogger.PrintContext(ctx, level, fmt.Sprintf("[%s] %s", t.tag, fmt.Sprint(a...)))
}
