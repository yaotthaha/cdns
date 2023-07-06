package log

import (
	"context"
	"fmt"
	"time"

	"github.com/yaotthaha/cdns/lib/tools"

	"github.com/fatih/color"
)

type contextTag struct{}

type contextMsg struct {
	tag   string
	color color.Attribute
	start time.Time
}

type contextLogger struct {
	Logger
}

func AddContextTag(ctx context.Context) context.Context {
	cmg := &contextMsg{
		tag:   tools.RandomNumStr(8),
		color: RandomColor(),
		start: time.Now(),
	}
	return context.WithValue(ctx, (*contextTag)(nil), cmg)
}

func GetContextTag(ctx context.Context) string {
	v := ctx.Value((*contextTag)(nil))
	if v == nil {
		return ""
	}
	return v.(*contextMsg).tag
}

func NewContextLogger(rootLogger Logger) ContextLogger {
	c := &contextLogger{
		Logger: rootLogger,
	}
	return c
}

func (c *contextLogger) EnableColor() bool {
	if cl, ok := c.Logger.(ColorLogger); ok {
		return cl.EnableColor()
	} else {
		return false
	}
}

func (c *contextLogger) PrintContext(ctx context.Context, level Level, a ...any) {
	v := ctx.Value((*contextTag)(nil))
	if v == nil {
		c.Print(level, a...)
		return
	}
	value := v.(*contextMsg)
	an := make([]any, 0)
	if c.EnableColor() {
		an = append(an, fmt.Sprintf("[%s] ", GetColor(value.color).Sprintf("%s %dms", value.tag, time.Since(value.start).Milliseconds())))
	} else {
		an = append(an, fmt.Sprintf("[%s %dms] ", value.tag, time.Since(value.start).Milliseconds()))
	}
	an = append(an, a...)
	c.Print(level, an...)
}

func (c *contextLogger) InfoContext(ctx context.Context, a ...any) {
	c.PrintContext(ctx, Info, a...)
}

func (c *contextLogger) WarnContext(ctx context.Context, a ...any) {
	c.PrintContext(ctx, Warn, a...)
}

func (c *contextLogger) ErrorContext(ctx context.Context, a ...any) {
	c.PrintContext(ctx, Error, a...)
}

func (c *contextLogger) DebugContext(ctx context.Context, a ...any) {
	c.PrintContext(ctx, Debug, a...)
}

func (c *contextLogger) FatalContext(ctx context.Context, a ...any) {
	c.PrintContext(ctx, Fatal, a...)
}
