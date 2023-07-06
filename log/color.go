package log

import (
	"math/rand"
	"sync"
	"time"

	"github.com/fatih/color"
)

var m sync.Map

func GetColor(c color.Attribute) *color.Color {
	ccAny, _ := m.LoadOrStore(c, color.New(c))
	cc := ccAny.(*color.Color)
	return cc
}

func RandomColor() color.Attribute {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return color.Attribute(31 + r.Intn(6))
}
