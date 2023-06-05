package tools

import (
	"math/rand"
	"strconv"
	"time"
)

func RandomNumStr(length int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var result string
	for i := 0; i < length; i++ {
		result += strconv.Itoa(r.Intn(10))
	}
	return result
}
