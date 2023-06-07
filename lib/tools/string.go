package tools

import (
	"fmt"
	"strings"
)

func Join[T fmt.Stringer](arr []T, sep string) string {
	arrStr := make([]string, len(arr))
	for i, v := range arr {
		arrStr[i] = v.String()
	}
	return strings.Join(arrStr, sep)
}
