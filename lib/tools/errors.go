package tools

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
)

var errs = []error{io.EOF, net.ErrClosed, io.ErrClosedPipe, os.ErrClosed, http.ErrServerClosed, syscall.EPIPE, syscall.ECONNRESET, context.Canceled, context.DeadlineExceeded}

func IsCloseOrCanceled(err error) bool {
	for _, e := range errs {
		if errors.Is(err, e) {
			return true
		}
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	if strings.Contains(err.Error(), "broken pipe") {
		return true
	}
	return false
}
