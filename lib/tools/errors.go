package tools

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

var errs = []error{io.EOF, net.ErrClosed, io.ErrClosedPipe, os.ErrClosed, syscall.EPIPE, syscall.ECONNRESET, context.Canceled, context.DeadlineExceeded}

func IsCloseOrCanceled(err error) bool {
	for _, e := range errs {
		if errors.Is(err, e) {
			return true
		}
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}
