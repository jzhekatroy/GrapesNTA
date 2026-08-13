//go:build !linux

package afxdp

import (
	"context"
	"fmt"
	"runtime"
)

// Run is only available on Linux.
func Run(ctx context.Context, c Config) error {
	_ = ctx
	_ = c
	return fmt.Errorf("afxdp: only supported on linux (current GOOS=%s)", runtime.GOOS)
}
