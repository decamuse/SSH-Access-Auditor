//go:build !linux && !windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
)

func runtimeIsLinux() bool { return runtime.GOOS == "linux" }
func isDarwin() bool       { return runtime.GOOS == "darwin" }
func isWindows() bool      { return false }
func runtimeGOOS() string  { return runtime.GOOS }

func notifyInterrupt(ch chan<- os.Signal) { signal.Notify(ch, os.Interrupt) }

func isATTY(fd uintptr) bool { return false }

func enableVT() {}

func terminalWidth() int { return 80 }

func enterRawMode() (func(), error) {
	return nil, fmt.Errorf("当前平台不支持原始终端模式")
}

func readKeyByte() (byte, bool) {
	var b [1]byte
	n, err := os.Stdin.Read(b[:])
	if err != nil || n == 0 {
		return 0, false
	}
	return b[0], true
}
