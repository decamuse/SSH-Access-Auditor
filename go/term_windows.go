//go:build windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"
)

func runtimeIsLinux() bool { return false }
func isDarwin() bool       { return false }
func isWindows() bool      { return true }
func runtimeGOOS() string  { return runtime.GOOS }

func notifyInterrupt(ch chan<- os.Signal) { signal.Notify(ch, os.Interrupt) }

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

var (
	procGetConsoleMode            = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode            = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

const (
	enableVirtualTerminalInput      = 0x0200
	enableVirtualTerminalProcessing = 0x0004
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableProcessedInput            = 0x0001
)

func consoleMode(h syscall.Handle) (uint32, bool) {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	return mode, r != 0
}

func isATTY(fd uintptr) bool {
	_, ok := consoleMode(syscall.Handle(fd))
	return ok
}

func enableVT() {
	h := syscall.Handle(os.Stdout.Fd())
	if mode, ok := consoleMode(h); ok {
		procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	}
}

func terminalWidth() int {
	type coord struct{ X, Y int16 }
	type smallRect struct{ L, T, R, B int16 }
	type csbi struct {
		Size              coord
		CursorPosition    coord
		Attributes        uint16
		Window            smallRect
		MaximumWindowSize coord
	}
	h := syscall.Handle(os.Stdout.Fd())
	var info csbi
	r, _, _ := procGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return 80
	}
	w := int(info.Window.R-info.Window.L) + 1
	if w <= 0 {
		return 80
	}
	return w
}

// enterRawMode 启用虚拟终端输入并关闭行输入、回显与 ^C 处理，方向键以 VT 序列读入。
func enterRawMode() (func(), error) {
	h := syscall.Handle(os.Stdin.Fd())
	old, ok := consoleMode(h)
	if !ok {
		return nil, fmt.Errorf("stdin 不是控制台")
	}
	mode := (old | enableVirtualTerminalInput) &^ uint32(enableLineInput|enableEchoInput|enableProcessedInput)
	if r, _, err := procSetConsoleMode.Call(uintptr(h), uintptr(mode)); r == 0 {
		return nil, err
	}
	return func() {
		procSetConsoleMode.Call(uintptr(h), uintptr(old))
	}, nil
}

func readKeyByte() (byte, bool) {
	var b [1]byte
	n, err := os.Stdin.Read(b[:])
	if err != nil || n == 0 {
		return 0, false
	}
	return b[0], true
}
