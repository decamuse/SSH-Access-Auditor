//go:build linux

package main

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"
)

func runtimeIsLinux() bool { return runtime.GOOS == "linux" }
func isDarwin() bool       { return false }
func isWindows() bool      { return false }
func runtimeGOOS() string  { return runtime.GOOS }

func notifyInterrupt(ch chan<- os.Signal) { signal.Notify(ch, os.Interrupt) }

// enableVT 在 Linux 上无需启用 VT 序列（原生支持）。
func enableVT() {}

// tcsetsw 为 TCSETSW 的 ioctl 请求字（stdlib syscall 未导出），
// 等价 libc tcsetattr 的 TCSADRAIN 语义（等待输出排空后生效）。
// x86_64 上 TCGETS=0x5401、TCSETS=0x5402、TCSETSW=0x5403、TCSETSF=0x5404。
const tcsetsw = 0x5403

func isATTY(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}

type winsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

func terminalWidth() int {
	ws := winsize{}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(),
		uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Col == 0 {
		return 80
	}
	return int(ws.Col)
}

// enterRawMode 进入原始终端模式（关闭行缓冲与回显），返回恢复函数。
func enterRawMode() (func(), error) {
	fd := os.Stdin.Fd()
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	raw := old
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(tcsetsw),
		uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	return func() {
		syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(tcsetsw),
			uintptr(unsafe.Pointer(&old)), 0, 0, 0)
	}, nil
}

func readKeyByte() (byte, bool) {
	var b [1]byte
	n, err := syscall.Read(int(os.Stdin.Fd()), b[:])
	if err != nil || n == 0 {
		return 0, false
	}
	return b[0], true
}
