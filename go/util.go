package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// runCommand 运行外部命令，返回 (stdout, stderr, 退出码)。
func runCommand(name string, args []string) (string, string, int) {
	cmd := exec.Command(name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return "", err.Error(), -1
		}
	}
	return outBuf.String(), errBuf.String(), code
}

func sortStrings(s []string) { sort.Strings(s) }

func stableSortPairsByCountDesc(pairs []cntPair) {
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].n > pairs[j].n })
}

func nowStamp() string { return time.Now().Format("20060102_150405") }

func nowTime() time.Time { return time.Now() }

func netIPString(b []byte) string { return net.IP(b).String() }

func ioReadFull(r io.Reader, buf []byte) (int, error) { return io.ReadFull(r, buf) }

// readLinesFile 读取文本文件为行列表（非法字节以替换符保留，去掉 BOM）。
func readLinesFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ToValidUTF8(string(data), "\uFFFD")
	text = strings.TrimPrefix(text, "\uFEFF")
	return strings.Split(text, "\n"), nil
}

// readKey 读取一个按键并归类（依赖平台的 readKeyByte 提供原始字节）。
func readKey() string {
	ch, ok := readKeyByte()
	if !ok {
		return "quit"
	}
	if ch == 0x1b {
		ch2, ok2 := readKeyByte()
		if !ok2 {
			return "quit"
		}
		if ch2 == '[' {
			ch3, ok3 := readKeyByte()
			if !ok3 {
				return "other"
			}
			switch ch3 {
			case 'A':
				return "up"
			case 'B':
				return "down"
			default:
				return "other"
			}
		}
		return "quit"
	}
	if ch == '\r' || ch == '\n' {
		return "enter"
	}
	if ch == ' ' {
		return "space"
	}
	if ch == 'a' || ch == 'A' {
		return "all"
	}
	if ch == 'q' || ch == 'Q' {
		return "quit"
	}
	return "other"
}
