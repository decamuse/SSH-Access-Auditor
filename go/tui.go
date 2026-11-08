package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ==================== 显示宽度 ====================

// dispWidth 字符串的终端显示宽度：东亚全角按 2，其余按 1。
func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func runeWidth(r rune) int {
	if isWideRune(r) {
		return 2
	}
	return 1
}

// isWideRune 覆盖常见东亚全角区间，命中字符按 2 个显示单元计。
func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E, // CJK 部首与符号
		r >= 0x3041 && r <= 0x33FF, // 假名与 CJK 符号
		r >= 0x3400 && r <= 0x4DBF, // CJK 扩展 A
		r >= 0x4E00 && r <= 0x9FFF, // CJK 统一表意
		r >= 0xA000 && r <= 0xA4CF, // 彝文
		r >= 0xAC00 && r <= 0xD7A3, // 谚文音节
		r >= 0xF900 && r <= 0xFAFF, // CJK 兼容表意
		r >= 0xFE30 && r <= 0xFE4F, // CJK 兼容形式
		r >= 0xFF00 && r <= 0xFF60, // 全角形式
		r >= 0xFFE0 && r <= 0xFFE6: // 全角符号
		return true
	}
	return false
}

// fitLine 把 label 截断到与 prefix 合计不超过终端宽度，避免换行破坏光标上移重绘。
func fitLine(prefix, label string, width int) string {
	avail := width - 2 - dispWidth(prefix)
	if avail < 4 {
		avail = 4
	}
	var out strings.Builder
	w := 0
	for _, ch := range label {
		cw := runeWidth(ch)
		if w+cw > avail-1 {
			out.WriteString("…")
			break
		}
		out.WriteRune(ch)
		w += cw
	}
	return prefix + out.String()
}

// ==================== 勾选界面 ====================

// checkboxSelect 通用空格勾选界面，返回选中下标列表。
// 按键：上下移动，空格 切换，a 全选/全不选，回车 确认，q 或 Esc 取消（恢复初始勾选）。
// 非 TTY 环境自动回退为数字选择。
func checkboxSelect(labels []string, checked []bool, title string) []int {
	n := len(labels)
	initial := make([]bool, n)
	copy(initial, checked)
	if !isATTY(os.Stdin.Fd()) || !isATTY(os.Stdout.Fd()) || n == 0 {
		return checkboxNumeric(labels, initial, title)
	}

	termWidth := terminalWidth()
	state := make([]bool, n)
	copy(state, initial)
	cursor := 0

	lineText := func(i int) string {
		mark := "[ ]"
		if state[i] {
			mark = "[x]"
		}
		return fitLine(fmt.Sprintf("  %s %d. ", mark, i+1), labels[i], termWidth)
	}

	renderHeader := func() {
		fmt.Println(fitLine("", fmt.Sprintf("%s（上下移动，空格 切换，a 全选/全不选，回车 确认，q 取消）", title), termWidth))
	}

	draw := func(first bool) {
		var out strings.Builder
		for i := 0; i < n; i++ {
			text := lineText(i)
			if i == cursor {
				text = "\x1b[7m" + text + "\x1b[27m"
			}
			out.WriteString("\r\x1b[K")
			out.WriteString(text)
			if i < n-1 {
				out.WriteString("\n")
			}
		}
		// 光标上移指令单独写入：与其余输出拼接会引入多余换行，重绘后整体下移一行
		prefix := ""
		if !first {
			prefix = fmt.Sprintf("\x1b[%dA", n)
		}
		fmt.Print(prefix + out.String() + "\n")
	}

	restore, err := enterRawMode()
	if err != nil {
		return checkboxNumeric(labels, initial, title)
	}
	defer restore()

	renderHeader()
	for i := 0; i < n; i++ {
		fmt.Printf("\r\x1b[K%s\n", lineText(i))
	}
	for {
		key := readKey()
		switch key {
		case "up":
			cursor = (cursor - 1 + n) % n
		case "down":
			cursor = (cursor + 1) % n
		case "space":
			state[cursor] = !state[cursor]
		case "all":
			all := true
			for _, s := range state {
				if !s {
					all = false
					break
				}
			}
			flag := !all
			for i := range state {
				state[i] = flag
			}
		case "enter":
			var picked []int
			for i := range state {
				if state[i] {
					picked = append(picked, i)
				}
			}
			return picked
		case "quit":
			var picked []int
			for i := range initial {
				if initial[i] {
					picked = append(picked, i)
				}
			}
			return picked
		}
		draw(false)
	}
}

func checkboxNumeric(labels []string, state []bool, title string) []int {
	fmt.Println(title)
	for i, label := range labels {
		mark := "[ ]"
		if state[i] {
			mark = "[x]"
		}
		fmt.Printf("  %s %d. %s\n", mark, i+1, label)
	}
	fmt.Print("输入要保留的编号（逗号分隔，回车=保持当前勾选，0=全部取消）: ")
	line, ok := readLine()
	if !ok || strings.TrimSpace(line) == "" {
		var picked []int
		for i, v := range state {
			if v {
				picked = append(picked, i)
			}
		}
		return picked
	}
	line = strings.TrimSpace(line)
	if line == "0" {
		return []int{}
	}
	picks := map[int]bool{}
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if n := atoi(tok); n >= 1 && n <= len(labels) {
			picks[n-1] = true
		}
	}
	var out []int
	for i := range picks {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

// ==================== 输入辅助 ====================

var stdinReader = bufio.NewReader(os.Stdin)

func readLine() (string, bool) {
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return strings.TrimRight(line, "\r\n"), true
}

func inputPaths(prompt string) []string {
	fmt.Print(prompt)
	line, ok := readLine()
	if !ok {
		return nil
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	var out []string
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "~") {
			if home, err := os.UserHomeDir(); err == nil {
				tok = filepath.Join(home, tok[1:])
			}
		}
		if abs, err := filepath.Abs(tok); err == nil {
			tok = abs
		}
		out = append(out, tok)
	}
	return out
}

// ==================== 交互模式 ====================

func detectSystem() (string, string) {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		info := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.Index(line, "="); i >= 0 {
				k := strings.TrimSpace(line[:i])
				v := strings.TrimSpace(line[i+1:])
				v = strings.Trim(v, `"`)
				info[k] = v
			}
		}
		name := info["NAME"]
		if name == "" {
			name = "Linux"
		}
		return strings.TrimSpace(name+" "+info["VERSION_ID"]), "/var/log"
	}
	if runtimeIsLinux() {
		return "Linux", "/var/log"
	}
	if isDarwin() {
		return "macOS", ""
	}
	if isWindows() {
		return "Windows", ""
	}
	return runtimeGOOS(), ""
}

func renderFileList(items []*logItem) {
	checked := 0
	for _, it := range items {
		if it.Checked {
			checked++
		}
	}
	fmt.Printf("\n当前文件（共 %d 个，已勾选 %d 个）：\n", len(items), checked)
	if len(items) == 0 {
		fmt.Println("  （空）")
	}
	labels := itemLabels(items)
	for i, it := range items {
		mark := cRed("[ ]")
		if it.Checked {
			mark = cGreen("[✓]")
		}
		fmt.Printf("  %s %s\n", mark, labels[i])
	}
}

func interactiveSelect() []*logItem {
	sysname, logdir := detectSystem()
	var items []*logItem
	fmt.Println(cCyan(cBold("=== SSH-Access-Auditor 交互模式 ===")))
	if logdir != "" {
		fmt.Printf("检测到系统：%s（Linux）\n", cCyan(cBold(sysname)))
		items = discoverDir(logdir)
		fmt.Printf("日志目录：%s，共发现 %s 个 SSH 相关日志文件\n", cCyan(logdir), cBold(fmt.Sprintf("%d", len(items))))
		kinds := map[string]bool{}
		for _, it := range items {
			kinds[it.Kind] = true
		}
		if len(items) == 0 {
			fmt.Println(cYellow("默认目录未发现 SSH 日志，可手动添加；直接分析时将自动从 journald 提取 sshd 日志"))
		} else if !kinds["text"] {
			fmt.Println(cYellow(fmt.Sprintf("未发现文本 SSH 日志（auth.log/secure）：分析时将自动从 journald 提取最近 %d 天 sshd 日志，也可通过菜单手动添加", journalDays)))
		}
	} else {
		fmt.Printf("检测到系统：%s（非 Linux，无默认 SSH 日志目录）\n", cCyan(cBold(sysname)))
		fmt.Println("请通过菜单手动添加文件或目录")
	}

	for {
		renderFileList(items)
		fmt.Println("\n操作：")
		fmt.Println("  1. 开始分析（回车默认）")
		fmt.Println("  2. 添加目录")
		fmt.Println("  3. 添加文件")
		fmt.Println("  4. 只选特定文件")
		fmt.Print("> ")
		choice, ok := readLine()
		if !ok {
			return nil
		}
		choice = strings.TrimSpace(choice)
		switch choice {
		case "", "1":
			var selected []*logItem
			for _, it := range items {
				if it.Checked {
					selected = append(selected, it)
				}
			}
			if len(selected) == 0 {
				fmt.Println(cYellow("未勾选任何文件，无法开始分析；请先添加或勾选"))
				continue
			}
			return selected
		case "2":
			for _, p := range inputPaths("输入目录路径（空格分隔多个）: ") {
				st, err := os.Stat(p)
				if err != nil || !st.IsDir() {
					fmt.Println(cRed(fmt.Sprintf("  跳过：不是目录 %s", p)))
					continue
				}
				known := map[string]bool{}
				for _, it := range items {
					known[it.Path] = true
				}
				var newItems []*logItem
				for _, it := range discoverDir(p) {
					if !known[it.Path] {
						newItems = append(newItems, it)
					}
				}
				if len(newItems) > 0 {
					items = append(items, newItems...)
					sortItemsByPath(items)
					fmt.Println(cGreen(fmt.Sprintf("  已添加 %d 个文件", len(newItems))))
				} else {
					fmt.Println(cYellow(fmt.Sprintf("  目录中未发现 SSH 日志文件 %s", p)))
				}
			}
		case "3":
			for _, p := range inputPaths("输入文件路径（空格分隔多个）: ") {
				st, err := os.Stat(p)
				if err != nil || st.IsDir() {
					fmt.Println(cRed(fmt.Sprintf("  跳过：不是文件 %s", p)))
					continue
				}
				known := map[string]bool{}
				for _, it := range items {
					known[it.Path] = true
				}
				if known[p] {
					fmt.Println(cYellow(fmt.Sprintf("  已存在 %s", p)))
					continue
				}
				items = append(items, makeItem(p, ""))
				sortItemsByPath(items)
				fmt.Println(cGreen(fmt.Sprintf("  已添加 %s", filepath.Base(p))))
			}
		case "4":
			if len(items) == 0 {
				fmt.Println(cYellow("当前没有文件可筛选，请先添加"))
				continue
			}
			labels := itemLabels(items)
			state := make([]bool, len(items))
			for i, it := range items {
				state[i] = it.Checked
			}
			picked := checkboxSelect(labels, state, "勾选要分析的文件")
			pickSet := map[int]bool{}
			for _, i := range picked {
				pickSet[i] = true
			}
			for i, it := range items {
				it.Checked = pickSet[i]
			}
			fmt.Println(cGreen(fmt.Sprintf("  已勾选 %d/%d 个文件", len(picked), len(items))))
		default:
			fmt.Println(cYellow(fmt.Sprintf("无效选项 '%s'，请输入 1～4", choice)))
		}
	}
}

func sortItemsByPath(items []*logItem) {
	sort.SliceStable(items, func(i, j int) bool { return items[i].Path < items[j].Path })
}

// ==================== 退出/导出菜单 ====================

func finishMenu(ctx *runCtx, opts *options) {
	for {
		fmt.Println("\n后续操作：")
		fmt.Println("  1. 退出（回车默认）")
		fmt.Println("  2. 导出")
		fmt.Print("> ")
		choice, ok := readLine()
		if !ok {
			fmt.Println()
			return
		}
		choice = strings.TrimSpace(choice)
		if choice == "" || choice == "1" {
			return
		}
		if choice == "2" {
			exportMenu(ctx, opts)
			continue
		}
		fmt.Println(cYellow(fmt.Sprintf("无效选项 '%s'，请输入 1 或 2", choice)))
	}
}

func exportMenu(ctx *runCtx, opts *options) {
	labels := make([]string, len(exportItems))
	defaults := make([]bool, len(exportItems))
	for i, it := range exportItems {
		labels[i] = it.Desc
		defaults[i] = it.Key == "html"
	}
	picked := checkboxSelect(labels, defaults, "选择要导出的格式")
	if len(picked) == 0 {
		fmt.Println(cYellow("未选择任何格式，已返回"))
		return
	}
	base := "SSH审计报告_" + nowStamp()
	cwd, _ := os.Getwd()
	stem := filepath.Join(cwd, base)
	for _, i := range picked {
		switch exportItems[i].Key {
		case "txt":
			renderReportTxt(ctx.an, opts, stem+".txt", ctx.binary, opts.threshold, opts.window)
		case "html":
			renderReportHTML(ctx.an, opts, stem+".html", ctx.binary, opts.threshold, opts.window, ctx.dormant)
		case "json":
			exportJSON(ctx.sources, ctx.an, opts, stem+".json", ctx.binary, opts.threshold, opts.window)
		case "csv":
			exportCSV(ctx.sources, stem+".csv")
		}
	}
}
