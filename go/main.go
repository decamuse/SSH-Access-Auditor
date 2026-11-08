// SSH-Access-Auditor：SSH 日志应急审计工具，编译产物为静态单文件二进制。
//
// 解析文本日志（auth.log/secure，含旋转与 .gz）与二进制日志（btmp/wtmp/lastlog），
// 自动发现日志并进入交互勾选界面，无文本日志时从 journald 兜底提取；
// 输出暴力破解、后门、提权等判定结果，支持 txt/html/json/csv 四类导出。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ==================== 常量 ====================

const (
	offHoursStart = 0
	offHoursEnd   = 6 // [0, 6) 即 00:00～05:59

	concurrentMinutes = 10 // 同账户相邻成功登录不同 IP 的判定窗口（分钟）
	newUserLoginDays  = 7  // 新建账户与首次成功登录的关联范围（天）
	journalDays       = 30 // journald 兜底提取的时间窗（天）
	topProfiles       = 10 // 终端结论区 IP 画像条数
	privRecent        = 20 // 终端结论区提权事件明细条数
	recentRows        = 20 // 二进制日志节明细条数上限
	dateProfileDays   = 3  // 日期画像默认显示的最近天数
	dateProfileRows   = 5  // 日期画像每天显示的来源 IP 条数上限
)

var enMonths = map[string]int{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

var failClass = map[string]bool{
	"failed": true, "invalid_user": true, "max_auth": true, "preauth_close": true,
}

var privGroups = map[string]bool{"sudo": true, "wheel": true, "adm": true, "admin": true, "root": true}

var typeLabelOrder = []string{
	"accepted", "failed", "invalid_user", "max_auth", "preauth_close",
	"session_open", "session_close", "useradd_new", "group_add",
	"sudo_cmd", "sudo_deny", "sudo_session", "su_session", "su_deny",
}

var typeLabel = map[string]string{
	"accepted":      "登录成功",
	"failed":        "认证失败",
	"invalid_user":  "无效用户",
	"max_auth":      "认证超限",
	"preauth_close": "认证中断",
	"session_open":  "会话开启",
	"session_close": "会话关闭",
	"useradd_new":   "新建账户",
	"group_add":     "组添加",
	"sudo_cmd":      "sudo提权",
	"sudo_deny":     "sudo认证失败",
	"sudo_session":  "sudo会话",
	"su_session":    "su会话",
	"su_deny":       "su认证失败",
}

var privTypes = []string{"sudo_cmd", "sudo_deny", "sudo_session", "su_session", "su_deny"}

var privTypesSet = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range privTypes {
		m[t] = true
	}
	return m
}()

var kindLabel = map[string]string{
	"text": "文本日志", "btmp": "失败登录", "wtmp": "登录会话",
	"lastlog": "末次登录", "unknown": "未知",
}

var exportItems = []struct {
	Key  string
	Desc string
}{
	{"txt", "文本报告（.txt）"},
	{"html", "HTML 报告（.html）"},
	{"json", "JSON 事件（.json）"},
	{"csv", "CSV 事件（.csv）"},
}

// ==================== 颜色 ====================

var useColor bool

func initColor(noColor bool) {
	if noColor || !isATTY(os.Stdout.Fd()) {
		return
	}
	enableVT()
	useColor = true
}

func cc(text, code string) string {
	if useColor {
		return "\x1b[" + code + "m" + text + "\x1b[0m"
	}
	return text
}

func cGreen(t string) string  { return cc(t, "32") }
func cRed(t string) string    { return cc(t, "31") }
func cYellow(t string) string { return cc(t, "33") }
func cHRed(t string) string   { return cc(t, "91") }
func cCyan(t string) string   { return cc(t, "36") }
func cBold(t string) string   { return cc(t, "1") }

// ==================== 时间与格式化 ====================

func fmtDT(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

// fmtTimeOfDay 只取时刻部分（15:04:05），零值显示 -。
func fmtTimeOfDay(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("15:04:05")
}

func fmtDuration(d time.Duration) string {
	total := int(d.Seconds())
	if total < 60 {
		return fmt.Sprintf("%d 秒", total)
	}
	if total < 3600 {
		return fmt.Sprintf("%d 分钟", total/60)
	}
	if total < 86400 {
		return fmt.Sprintf("%d 小时 %d 分", total/3600, total%3600/60)
	}
	return fmt.Sprintf("%d 天 %d 小时", total/86400, total%86400/3600)
}

// ==================== 有序计数器 ====================

// ocounter 有序计数器：按首次出现顺序稳定排序，同频次保持插入序。
type ocounter struct {
	counts map[string]int
	order  []string
}

func newOcounter() *ocounter {
	return &ocounter{counts: make(map[string]int)}
}

func (c *ocounter) add(s string) {
	if _, ok := c.counts[s]; !ok {
		c.order = append(c.order, s)
	}
	c.counts[s]++
}

func (c *ocounter) addN(s string, n int) {
	if _, ok := c.counts[s]; !ok {
		c.order = append(c.order, s)
	}
	c.counts[s] += n
}

func (c *ocounter) get(s string) int { return c.counts[s] }

func (c *ocounter) length() int { return len(c.order) }

type cntPair struct {
	k string
	n int
}

// mostCommon 返回按次数降序的前 n 项（n<0 表示全部）。
func (c *ocounter) mostCommon(n int) []cntPair {
	pairs := make([]cntPair, 0, len(c.order))
	for _, k := range c.order {
		pairs = append(pairs, cntPair{k, c.counts[k]})
	}
	stableSortPairsByCountDesc(pairs)
	if n >= 0 && len(pairs) > n {
		pairs = pairs[:n]
	}
	return pairs
}

// topUsernames 按频次取前 limit 个用户名，超出以「等 N 个」收尾。
func topUsernames(c *ocounter, limit int) string {
	if limit < 0 {
		limit = 5
	}
	common := c.mostCommon(limit)
	names := make([]string, 0, len(common))
	for _, p := range common {
		names = append(names, p.k)
	}
	suffix := ""
	if c.length() > limit {
		suffix = fmt.Sprintf(" 等 %d 个", c.length())
	}
	return strings.Join(names, "、") + suffix
}

// usernamesFull 全部尝试用户名，按次数降序（同频次保持插入序），顿号连接；
// 无记录返回 -。导出内容使用，不做任何截断。
func usernamesFull(c *ocounter) string {
	if c.length() == 0 {
		return "-"
	}
	names := make([]string, 0, c.length())
	for _, p := range c.mostCommon(-1) {
		names = append(names, p.k)
	}
	return strings.Join(names, "、")
}

// ==================== 字符串驻留 ====================

var internTab = map[string]string{}

func intern(s string) string {
	if s == "" {
		return ""
	}
	if v, ok := internTab[s]; ok {
		return v
	}
	internTab[s] = s
	return s
}

// ==================== CLI ====================

type options struct {
	paths     []string
	accepted  bool
	failed    bool
	outfile   string
	export    []string
	top       int
	threshold int
	window    int
	blacklist string
	noColor   bool
	yes       bool
	logfile   string
}

const helpText = `SSH 日志应急审计工具：暴力破解检测、时间窗关联、IP 画像、后门账户检测、btmp/wtmp/lastlog 解析、sudo/su 提权分析

用法:
  %[1]s [文件或目录...] [选项]

使用示例:
  1. 交互模式（自动识别系统与日志目录）:
     %[1]s

  2. 直接分析单个日志文件:
     %[1]s /var/log/auth.log

  3. 分析多个文件（目录只做一层发现，自动去重合并）:
     %[1]s /var/log/auth.log /var/log/auth.log.1 /var/log/btmp

  4. 大日志下只看 Top 10 攻击 IP 汇总:
     %[1]s ./auth.log -f --top 10

  5. 生成综合审计报告（.html 后缀自动生成 HTML 报告）:
     %[1]s ./auth.log -o report.html

  6. 导出 JSON 与 CSV 事件明细:
     %[1]s ./auth.log --export json,csv

  7. 自动化: 免交互分析并导出，不进入退出/导出菜单:
     %[1]s /var/log/auth.log -y -o report.txt --export csv

  8. 自定义暴力破解阈值与时间窗，加载本地 IP 黑名单:
     %[1]s ./auth.log --threshold 20 --window 60 --blacklist iplist.txt

选项:
  -a, --accepted          在屏幕显示认证成功的登录记录及统计信息
  -f, --failed            在屏幕显示认证失败的登录尝试及统计信息
  -o, --output FILE       生成审计报告并输出到指定文件（.html 后缀自动生成 HTML 报告）
      --export FORMats    导出结构化事件，格式 json 或 csv，逗号分隔可复选 (例如: --export json,csv)
      --top N             汇总模式：失败明细只显示 Top N 攻击 IP (例如: --top 10)
      --threshold N       暴力破解判定阈值：失败次数超过该值判定为暴力破解 (默认 10)
      --window N          疑似暴力破解成功关联窗口：成功登录前 N 分钟内失败达到阈值即高危 (默认 30)
      --blacklist FILE    本地 IP 黑名单文件，每行一个 IP 或 CIDR，命中在报告中高亮
      --no-color          关闭颜色输出
  -y, --yes               免交互：分析后不进入退出/导出菜单（需提供文件/目录参数）
  -h, --help              查看帮助

参数:
  paths                   日志文件或目录（目录只做一层发现；不带参数进入交互模式）
`

func cliError(msg string) {
	fmt.Fprintf(os.Stderr, "错误: %s\n", msg)
	os.Exit(2)
}

func parseArgs(argvIn []string) *options {
	opts := &options{threshold: 10, window: 30}
	argv := argvIn
	pos := 0
	next := func(name string) string {
		if pos >= len(argv) {
			cliError(fmt.Sprintf("%s 需要一个参数", name))
		}
		v := argv[pos]
		pos++
		return v
	}
	takeEq := func(a, name string) (string, bool) {
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"="), true
		}
		return "", false
	}

	for pos < len(argv) {
		a := argv[pos]
		pos++
		switch {
		case a == "-a" || a == "--accepted":
			opts.accepted = true
		case a == "-f" || a == "--failed":
			opts.failed = true
		case a == "-h" || a == "--help":
			fmt.Printf(helpText, filepath.Base(os.Args[0]))
			os.Exit(0)
		case a == "--no-color":
			opts.noColor = true
		case a == "-y" || a == "--yes":
			opts.yes = true
		case a == "-o" || a == "--output":
			opts.outfile = next(a)
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			opts.outfile = a[2:]
		default:
			if v, ok := takeEq(a, "--output"); ok {
				opts.outfile = v
				continue
			}
			if a == "--export" {
				opts.export = splitExport(next(a))
				continue
			}
			if v, ok := takeEq(a, "--export"); ok {
				opts.export = splitExport(v)
				continue
			}
			if a == "--top" {
				opts.top = atoiStrict(next(a), "--top")
				continue
			}
			if v, ok := takeEq(a, "--top"); ok {
				opts.top = atoiStrict(v, "--top")
				continue
			}
			if a == "--threshold" {
				opts.threshold = atoiStrict(next(a), "--threshold")
				continue
			}
			if v, ok := takeEq(a, "--threshold"); ok {
				opts.threshold = atoiStrict(v, "--threshold")
				continue
			}
			if a == "--window" {
				opts.window = atoiStrict(next(a), "--window")
				continue
			}
			if v, ok := takeEq(a, "--window"); ok {
				opts.window = atoiStrict(v, "--window")
				continue
			}
			if a == "--blacklist" {
				opts.blacklist = next(a)
				continue
			}
			if v, ok := takeEq(a, "--blacklist"); ok {
				opts.blacklist = v
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				cliError(fmt.Sprintf("不支持的参数: %s", a))
			}
			opts.paths = append(opts.paths, a)
		}
	}

	if opts.threshold < 1 {
		cliError("--threshold 必须 >= 1")
	}
	if opts.window < 1 {
		cliError("--window 必须 >= 1")
	}
	if opts.top < 0 {
		cliError("--top 必须 >= 1")
	}
	if opts.top == 0 {
		opts.top = 0 // 0 表示未启用
	}
	if opts.yes && len(opts.paths) == 0 {
		cliError("-y 免交互模式需要至少一个文件或目录参数")
	}
	return opts
}

func atoiStrict(s, name string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		cliError(fmt.Sprintf("%s 需要一个整数", name))
	}
	return v
}

func splitExport(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" {
			continue
		}
		out = append(out, x)
	}
	var bad []string
	for _, x := range out {
		if x != "json" && x != "csv" {
			bad = append(bad, x)
		}
	}
	if len(bad) > 0 {
		cliError(fmt.Sprintf("不支持的导出格式: %s（可选 json、csv）", strings.Join(bad, ", ")))
	}
	return out
}

// ==================== 主流程 ====================

func main() {
	opts := parseArgs(os.Args[1:])
	initColor(opts.noColor)

	if opts.blacklist != "" && !fileExists(opts.blacklist) {
		fmt.Println(cRed(fmt.Sprintf("错误: 找不到黑名单文件 '%s'", opts.blacklist)))
		os.Exit(1)
	}

	tmpPath := ""
	cleanup := func() {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}
	sigCh := make(chan os.Signal, 1)
	notifyInterrupt(sigCh)
	go func() {
		if _, ok := <-sigCh; ok {
			fmt.Println("\n已中断退出")
			cleanup()
			os.Exit(0)
		}
	}()

	var items []*logItem
	if len(opts.paths) > 0 {
		items = resolvePaths(opts.paths)
	} else {
		items = interactiveSelect()
	}
	if len(items) == 0 {
		fmt.Println("未选择任何文件，已退出")
		return
	}
	opts.logfile = ""
	ctx, _ := runAnalysis(items, opts)
	if ctx.tmpPath != "" {
		tmpPath = ctx.tmpPath
	}
	if !opts.yes {
		finishMenu(ctx, opts)
	}
	cleanup()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// ==================== 日志文件项 ====================

type logItem struct {
	Path    string
	Kind    string
	Mtime   time.Time
	HasTime bool
	Size    int64
	Checked bool
}

func classifyLogname(name string) string {
	if textPat.MatchString(name) {
		return "text"
	}
	if btmpPat.MatchString(name) {
		return "btmp"
	}
	if wtmpPat.MatchString(name) {
		return "wtmp"
	}
	if lastlogPat.MatchString(name) {
		return "lastlog"
	}
	return ""
}

func makeItem(path string, kind string) *logItem {
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	if kind == "" {
		k := classifyLogname(filepath.Base(path))
		if k == "" {
			k = "text"
		}
		kind = k
	}
	it := &logItem{Path: path, Kind: kind}
	if st, err := os.Stat(path); err == nil {
		it.Mtime = st.ModTime()
		it.HasTime = true
		it.Size = st.Size()
	}
	it.Checked = true
	return it
}

func discoverDir(path string) []*logItem {
	var items []*logItem
	names, err := os.ReadDir(path)
	if err != nil {
		fmt.Println(cRed(fmt.Sprintf("错误: 无法读取目录 %s: %v", path, err)))
		return items
	}
	var sorted []string
	for _, e := range names {
		sorted = append(sorted, e.Name())
	}
	sortStrings(sorted)
	for _, name := range sorted {
		full := filepath.Join(path, name)
		st, err := os.Stat(full)
		if err != nil || st.IsDir() {
			continue
		}
		kind := classifyLogname(name)
		if kind != "" {
			items = append(items, makeItem(full, kind))
		}
	}
	return items
}

type itemParts struct {
	name  string
	kind  string
	size  string
	mtime string
}

func itemPartsOf(it *logItem) itemParts {
	p := itemParts{kind: kindLabel[it.Kind], mtime: "?"}
	name := it.Path
	logdir := "/var/log"
	if strings.HasPrefix(name, logdir+string(os.PathSeparator)) {
		name = filepath.Base(name)
	}
	p.name = name
	if it.HasTime {
		p.mtime = it.Mtime.Format("2006-01-02 15:04")
	}
	size := it.Size
	if size >= 1024*1024 {
		p.size = fmt.Sprintf("%.1f MB", float64(size)/1024/1024)
	} else if size >= 1024 {
		p.size = fmt.Sprintf("%.0f KB", float64(size)/1024)
	} else {
		p.size = fmt.Sprintf("%d B", size)
	}
	return p
}

// padWidth 按终端显示宽度在右侧补空格到 w。
func padWidth(s string, w int) string {
	if d := dispWidth(s); d < w {
		return s + strings.Repeat(" ", w-d)
	}
	return s
}

// itemLabels 生成按列对齐的文件条目：文件名、类型、大小三列
// 分别按列表内最宽值补齐，文件名超宽时不截断，仅该行不参与对齐。
func itemLabels(items []*logItem) []string {
	parts := make([]itemParts, len(items))
	nameW, kindW, sizeW := 0, 0, 0
	for i, it := range items {
		parts[i] = itemPartsOf(it)
		if w := dispWidth(parts[i].name); w > nameW {
			nameW = w
		}
		if w := dispWidth(parts[i].kind); w > kindW {
			kindW = w
		}
		if w := len(parts[i].size); w > sizeW {
			sizeW = w
		}
	}
	out := make([]string, len(items))
	for i, p := range parts {
		out[i] = padWidth(p.name, nameW) + "  " + padWidth(p.kind, kindW) + " " +
			fmt.Sprintf("%*s", sizeW, p.size) + "  修改 " + p.mtime
	}
	return out
}

func resolvePaths(paths []string) []*logItem {
	var items []*logItem
	known := map[string]bool{}
	for _, p := range paths {
		if strings.HasPrefix(p, "~") {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, p[1:])
			}
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		st, err := os.Stat(p)
		if err != nil {
			fmt.Println(cRed(fmt.Sprintf("错误: 找不到文件或目录 '%s'", p)))
			os.Exit(1)
		}
		if st.IsDir() {
			found := discoverDir(p)
			if len(found) == 0 {
				fmt.Println(cYellow(fmt.Sprintf("警告: 目录中未发现 SSH 日志文件 %s", p)))
			}
			for _, it := range found {
				if !known[it.Path] {
					items = append(items, it)
					known[it.Path] = true
				}
			}
		} else {
			if !known[p] {
				items = append(items, makeItem(p, ""))
				known[p] = true
			}
		}
	}
	return items
}

// ==================== journald 兜底 ====================

func journalCapture() (string, string) {
	if _, err := lookPath("journalctl"); err != nil {
		return "", "journalctl 不可用"
	}
	args := []string{"-u", "ssh", "-u", "sshd",
		"-o", "short-iso-precise", "--no-pager", "--quiet",
		"--since", fmt.Sprintf("-%d days", journalDays)}
	out, errText, code := runCommand("journalctl", args)
	if code != 0 {
		msg := strings.TrimSpace(errText)
		if msg == "" {
			msg = "journalctl 执行失败"
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", msg
	}
	if strings.TrimSpace(out) == "" {
		return "", "journal 中没有 ssh/sshd 单元的日志"
	}
	f, err := os.CreateTemp("", "ssh_audit_journal_*.log")
	if err != nil {
		return "", err.Error()
	}
	if _, err := f.WriteString(out); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err.Error()
	}
	f.Close()
	return f.Name(), ""
}

// ==================== 分析编排 ====================

type runCtx struct {
	sources []source
	an      *analysis
	binary  *binaryStats
	dormant map[string]bool
	tmpPath string
}

func runAnalysis(items []*logItem, opts *options) (*runCtx, bool) {
	var textItems, btmpItems, wtmpItems, lastlogItems []*logItem
	for _, it := range items {
		switch it.Kind {
		case "text", "unknown":
			textItems = append(textItems, it)
		case "btmp":
			btmpItems = append(btmpItems, it)
		case "wtmp":
			wtmpItems = append(wtmpItems, it)
		case "lastlog":
			lastlogItems = append(lastlogItems, it)
		}
	}

	var sources []source
	var srcLines []string
	tmpPath := ""

	// journald 兜底：未选中文本日志时尝试提取（限定最近 journalDays 天）
	if len(textItems) == 0 && runtimeIsLinux() {
		fmt.Println(cYellow(fmt.Sprintf("未选中文本 SSH 日志，尝试从 journald 提取最近 %d 天的 sshd 日志（需要 root 或 systemd-journal 组权限，大日志约需 1 分钟）", journalDays)))
		p, err := journalCapture()
		if p != "" {
			tmpPath = p
			sources = append(sources, source{Path: p, Label: fmt.Sprintf("journald 近 %d 天", journalDays)})
			srcLines = append(srcLines, cCyan(fmt.Sprintf("journald（近 %d 天）: 已提取至临时文件", journalDays)))
			opts.logfile = fmt.Sprintf("journald 近 %d 天（journalctl -u ssh -u sshd）", journalDays)
		} else {
			fmt.Println(cYellow(fmt.Sprintf("  journald 提取失败: %s", err)))
		}
	}

	for _, it := range textItems {
		sources = append(sources, source{Path: it.Path, Label: filepath.Base(it.Path)})
	}

	var btmpList []*btmpStats
	for _, it := range btmpItems {
		if s := parseBtmpStats(it.Path); s != nil {
			btmpList = append(btmpList, s)
		}
	}
	for _, b := range btmpList {
		srcLines = append(srcLines, fmt.Sprintf("btmp %s: 失败记录 %d 条", filepath.Base(b.File), b.Fails))
	}
	var wtmpList []*wtmpStats
	for _, it := range wtmpItems {
		if s := parseWtmpStats(it.Path); s != nil {
			wtmpList = append(wtmpList, s)
		}
	}
	for _, w := range wtmpList {
		srcLines = append(srcLines, fmt.Sprintf("wtmp %s: 会话 %d 次", filepath.Base(w.File), len(w.Sessions)))
	}
	uidNames := loadPasswdNames()
	var lastlogList []*lastlogStats
	for _, it := range lastlogItems {
		if s := parseLastlogStats(it.Path, uidNames); s != nil {
			lastlogList = append(lastlogList, s)
		}
	}
	for _, ll := range lastlogList {
		srcLines = append(srcLines, fmt.Sprintf("lastlog %s: 记录 %d 条", filepath.Base(ll.File), len(ll.Entries)))
	}

	if opts.logfile == "" {
		names := make([]string, 0, len(items))
		for _, it := range items {
			names = append(names, filepath.Base(it.Path))
		}
		opts.logfile = strings.Join(names, "、")
	}

	var blacklistNets []netipPrefix
	if opts.blacklist != "" {
		nets, err := loadBlacklist(opts.blacklist)
		if err != nil {
			fmt.Println(cRed(fmt.Sprintf("错误: 无法读取黑名单文件 '%s': %v", opts.blacklist, err)))
			os.Exit(1)
		}
		blacklistNets = nets
	}

	an := analyzeSources(sources, opts.threshold, opts.window, blacklistNets)
	for _, ps := range an.perSource {
		srcLines = append(srcLines, fmt.Sprintf("%s: 事件 %d 条", ps.label, ps.count))
	}

	binary := &binaryStats{Btmp: btmpList, Wtmp: wtmpList, Lastlog: lastlogList}
	backdoorNames := map[string]bool{}
	for _, b := range an.backdoors {
		backdoorNames[b.User] = true
	}
	dormant := map[string]bool{}
	if len(lastlogList) > 0 || len(an.accepted) > 0 {
		// 登录记录同时来自 lastlog 与文本日志，两类都有的账户不算沉睡
		logged := map[string]bool{}
		for _, ll := range lastlogList {
			for _, e := range ll.Entries {
				logged[e.Name] = true
			}
		}
		for _, e := range an.accepted {
			if e.User != "" {
				logged[e.User] = true
			}
		}
		for n := range backdoorNames {
			if !logged[n] {
				dormant[n] = true
			}
		}
	}

	printHeader(an, opts, srcLines)
	total := an.totalEvents()
	if total == 0 && len(btmpList) == 0 && len(wtmpList) == 0 && len(lastlogList) == 0 {
		fmt.Println(cRed("未解析到任何已知 SSH 事件或日志记录，请确认文件格式"))
	} else {
		printConclusion(an, opts.threshold, opts.window, dormant)
		topN := opts.top
		if topN == 0 {
			topN = topProfiles
		}
		printProfileTable(an, topN)
		printDateProfile(an)
		printBtmpSection(btmpList)
		printWtmpSection(wtmpList)
		printLastlogSection(lastlogList, backdoorNames)
		if opts.accepted {
			printAcceptedDetail(an.accepted, opts.top)
		}
		if opts.failed {
			printFailedDetail(an, sources, opts.top)
		}
	}

	didOutput := false
	if opts.outfile != "" {
		var err error
		if strings.HasSuffix(strings.ToLower(opts.outfile), ".html") {
			err = renderReportHTML(an, opts, opts.outfile, binary, opts.threshold, opts.window, dormant)
		} else {
			err = renderReportTxt(an, opts, opts.outfile, binary, opts.threshold, opts.window)
		}
		if err != nil {
			fmt.Println(cRed(fmt.Sprintf("写入报告文件时发生错误: %v", err)))
			os.Exit(1)
		}
		didOutput = true
	}
	if len(opts.export) > 0 {
		base := "SSH审计报告_" + time.Now().Format("20060102_150405")
		cwd, _ := os.Getwd()
		stem := filepath.Join(cwd, base)
		for _, f := range opts.export {
			if f == "json" {
				exportJSON(sources, an, opts, stem+".json", binary, opts.threshold, opts.window)
			}
			if f == "csv" {
				exportCSV(sources, stem+".csv")
			}
		}
		didOutput = true
	}

	return &runCtx{sources: sources, an: an, binary: binary, dormant: dormant, tmpPath: tmpPath}, didOutput
}
