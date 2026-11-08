package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ==================== 正则 ====================

const ipPart = `([0-9a-fA-F.:]+)`

var (
	timeRE = regexp.MustCompile(`^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{1,2}月\s*\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

	isoTimeRE = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?`)

	sshPrefixRE = regexp.MustCompile(`sshd(?:-session)?\[(\d+)\]:\s*`)

	pAccept = regexp.MustCompile(`Accepted (\S+) for (\S+) from ` + ipPart + `(?: port (\d+))?`)

	pFailed = regexp.MustCompile(`Failed (\S+) for (?:(?:invalid|illegal) user ?)?(\S*) from ` + ipPart + `(?: port (\d+))?`)

	pInvalid = regexp.MustCompile(`Invalid user (\S*) from ` + ipPart + `(?: port (\d+))?`)

	pMaxauth = regexp.MustCompile(`maximum authentication attempts exceeded for (invalid user ?)?(\S*) from ` + ipPart + `(?: port (\d+))?`)

	pPreauthUser = regexp.MustCompile(`(?:Connection closed by|Disconnected from) (?:authenticating user|invalid user) (\S+) ` + ipPart + `(?: port (\d+))?`)

	pPreauthNouser = regexp.MustCompile(`(?:Connection closed by|Disconnected from|Did not receive identification string from|banner exchange: Connection from) ` + ipPart + `(?: port (\d+))?`)

	pSession = regexp.MustCompile(`pam_unix\(sshd(?:-session)?:session\): session (opened|closed) for user ([^\s(]+)`)

	pNewuser = regexp.MustCompile(`useradd\[\d+\]: new user: name=([^,]+), UID=(\d+)`)

	pGroupadd = regexp.MustCompile(`(?:useradd|usermod)\[\d+\]: add '([^']+)' to group '([^']+)'`)

	pSudoCmd = regexp.MustCompile(`sudo:\s+(\S+)\s+:\s+TTY=\S+\s*;\s*PWD=\S*\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)`)

	pSudoDeny = regexp.MustCompile(`sudo:\s+(\S+)\s+:\s+command not allowed\s*;.*?USER=(\S+)\s*;\s*COMMAND=(.*)`)

	pSudoNotin = regexp.MustCompile(`sudo:\s+(\S+)\s+:\s+user NOT in sudoers`)

	pSudoFailcnt = regexp.MustCompile(`sudo:\s+(\S+)\s+:\s+(\d+)\s+incorrect password attempts`)

	pSudoSession = regexp.MustCompile(`pam_unix\(sudo:session\): session opened for user (\S+) by (.*?)\(uid=\d+\)`)

	pSuSession = regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session opened for user (\S+) by (.*?)\(uid=\d+\)`)

	pSuTo = regexp.MustCompile(`su\[\d+\]: \(to (\S+)\) (\S+) on (\S+)`)

	pSuDenied = regexp.MustCompile(`su\[\d+\]: FAILED SU \(to (\S+)\) (\S+) on (\S+)`)

	textPat    = regexp.MustCompile(`(?i)^(?:auth\.log|secure)(?:[.\-][\w.]+)?(?:\.gz)?$`)
	btmpPat    = regexp.MustCompile(`(?i)^btmp(?:[.\-]\d+)?(?:\.gz)?$`)
	wtmpPat    = regexp.MustCompile(`(?i)^wtmp(?:[.\-]\d+)?(?:\.gz)?$`)
	lastlogPat = regexp.MustCompile(`(?i)^lastlog$`)
)

// ==================== 事件 ====================

type Event struct {
	Type    string
	Time    time.Time
	Date    string
	TimeStr string
	User    string
	IP      string
	Port    int
	Method  string
	Invalid bool
	PID     string
	UID     int
	HasUID  bool
	Group   string
	Target  string
	Command string
	Raw     string
}

func newEvent(evType string, t time.Time, raw string) *Event {
	return &Event{
		Type:    evType,
		Time:    t,
		Date:    t.Format("2006-01-02"),
		TimeStr: t.Format("15:04:05"),
		Raw:     raw,
	}
}

// ==================== 时间戳解析 ====================

var syslogTimeRE = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$`)
var cnTimeRE = regexp.MustCompile(`^(\d{1,2})月\s*(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$`)

// parseLogTime 解析 syslog 时间戳（英文 Feb 11 与中文 2月 11）。
func parseLogTime(t string) (mo, d, h, mi, s int, ok bool) {
	if m := syslogTimeRE.FindStringSubmatch(t); m != nil {
		mo, ok = enMonths[m[1]]
		if !ok {
			return 0, 0, 0, 0, 0, false
		}
		return mo, atoi(m[2]), atoi(m[3]), atoi(m[4]), atoi(m[5]), true
	}
	if m := cnTimeRE.FindStringSubmatch(t); m != nil {
		return atoi(m[1]), atoi(m[2]), atoi(m[3]), atoi(m[4]), atoi(m[5]), true
	}
	return 0, 0, 0, 0, 0, false
}

func validDate(y, mo, d int) bool {
	if mo < 1 || mo > 12 || d < 1 {
		return false
	}
	return d <= daysIn(y, mo)
}

func daysIn(y, mo int) int {
	switch mo {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	}
	if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
		return 29
	}
	return 28
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// inferYear 无年份日志按文件修改时间推断年份：月份差 >= 6 视为跨年。
func inferYear(mtime time.Time, month int) int {
	y := mtime.Year()
	if month-int(mtime.Month()) >= 6 {
		y--
	}
	return y
}

type tsInfo struct {
	yearKnown bool
	dt        time.Time
	mo, d     int
	h, mi, s  int
	rest      string
	ok        bool
}

// splitTimestamp 识别行首时间戳：syslog 或 ISO（journald）。
func splitTimestamp(line string) tsInfo {
	if loc := timeRE.FindStringIndex(line); loc != nil {
		t := line[:loc[1]]
		if mo, d, h, mi, s, ok := parseLogTime(t); ok {
			return tsInfo{mo: mo, d: d, h: h, mi: mi, s: s, rest: line[loc[1]:], ok: true}
		}
		return tsInfo{}
	}
	if m := isoTimeRE.FindStringSubmatch(line); m != nil {
		y, mo, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
		h, mi, s := atoi(m[4]), atoi(m[5]), atoi(m[6])
		if !validDate(y, mo, d) || h > 23 || mi > 59 || s > 60 {
			return tsInfo{}
		}
		// ISO 时间戳带时区偏移时同样丢弃偏移，统一按本地时间构造
		dt := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.Local)
		return tsInfo{yearKnown: true, dt: dt, rest: line[len(m[0]):], ok: true}
	}
	return tsInfo{}
}

// ==================== 行解析 ====================

func parseSudoSu(rest string, t time.Time, line string) *Event {
	if m := pSudoCmd.FindStringSubmatch(rest); m != nil {
		ev := newEvent("sudo_cmd", t, line)
		ev.User = intern(m[1])
		ev.Target = m[2]
		ev.Command = strings.TrimSpace(m[3])
		return ev
	}
	if m := pSudoDeny.FindStringSubmatch(rest); m != nil {
		ev := newEvent("sudo_deny", t, line)
		ev.User = intern(m[1])
		ev.Target = m[2]
		ev.Command = strings.TrimSpace(m[3])
		return ev
	}
	if m := pSudoNotin.FindStringSubmatch(rest); m != nil {
		ev := newEvent("sudo_deny", t, line)
		ev.User = intern(m[1])
		return ev
	}
	if m := pSudoFailcnt.FindStringSubmatch(rest); m != nil {
		ev := newEvent("sudo_deny", t, line)
		ev.User = intern(m[1])
		ev.Command = fmt.Sprintf("%d 次密码错误", atoi(m[2]))
		return ev
	}
	if m := pSudoSession.FindStringSubmatch(rest); m != nil {
		ev := newEvent("sudo_session", t, line)
		ev.User = intern(m[2])
		ev.Target = m[1]
		return ev
	}
	if m := pSuSession.FindStringSubmatch(rest); m != nil {
		ev := newEvent("su_session", t, line)
		ev.User = intern(m[2])
		ev.Target = m[1]
		return ev
	}
	if m := pSuTo.FindStringSubmatch(rest); m != nil {
		ev := newEvent("su_session", t, line)
		ev.User = intern(m[2])
		ev.Target = m[1]
		return ev
	}
	if m := pSuDenied.FindStringSubmatch(rest); m != nil {
		ev := newEvent("su_deny", t, line)
		ev.User = intern(m[2])
		ev.Target = m[1]
		return ev
	}
	return nil
}

// parseLine 把一行日志解析为事件；未命中任何已知模式时返回 nil。
func parseLine(line string, mtime time.Time) *Event {
	ts := splitTimestamp(line)
	if !ts.ok {
		return nil
	}
	var t time.Time
	if ts.yearKnown {
		t = ts.dt
	} else {
		y := inferYear(mtime, ts.mo)
		if !validDate(y, ts.mo, ts.d) || ts.h > 23 || ts.mi > 59 || ts.s > 60 {
			return nil
		}
		t = time.Date(y, time.Month(ts.mo), ts.d, ts.h, ts.mi, ts.s, 0, time.Local)
	}
	rest := ts.rest

	if strings.Contains(rest, "useradd") || strings.Contains(rest, "usermod") {
		if m := pNewuser.FindStringSubmatch(rest); m != nil {
			ev := newEvent("useradd_new", t, line)
			ev.User = intern(strings.TrimSpace(m[1]))
			ev.UID = atoi(m[2])
			ev.HasUID = true
			return ev
		}
		if m := pGroupadd.FindStringSubmatch(rest); m != nil {
			ev := newEvent("group_add", t, line)
			ev.User = intern(m[1])
			ev.Group = m[2]
			return ev
		}
		return nil
	}

	if strings.Contains(rest, "sudo") || strings.Contains(rest, "su[") || strings.Contains(rest, "pam_unix(su") {
		return parseSudoSu(rest, t, line)
	}

	if !strings.Contains(rest, "sshd") {
		return nil
	}
	pid := ""
	if pm := sshPrefixRE.FindStringSubmatch(rest); pm != nil {
		pid = pm[1]
	}

	if strings.Contains(rest, "session opened") || strings.Contains(rest, "session closed") {
		if m := pSession.FindStringSubmatch(rest); m != nil {
			evType := "session_close"
			if m[1] == "opened" {
				evType = "session_open"
			}
			ev := newEvent(evType, t, line)
			ev.User = intern(m[2])
			ev.PID = pid
			return ev
		}
		return nil
	}

	if m := pAccept.FindStringSubmatch(rest); m != nil {
		ev := newEvent("accepted", t, line)
		ev.User = intern(m[2])
		ev.IP = intern(m[3])
		ev.Port = atoi(m[4])
		ev.Method = intern(m[1])
		ev.PID = pid
		return ev
	}

	if m := pFailed.FindStringSubmatch(rest); m != nil {
		ev := newEvent("failed", t, line)
		ev.User = intern(orEmpty(m[2], "(空)"))
		ev.IP = intern(m[3])
		ev.Port = atoi(m[4])
		ev.Method = intern(m[1])
		ev.PID = pid
		return ev
	}

	if m := pInvalid.FindStringSubmatch(rest); m != nil {
		ev := newEvent("invalid_user", t, line)
		ev.User = intern(orEmpty(m[1], "(空)"))
		ev.IP = intern(m[2])
		ev.Port = atoi(m[3])
		ev.Invalid = true
		ev.PID = pid
		return ev
	}

	if m := pMaxauth.FindStringSubmatch(rest); m != nil {
		ev := newEvent("max_auth", t, line)
		ev.User = intern(orEmpty(m[2], "(空)"))
		ev.IP = intern(m[3])
		ev.Port = atoi(m[4])
		ev.Invalid = m[1] != ""
		ev.PID = pid
		return ev
	}

	if m := pPreauthUser.FindStringSubmatch(rest); m != nil {
		ev := newEvent("preauth_close", t, line)
		ev.User = intern(m[1])
		ev.IP = intern(m[2])
		ev.Port = atoi(m[3])
		ev.PID = pid
		return ev
	}

	if m := pPreauthNouser.FindStringSubmatch(rest); m != nil {
		// 无用户名的断开（Connection closed by IP / Did not receive / banner exchange）
		// 在 OpenSSH 7.x～9.x 均发生在认证前阶段，计入认证中断
		ev := newEvent("preauth_close", t, line)
		ev.IP = intern(m[1])
		ev.Port = atoi(m[2])
		ev.PID = pid
		return ev
	}

	return nil
}

func orEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// ==================== 文件流 ====================

// openMaybeGzip 打开文件并识别 gzip 魔数自动解压；错误打印警告并返回 ok=false。
func openMaybeGzip(path string) (io.Reader, io.Closer, bool) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			fmt.Println(cYellow(fmt.Sprintf("警告: 无权限读取 %s，已跳过（需要 root 或对应组权限）", path)))
		} else {
			fmt.Println(cYellow(fmt.Sprintf("警告: 读取 %s 失败: %v", path, err)))
		}
		return nil, nil, false
	}
	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := br.Peek(2)
	if err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			fmt.Println(cYellow(fmt.Sprintf("警告: 解压 %s 失败: %v", path, gerr)))
			f.Close()
			return nil, nil, false
		}
		return gz, multiCloser{gz, f}, true
	}
	return br, f, true
}

type multiCloser struct {
	gz *gzip.Reader
	f  *os.File
}

func (m multiCloser) Close() error {
	m.gz.Close()
	return m.f.Close()
}

// eachTextLine 逐行回调日志文本（自动解压、去空白、跳过空行）。
func eachTextLine(path string, fn func(string)) {
	rc, closer, ok := openMaybeGzip(path)
	if !ok {
		return
	}
	defer closer.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			line = strings.ToValidUTF8(line, string(utf8.RuneError))
		}
		fn(line)
	}
}

// eachTextEvent 逐事件回调文本日志（生成器语义，不在内存保留事件列表）。
func eachTextEvent(path string, mtime time.Time, fn func(*Event)) {
	eachTextLine(path, func(line string) {
		if ev := parseLine(line, mtime); ev != nil {
			fn(ev)
		}
	})
}

// iterAllEvents 按来源顺序串联全部文本事件流。
func iterAllEvents(sources []source, fn func(*Event)) {
	for _, src := range sources {
		var mtime time.Time
		if st, err := os.Stat(src.Path); err == nil {
			mtime = st.ModTime()
		}
		eachTextEvent(src.Path, mtime, fn)
	}
}
