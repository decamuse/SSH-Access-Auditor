package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// ==================== utmp 系列二进制（glibc 布局，384 字节） ====================

// binaryStats 三类二进制日志的聚合结果。
type binaryStats struct {
	Btmp    []*btmpStats
	Wtmp    []*wtmpStats
	Lastlog []*lastlogStats
}

// 记录为 glibc 定长 384 字节的小端布局：
// 0 ut_type(i16) / 2 pad / 4 pid(i32) / 8 line(32) / 40 id(4) /
// 44 user(32) / 76 host(256) / 332 exit(i16) / 334 termination(i16) /
// 336 session(i32) / 340 tv_sec(i32) / 344 tv_usec(i32) / 348 addr(16) / 364 保留(20)
const utmpSize = 384

type utmpRec struct {
	utType  int
	pid     int32
	line    string
	user    string
	host    string
	t       time.Time
	hasTime bool
}

// eachUtmpRecord 逐块解出 utmp 系列记录；记录大小非标准时警告并整体跳过。
func eachUtmpRecord(path string, fn func(utmpRec) bool) bool {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Println(cYellow(fmt.Sprintf("警告: 读取 %s 失败: %v", path, err)))
		return false
	}
	if !isGzipFile(path) && fi.Size()%utmpSize != 0 {
		warnUtmpSize(path, fi.Size())
		return false
	}
	rc, closer, ok := openMaybeGzip(path)
	if !ok {
		return false
	}
	defer closer.Close()

	buf := make([]byte, utmpSize)
	var total int64
	for {
		n, rerr := ioReadFull(rc, buf)
		total += int64(n)
		if n > 0 && n < utmpSize {
			// 尾部残缺记录不足一条，按非标准大小整体跳过
			warnUtmpSize(path, total)
			return false
		}
		if rerr != nil {
			break
		}
		rec := parseUtmpRecord(buf)
		if !fn(rec) {
			return true
		}
	}
	if total > 0 && total%utmpSize != 0 {
		warnUtmpSize(path, total)
		return false
	}
	return true
}

func warnUtmpSize(path string, size int64) {
	fmt.Println(cYellow(fmt.Sprintf("警告: %s 记录大小非标准（%d 字节，不是 %d 的整数倍），可能是非 glibc 架构生成，已跳过", path, size, utmpSize)))
}

func parseUtmpRecord(b []byte) utmpRec {
	le := binary.LittleEndian
	utType := int(int16(le.Uint16(b[0:2])))
	pid := int32(le.Uint32(b[4:8]))
	tvSec := int64(int32(le.Uint32(b[340:344])))
	rec := utmpRec{
		utType: utType,
		pid:    pid,
		line:   cstr(b[8:40]),
		user:   cstr(b[44:76]),
		host:   cstr(b[76:332]),
	}
	if h := cstr(b[76:332]); h != "" {
		rec.host = h
	} else {
		rec.host = cstrIP(b[348:364])
	}
	if tvSec > 0 {
		rec.t = time.Unix(tvSec, 0)
		rec.hasTime = true
	}
	return rec
}

// cstr 定长字段字节转字符串：NUL 截断，非 UTF-8 回退 latin-1。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	if utf8Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// cstrIP ut_addr_v6 的 16 字节转 IP 字符串，全零返回空。
func cstrIP(b []byte) string {
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	tailZero := true
	for _, c := range b[4:] {
		if c != 0 {
			tailZero = false
			break
		}
	}
	if tailZero {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	// IPv4 映射地址（::ffff:0:0/96）打印为点分形式 ::ffff:a.b.c.d
	headZero := true
	for _, c := range b[:10] {
		if c != 0 {
			headZero = false
			break
		}
	}
	if headZero && b[10] == 0xff && b[11] == 0xff {
		return fmt.Sprintf("::ffff:%d.%d.%d.%d", b[12], b[13], b[14], b[15])
	}
	return netIPString(b)
}

// ==================== btmp 失败登录 ====================

type btmpStats struct {
	File         string
	TotalRecords int
	Fails        int
	Hosts        *ocounter
	Users        *ocounter
	First, Last  time.Time
}

// parseBtmpStats 流式聚合失败登录统计，不物化记录列表。
func parseBtmpStats(path string) *btmpStats {
	st := &btmpStats{File: path, Hosts: newOcounter(), Users: newOcounter()}
	ok := eachUtmpRecord(path, func(r utmpRec) bool {
		st.TotalRecords++
		if r.user == "" || (r.utType != 6 && r.utType != 7) {
			return true
		}
		st.Fails++
		h := r.host
		if h == "" {
			h = "(未知)"
		}
		st.Hosts.add(h)
		st.Users.add(r.user)
		if r.hasTime {
			if st.First.IsZero() || r.t.Before(st.First) {
				st.First = r.t
			}
			if st.Last.IsZero() || r.t.After(st.Last) {
				st.Last = r.t
			}
		}
		return true
	})
	if !ok {
		return nil
	}
	return st
}

// ==================== wtmp 登录会话 ====================

type wtmpSession struct {
	User, Line, Host string
	Open, Close      time.Time
	HasClose         bool
	Duration         time.Duration
	HasDur           bool
	Long             bool
	Note             string
}

type wtmpStats struct {
	File     string
	Sessions []wtmpSession
	Boots    int
}

func wtmpSessionOf(o utmpRec, close time.Time, hasClose bool, note string) wtmpSession {
	s := wtmpSession{
		User: o.user, Line: o.line, Host: o.host,
		Open: o.t, Close: close, HasClose: hasClose, Note: note,
	}
	if hasClose && o.hasTime {
		s.Duration = close.Sub(o.t)
		s.HasDur = true
		s.Long = s.Duration > 24*time.Hour
	}
	return s
}

// parseWtmpStats 按终端行配对 opened/closed，重启打断单独标注。
func parseWtmpStats(path string) *wtmpStats {
	st := &wtmpStats{File: path}
	opens := map[string]utmpRec{}
	var openOrder []string
	ok := eachUtmpRecord(path, func(r utmpRec) bool {
		if r.utType == 7 && r.user != "" {
			if _, exists := opens[r.line]; exists {
				st.Sessions = append(st.Sessions, wtmpSessionOf(opens[r.line], time.Time{}, false, ""))
			} else {
				openOrder = append(openOrder, r.line)
			}
			opens[r.line] = r
		} else if r.utType == 8 && r.line != "" {
			if o, exists := opens[r.line]; exists {
				st.Sessions = append(st.Sessions, wtmpSessionOf(o, r.t, r.hasTime, ""))
				delete(opens, r.line)
			}
		} else if r.utType == 2 {
			st.Boots++
			for _, line := range openOrder {
				if o, exists := opens[line]; exists {
					st.Sessions = append(st.Sessions, wtmpSessionOf(o, time.Time{}, false, "重启打断"))
					delete(opens, line)
				}
			}
			openOrder = nil
		}
		return true
	})
	if !ok {
		return nil
	}
	for _, line := range openOrder {
		if o, exists := opens[line]; exists {
			st.Sessions = append(st.Sessions, wtmpSessionOf(o, time.Time{}, false, ""))
			delete(opens, line)
		}
	}
	stableSortSessionsByOpen(st.Sessions)
	return st
}

func sessionOpenVal(s wtmpSession) int64 {
	if s.Open.IsZero() {
		return math.MinInt64 + 1
	}
	return s.Open.UnixNano()
}

func stableSortSessionsByOpen(ss []wtmpSession) {
	// 稳定排序保持同一时刻会话在文件中的先后顺序
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && sessionOpenVal(ss[j]) < sessionOpenVal(ss[j-1]); j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}

// ==================== lastlog 末次登录 ====================

var lastlogCands = []struct {
	rec  int
	tsize int
}{
	{292, 4},
	{296, 8},
	{288, 4},
}

type lastlogEntry struct {
	UID       int
	Name      string
	Time      time.Time
	Line, Host string
}

type lastlogStats struct {
	File       string
	Entries    []lastlogEntry
	RecordSize int
}

// loadPasswdNames 读 /etc/passwd 构建 uid 到用户名映射。
func loadPasswdNames() map[int]string {
	names := map[int]string{}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return names
	}
	for _, row := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSuffix(row, "\r"), ":")
		if len(parts) >= 3 && isDigits(parts[2]) {
			names[atoi(parts[2])] = parts[0]
		}
	}
	return names
}

// parseLastlogStats 按 uid 索引的定长记录解析末次登录。
func parseLastlogStats(path string, uidNames map[int]string) *lastlogStats {
	data := readAllMaybeGz(path)
	if len(data) == 0 {
		return nil
	}
	rec, tsize := 0, 4
	for _, cand := range lastlogCands {
		if len(data) >= cand.rec && len(data)%cand.rec == 0 {
			rec, tsize = cand.rec, cand.tsize
			break
		}
	}
	if rec == 0 {
		fmt.Println(cYellow(fmt.Sprintf("警告: %s 记录大小非标准（%d 字节），已跳过", path, len(data))))
		return nil
	}
	st := &lastlogStats{File: path, RecordSize: rec}
	count := len(data) / rec
	for uid := 0; uid < count; uid++ {
		chunk := data[uid*rec : (uid+1)*rec]
		var t int64
		off := 0
		if tsize == 8 {
			t = int64(binary.LittleEndian.Uint64(chunk[:8]))
			off = 8
		} else {
			t = int64(int32(binary.LittleEndian.Uint32(chunk[:4])))
			off = 4
		}
		if t <= 0 {
			continue
		}
		name, okName := uidNames[uid]
		if !okName {
			name = fmt.Sprintf("UID %d", uid)
		}
		st.Entries = append(st.Entries, lastlogEntry{
			UID:  uid,
			Name: name,
			Time: time.Unix(t, 0),
			Line: cstr(chunk[off : off+32]),
			Host: cstr(chunk[off+32 : off+32+256]),
		})
	}
	return st
}

// ==================== 工具 ====================

func isGzipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := ioReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x1f && magic[1] == 0x8b
}

// readAllMaybeGz 读取文件字节并自动解压 gzip（lastlog 需整体读取按记录数定档）。
func readAllMaybeGz(path string) []byte {
	rc, closer, ok := openMaybeGzip(path)
	if !ok {
		return nil
	}
	defer closer.Close()
	var out []byte
	buf := make([]byte, 1<<20)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return out
}

func utf8Valid(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		var size int
		switch {
		case c&0xe0 == 0xc0:
			size = 2
		case c&0xf0 == 0xe0:
			size = 3
		case c&0xf8 == 0xf0:
			size = 4
		default:
			return false
		}
		if i+size > len(b) {
			return false
		}
		for j := 1; j < size; j++ {
			if b[i+j]&0xc0 != 0x80 {
				return false
			}
		}
		i += size
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
