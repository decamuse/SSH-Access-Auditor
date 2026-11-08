package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
)

// fixJSON 关闭 HTML 转义：< > & 三字符原样输出，不转义为 \u003c 等。
func fixJSON(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\\u003c"), []byte("<"))
	b = bytes.ReplaceAll(b, []byte("\\u003e"), []byte(">"))
	b = bytes.ReplaceAll(b, []byte("\\u0026"), []byte("&"))
	return b
}

func marshalNoEscape(v any) []byte {
	b, _ := json.Marshal(v)
	return fixJSON(b)
}

func jstr(s string) []byte { return marshalNoEscape(s) }

// ==================== ocounter 的 JSON 输出（保持插入序） ====================

func (c *ocounter) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range c.order {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(fixJSON(kb))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(c.counts[k]))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// pairsJSON 计数器转 [键, 值] 数组（most_common 前 n 项）。
func pairsJSON(c *ocounter, n int) [][]any {
	out := [][]any{}
	for _, p := range c.mostCommon(n) {
		out = append(out, []any{p.k, p.n})
	}
	return out
}

// ==================== 事件的有序 JSON ====================

func evPubJSON(e *Event) []byte {
	var b bytes.Buffer
	b.WriteString(`{"type":`)
	b.Write(jstr(e.Type))
	b.WriteString(`,"type_label":`)
	b.Write(jstr(typeLabel[e.Type]))
	b.WriteString(`,"time":`)
	b.Write(jstr(e.Time.Format("2006-01-02 15:04:05")))
	b.WriteString(`,"date":`)
	b.Write(jstr(e.Date))
	b.WriteString(`,"time_str":`)
	b.Write(jstr(e.TimeStr))
	b.WriteString(`,"user":`)
	if e.User == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.User))
	}
	b.WriteString(`,"ip":`)
	if e.IP == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.IP))
	}
	b.WriteString(`,"port":`)
	if e.Port > 0 {
		b.WriteString(strconv.Itoa(e.Port))
	} else {
		b.WriteString("null")
	}
	b.WriteString(`,"method":`)
	if e.Method == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.Method))
	}
	b.WriteString(`,"invalid":`)
	if e.Invalid {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString(`,"pid":`)
	if e.PID == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.PID))
	}
	b.WriteString(`,"uid":`)
	if e.HasUID {
		b.WriteString(strconv.Itoa(e.UID))
	} else {
		b.WriteString("null")
	}
	b.WriteString(`,"group":`)
	if e.Group == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.Group))
	}
	b.WriteString(`,"target":`)
	if e.Target == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.Target))
	}
	b.WriteString(`,"command":`)
	if e.Command == "" {
		b.WriteString("null")
	} else {
		b.Write(jstr(e.Command))
	}
	b.WriteString(`,"raw":`)
	b.Write(jstr(e.Raw))
	b.WriteString("}")
	return b.Bytes()
}

// ==================== JSON 导出 ====================

type eventCountsJ struct {
	Accepted     int `json:"accepted"`
	Failed       int `json:"failed"`
	InvalidUser  int `json:"invalid_user"`
	MaxAuth      int `json:"max_auth"`
	PreauthClose int `json:"preauth_close"`
	SessionOpen  int `json:"session_open"`
	SessionClose int `json:"session_close"`
	UseraddNew   int `json:"useradd_new"`
	GroupAdd     int `json:"group_add"`
	SudoCmd      int `json:"sudo_cmd"`
	SudoDeny     int `json:"sudo_deny"`
	SudoSession  int `json:"sudo_session"`
	SuSession    int `json:"su_session"`
	SuDeny       int `json:"su_deny"`
}

func newEventCountsJ(counts map[string]int) *eventCountsJ {
	return &eventCountsJ{
		Accepted:     counts["accepted"],
		Failed:       counts["failed"],
		InvalidUser:  counts["invalid_user"],
		MaxAuth:      counts["max_auth"],
		PreauthClose: counts["preauth_close"],
		SessionOpen:  counts["session_open"],
		SessionClose: counts["session_close"],
		UseraddNew:   counts["useradd_new"],
		GroupAdd:     counts["group_add"],
		SudoCmd:      counts["sudo_cmd"],
		SudoDeny:     counts["sudo_deny"],
		SudoSession:  counts["sudo_session"],
		SuSession:    counts["su_session"],
		SuDeny:       counts["su_deny"],
	}
}

type jsonParams struct {
	Threshold     int     `json:"threshold"`
	WindowMinutes int     `json:"window_minutes"`
	Top           *int    `json:"top"`
	Blacklist     *string `json:"blacklist"`
	ConcurrentMin int     `json:"concurrent_minutes"`
	OffHours      string  `json:"off_hours"`
	NewuserDays   int     `json:"newuser_login_days"`
}

type jsonMeta struct {
	Logfile     string        `json:"logfile"`
	GeneratedAt string        `json:"generated_at"`
	TimeStart   *string       `json:"time_start"`
	TimeEnd     *string       `json:"time_end"`
	Params      jsonParams    `json:"params"`
	EventCounts *eventCountsJ `json:"event_counts"`
}

type jsonBrute struct {
	IP     string `json:"ip"`
	Failed int    `json:"failed"`
}

type jsonSuspect struct {
	IP          string `json:"ip"`
	User        string `json:"user"`
	Time        string `json:"time"`
	WindowFails int    `json:"window_fails"`
	Method      string `json:"method"`
}

type jsonBackdoor struct {
	User    string   `json:"user"`
	UID     int      `json:"uid"`
	Created string   `json:"created"`
	UID0    bool     `json:"uid0"`
	Groups  []string `json:"groups"`
}

type jsonNewuser struct {
	User       string `json:"user"`
	UID        int    `json:"uid"`
	Created    string `json:"created"`
	FirstLogin string `json:"first_login"`
	IP         string `json:"ip"`
	DeltaSecs  int    `json:"delta_seconds"`
}

type jsonRoot struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Method string `json:"method"`
}

type jsonConcurrent struct {
	User      string `json:"user"`
	IP1       string `json:"ip1"`
	Time1     string `json:"time1"`
	IP2       string `json:"ip2"`
	Time2     string `json:"time2"`
	DeltaSecs int    `json:"delta_seconds"`
}

type jsonOffHours struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	User   string `json:"user"`
	Method string `json:"method"`
}

type jsonPrivilege struct {
	SudoCmd     [][]byte `json:"sudo_cmd"`
	SudoDeny    [][]byte `json:"sudo_deny"`
	SudoSession [][]byte `json:"sudo_session"`
	SuSession   [][]byte `json:"su_session"`
	SuDeny      [][]byte `json:"su_deny"`
}

func (p jsonPrivilege) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"sudo_cmd":`)
	writeEventArr(&b, p.SudoCmd)
	b.WriteString(`,"sudo_deny":`)
	writeEventArr(&b, p.SudoDeny)
	b.WriteString(`,"sudo_session":`)
	writeEventArr(&b, p.SudoSession)
	b.WriteString(`,"su_session":`)
	writeEventArr(&b, p.SuSession)
	b.WriteString(`,"su_deny":`)
	writeEventArr(&b, p.SuDeny)
	b.WriteString("}")
	return b.Bytes(), nil
}

func writeEventArr(b *bytes.Buffer, arr [][]byte) {
	b.WriteByte('[')
	for i, e := range arr {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(e)
	}
	b.WriteByte(']')
}

type jsonSession struct {
	User        string  `json:"user"`
	Open        string  `json:"open"`
	Close       *string `json:"close"`
	DurationSec *int    `json:"duration_seconds"`
	Over24h     bool    `json:"over_24h"`
}

type jsonSummary struct {
	BruteForceIPs []jsonBrute      `json:"brute_force_ips"`
	Suspected     []jsonSuspect    `json:"suspected_compromised"`
	Backdoors     []jsonBackdoor   `json:"backdoor_users"`
	NewuserLogin  []jsonNewuser    `json:"newuser_login"`
	RootLogins    []jsonRoot       `json:"root_logins"`
	Concurrent    []jsonConcurrent `json:"concurrent_logins"`
	OffHours      []jsonOffHours   `json:"off_hours_logins"`
	Privilege     jsonPrivilege    `json:"privilege"`
	BlacklistHits []string         `json:"blacklist_hits"`
	Sessions      []jsonSession    `json:"sessions"`
}

type jsonProfile struct {
	IP       string    `json:"ip"`
	Failed   int       `json:"failed"`
	Accepted int       `json:"accepted"`
	Invalid  int       `json:"invalid"`
	Users    *ocounter `json:"users"`
	Ports    []int     `json:"ports"`
	First    string    `json:"first"`
	Last     string    `json:"last"`
}

type jsonBtmp struct {
	File         string    `json:"file"`
	TotalRecords int       `json:"total_records"`
	Fails        int       `json:"fails"`
	First        string    `json:"first"`
	Last         string    `json:"last"`
	TopHosts     [][]any   `json:"top_hosts"`
	TopUsers     [][]any   `json:"top_users"`
}

type jsonWtmpSession struct {
	User        string  `json:"user"`
	Line        string  `json:"line"`
	Host        string  `json:"host"`
	Open        string  `json:"open"`
	Close       *string `json:"close"`
	DurationSec *int    `json:"duration_seconds"`
	Note        *string `json:"note"`
}

type jsonWtmp struct {
	File     string            `json:"file"`
	Boots    int               `json:"boots"`
	Total    int               `json:"sessions_count"`
	Sessions []jsonWtmpSession `json:"sessions"`
}

type jsonLastlogEntry struct {
	Name string `json:"name"`
	UID  int    `json:"uid"`
	Time string `json:"time"`
	Line string `json:"line"`
	Host string `json:"host"`
}

type jsonLastlog struct {
	File    string             `json:"file"`
	Entries []jsonLastlogEntry `json:"entries"`
}

type jsonBinary struct {
	Btmp    []jsonBtmp    `json:"btmp"`
	Wtmp    []jsonWtmp    `json:"wtmp"`
	Lastlog []jsonLastlog `json:"lastlog"`
}

func strPtr(s string) *string { return &s }
func intPtr(n int) *int       { return &n }

// exportJSON 导出完整结构化结果：meta、summary、ip_profiles、binary、events（事件流式写出）。
func exportJSON(sources []source, a *analysis, opts *options, outfile string, binary *binaryStats, threshold, window int) {
	meta := jsonMeta{
		Logfile:     opts.logfile,
		GeneratedAt: timeNowString(),
		Params: jsonParams{
			Threshold:     threshold,
			WindowMinutes: window,
			ConcurrentMin: concurrentMinutes,
			OffHours:      fmt.Sprintf("%02d:00-%02d:59", offHoursStart, offHoursEnd-1),
			NewuserDays:   newUserLoginDays,
		},
		EventCounts: newEventCountsJ(a.eventCounts),
	}
	if a.hasSpan {
		meta.TimeStart = strPtr(fmtDT(a.spanFirst))
		meta.TimeEnd = strPtr(fmtDT(a.spanLast))
	}
	if opts.top > 0 {
		meta.Params.Top = intPtr(opts.top)
	}
	if opts.blacklist != "" {
		meta.Params.Blacklist = strPtr(opts.blacklist)
	}

	summary := jsonSummary{
		BruteForceIPs: []jsonBrute{},
		Suspected:     []jsonSuspect{},
		Backdoors:     []jsonBackdoor{},
		NewuserLogin:  []jsonNewuser{},
		RootLogins:    []jsonRoot{},
		Concurrent:    []jsonConcurrent{},
		OffHours:      []jsonOffHours{},
		BlacklistHits: []string{},
		Sessions:      []jsonSession{},
	}
	if len(a.blacklistHits) > 0 {
		summary.BlacklistHits = a.blacklistHits
	}
	for _, b := range a.bruteIPs {
		summary.BruteForceIPs = append(summary.BruteForceIPs, jsonBrute{IP: b.ip, Failed: b.n})
	}
	for _, h := range a.suspected {
		summary.Suspected = append(summary.Suspected, jsonSuspect{
			IP: h.IP, User: h.User, Time: h.Date + " " + h.TimeStr,
			WindowFails: h.WindowFails, Method: h.Method,
		})
	}
	for _, b := range a.backdoors {
		gs := []string{}
		for _, g := range b.Groups {
			gs = append(gs, g.Group)
		}
		summary.Backdoors = append(summary.Backdoors, jsonBackdoor{
			User: b.User, UID: b.UID, Created: fmtDT(b.Created), UID0: b.UID0, Groups: gs,
		})
	}
	for _, x := range a.newUserLogin {
		summary.NewuserLogin = append(summary.NewuserLogin, jsonNewuser{
			User: x.User, UID: x.UID, Created: fmtDT(x.Created), FirstLogin: fmtDT(x.Login),
			IP: x.IP, DeltaSecs: int(x.Delta.Seconds()),
		})
	}
	for _, e := range a.rootLogins {
		summary.RootLogins = append(summary.RootLogins, jsonRoot{
			Time: fmtDT(e.Time), IP: e.IP, Port: e.Port, Method: e.Method,
		})
	}
	for _, x := range a.concurrent {
		summary.Concurrent = append(summary.Concurrent, jsonConcurrent{
			User: x.User, IP1: x.IP1, Time1: fmtDT(x.Time1), IP2: x.IP2, Time2: fmtDT(x.Time2),
			DeltaSecs: int(x.Delta.Seconds()),
		})
	}
	for _, e := range a.offHours {
		summary.OffHours = append(summary.OffHours, jsonOffHours{
			Time: fmtDT(e.Time), IP: e.IP, User: e.User, Method: e.Method,
		})
	}
	for _, t := range privTypes {
		for _, e := range a.privilege[t] {
			arr := evPubJSON(e)
			switch t {
			case "sudo_cmd":
				summary.Privilege.SudoCmd = append(summary.Privilege.SudoCmd, arr)
			case "sudo_deny":
				summary.Privilege.SudoDeny = append(summary.Privilege.SudoDeny, arr)
			case "sudo_session":
				summary.Privilege.SudoSession = append(summary.Privilege.SudoSession, arr)
			case "su_session":
				summary.Privilege.SuSession = append(summary.Privilege.SuSession, arr)
			case "su_deny":
				summary.Privilege.SuDeny = append(summary.Privilege.SuDeny, arr)
			}
		}
	}
	for _, s := range a.sessions {
		js := jsonSession{User: s.User, Open: fmtDT(s.Open), Over24h: s.Long}
		if s.HasClose {
			v := fmtDT(s.Close)
			js.Close = &v
		}
		// 零时长会话不写 0，duration_seconds 记 null，与「未知时长」同样处理
		if s.HasDur && s.Duration > 0 {
			v := int(s.Duration.Seconds())
			js.DurationSec = &v
		}
		summary.Sessions = append(summary.Sessions, js)
	}

	profilesDoc := []jsonProfile{}
	for _, p := range a.sortedProfiles() {
		ports := make([]int, 0, len(p.Ports))
		for port := range p.Ports {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		profilesDoc = append(profilesDoc, jsonProfile{
			IP: p.IP, Failed: p.Failed, Accepted: p.Accepted, Invalid: p.Invalid,
			Users: p.Users, Ports: ports, First: fmtDT(p.First), Last: fmtDT(p.Last),
		})
	}

	binaryDoc := jsonBinary{
		Btmp:    []jsonBtmp{},
		Wtmp:    []jsonWtmp{},
		Lastlog: []jsonLastlog{},
	}
	for _, b := range binary.Btmp {
		binaryDoc.Btmp = append(binaryDoc.Btmp, jsonBtmp{
			File: b.File, TotalRecords: b.TotalRecords, Fails: b.Fails,
			First: fmtDT(b.First), Last: fmtDT(b.Last),
			TopHosts: pairsJSON(b.Hosts, -1), TopUsers: pairsJSON(b.Users, -1),
		})
	}
	for _, w := range binary.Wtmp {
		jw := jsonWtmp{File: w.File, Boots: w.Boots, Total: len(w.Sessions), Sessions: []jsonWtmpSession{}}
		for _, s := range w.Sessions {
			jws := jsonWtmpSession{User: s.User, Line: s.Line, Host: s.Host, Open: fmtDT(s.Open)}
			if s.Note != "" {
				v := s.Note
				jws.Note = &v
			}
			if s.HasClose {
				v := fmtDT(s.Close)
				jws.Close = &v
			}
			if s.HasDur {
				v := int(s.Duration.Seconds())
				jws.DurationSec = &v
			}
			jw.Sessions = append(jw.Sessions, jws)
		}
		binaryDoc.Wtmp = append(binaryDoc.Wtmp, jw)
	}
	for _, ll := range binary.Lastlog {
		entries := make([]lastlogEntry, len(ll.Entries))
		copy(entries, ll.Entries)
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
		jl := jsonLastlog{File: ll.File, Entries: []jsonLastlogEntry{}}
		for _, e := range entries {
			jl.Entries = append(jl.Entries, jsonLastlogEntry{
				Name: e.Name, UID: e.UID, Time: fmtDT(e.Time), Line: e.Line, Host: e.Host,
			})
		}
		binaryDoc.Lastlog = append(binaryDoc.Lastlog, jl)
	}

	f, err := os.Create(outfile)
	if err != nil {
		fmt.Println(cRed(fmt.Sprintf("写入 JSON 文件时发生错误: %v", err)))
		return
	}
	defer f.Close()
	w := func(b []byte) { f.Write(b) }
	w([]byte("{\n  \"meta\": "))
	w(marshalNoEscapeIndent(meta))
	w([]byte(",\n  \"summary\": "))
	w(marshalNoEscapeIndent(summary))
	w([]byte(",\n  \"ip_profiles\": "))
	w(marshalNoEscapeIndent(profilesDoc))
	w([]byte(",\n  \"binary_sources\": "))
	w(marshalNoEscapeIndent(binaryDoc))
	w([]byte(",\n  \"events\": ["))
	first := true
	iterAllEvents(sources, func(e *Event) {
		if first {
			w([]byte("\n    "))
			first = false
		} else {
			w([]byte(",\n    "))
		}
		w(evPubJSON(e))
	})
	w([]byte("\n  ]\n}"))
	fmt.Println(cGreen(fmt.Sprintf("JSON 事件导出已完成: %s", outfile)))
}

func marshalNoEscapeIndent(v any) []byte {
	b, _ := json.Marshal(v)
	return fixJSON(jsonIndent(b))
}

// jsonIndent 对已生成 JSON 统一为 2 空格缩进。
func jsonIndent(b []byte) []byte {
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return b
	}
	return out.Bytes()
}

func timeNowString() string { return nowTime().Format("2006-01-02 15:04:05") }

// ==================== CSV 导出 ====================

var csvFields = []string{"日期", "时间", "类型", "用户", "目标用户", "IP", "端口", "方式",
	"无效用户", "命令", "进程号", "原始行"}

// exportCSV 导出事件级明细 CSV（UTF-8 无 BOM，事件流式写出）。
func exportCSV(sources []source, outfile string) {
	f, err := os.Create(outfile)
	if err != nil {
		fmt.Println(cRed(fmt.Sprintf("写入 CSV 文件时发生错误: %v", err)))
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.UseCRLF = true
	w.Write(csvFields)
	iterAllEvents(sources, func(e *Event) {
		port := ""
		if e.Port > 0 {
			port = strconv.Itoa(e.Port)
		}
		invalid := "否"
		if e.Invalid {
			invalid = "是"
		}
		w.Write([]string{
			e.Date, e.TimeStr, typeLabel[e.Type],
			e.User, e.Target, e.IP, port, e.Method, invalid,
			e.Command, e.PID, e.Raw,
		})
	})
	w.Flush()
	fmt.Println(cGreen(fmt.Sprintf("CSV 事件导出已完成: %s", outfile)))
}
