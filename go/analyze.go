package main

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

type netipPrefix = netip.Prefix

type source struct {
	Path  string
	Label string
}

// ==================== 聚合结果 ====================

type Profile struct {
	IP       string
	Failed   int
	Accepted int
	Invalid  int
	Users    *ocounter
	Ports    map[int]bool
	First    time.Time
	Last     time.Time
}

type ipCnt struct {
	ip string
	n  int
}

type suspectHit struct {
	IP, User    string
	Time        time.Time
	Date        string
	TimeStr     string
	WindowFails int
	Method      string
}

type groupAddHit struct {
	Group string
	Time  time.Time
}

type backdoor struct {
	User    string
	UID     int
	Created time.Time
	Groups  []groupAddHit
	UID0    bool
}

type newuserHit struct {
	User    string
	UID     int
	HasUID  bool
	Created time.Time
	Login   time.Time
	IP      string
	Delta   time.Duration
}

type concurHit struct {
	User         string
	IP1          string
	Time1        time.Time
	IP2          string
	Time2        time.Time
	Delta        time.Duration
}

type session struct {
	PID      string
	User     string
	Open     time.Time
	Close    time.Time
	HasClose bool
	Duration time.Duration
	HasDur   bool
	Long     bool
}

type srcCount struct {
	label string
	count int
}

type analysis struct {
	profiles   []*Profile // 按首次出现顺序保持插入序
	profileMap map[string]*Profile

	bruteIPs      []ipCnt
	suspected     []suspectHit
	sessions      []session
	backdoors     []backdoor
	blacklistHits []string
	lanHits       []ipCnt
	rootLogins    []*Event
	concurrent    []concurHit
	offHours      []*Event
	newUserLogin  []newuserHit
	privilege     map[string][]*Event
	accepted      []*Event
	eventCounts   map[string]int
	dateIPStats   map[dateIPKey]*dateIPStat // 按日期聚合各来源 IP 的登录行为（日期画像显示用）
	dateIPOrder   []dateIPKey               // 首次出现序
	failByDate    map[string]*ocounter      // 按日期统计各来源 IP 失败次数（报告用）
	perSource     []srcCount
	spanFirst     time.Time
	spanLast      time.Time
	hasSpan       bool
}

func (a *analysis) totalEvents() int {
	n := 0
	for _, c := range a.eventCounts {
		n += c
	}
	return n
}

// sortedProfiles 按失败次数降序（稳定，同频次保持插入序）。
func (a *analysis) sortedProfiles() []*Profile {
	out := make([]*Profile, len(a.profiles))
	copy(out, a.profiles)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Failed > out[j].Failed })
	return out
}

// ==================== 黑名单 ====================

// loadBlacklist 加载本地 IP 黑名单，每行一个 IP 或 CIDR，非法行警告并跳过。
func loadBlacklist(path string) ([]netipPrefix, error) {
	var nets []netipPrefix
	lines, err := readLinesFile(path)
	if err != nil {
		return nil, err
	}
	for no, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		s = strings.TrimPrefix(s, "\uFEFF")
		if strings.Contains(s, "/") {
			if p, err := netip.ParsePrefix(s); err == nil {
				nets = append(nets, p)
				continue
			}
		} else if addr, err := netip.ParseAddr(s); err == nil {
			nets = append(nets, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		fmt.Println(fmt.Sprintf("警告: 黑名单第 %d 行无法解析，已跳过: %s", no+1, s))
	}
	return nets, nil
}

func ipInBlacklist(ip string, nets []netipPrefix) bool {
	if len(nets) == 0 || ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// ==================== 主聚合 ====================

// analyzeSources 流式单遍聚合：逐事件统计，不在内存保留失败类与会话事件。
func analyzeSources(sources []source, threshold, window int, blacklistNets []netipPrefix) *analysis {
	a := &analysis{
		profileMap:  map[string]*Profile{},
		privilege:   map[string][]*Event{},
		eventCounts: map[string]int{},
		dateIPStats: map[dateIPKey]*dateIPStat{},
		failByDate:  map[string]*ocounter{},
	}
	for _, t := range privTypes {
		a.privilege[t] = nil
	}

	prof := func(ip string) *Profile {
		if p, ok := a.profileMap[ip]; ok {
			return p
		}
		p := &Profile{IP: ip, Users: newOcounter(), Ports: map[int]bool{}}
		a.profileMap[ip] = p
		a.profiles = append(a.profiles, p)
		return p
	}

	failTimes := map[string][]int64{}
	openByPid := map[string]pidOpen{}
	closeByPid := map[string]time.Time{}
	var pidOrder []string
	newUsers := map[string]newuserRaw{}
	var newUserOrder []string
	groupAdds := map[string][]groupAddHit{}

	for _, src := range sources {
		cnt := 0
		var mtime time.Time
		if st, err := os.Stat(src.Path); err == nil {
			mtime = st.ModTime()
		}
		eachTextEvent(src.Path, mtime, func(ev *Event) {
			cnt++
			t := ev.Type
			a.eventCounts[t]++
			if !a.hasSpan || ev.Time.Before(a.spanFirst) {
				a.spanFirst = ev.Time
			}
			if !a.hasSpan || ev.Time.After(a.spanLast) {
				a.spanLast = ev.Time
			}
			a.hasSpan = true

			// 按日聚合各来源 IP 的登录尝试：成功/失败/无效计数、用户名、首末时刻
			if (t == "accepted" || failClass[t]) && ev.IP != "" {
				k := dateIPKey{date: ev.Date, ip: ev.IP}
				ds, ok := a.dateIPStats[k]
				if !ok {
					ds = &dateIPStat{IP: ev.IP, Users: newOcounter()}
					a.dateIPStats[k] = ds
					a.dateIPOrder = append(a.dateIPOrder, k)
				}
				if t == "accepted" {
					ds.Accepted++
				} else {
					ds.Failed++
					if t == "invalid_user" {
						ds.Invalid++
					}
				}
				if ev.User != "" {
					ds.Users.add(ev.User)
				}
				if ds.First.IsZero() || ev.Time.Before(ds.First) {
					ds.First = ev.Time
				}
				if ds.Last.IsZero() || ev.Time.After(ds.Last) {
					ds.Last = ev.Time
				}
			}

			if t == "accepted" {
				a.accepted = append(a.accepted, ev)
			} else if privTypesSet[t] {
				a.privilege[t] = append(a.privilege[t], ev)
			} else if t == "useradd_new" {
				if _, ok := newUsers[ev.User]; !ok {
					newUsers[ev.User] = newuserRaw{ev: ev}
					newUserOrder = append(newUserOrder, ev.User)
				}
			} else if t == "group_add" {
				if privGroups[ev.Group] {
					groupAdds[ev.User] = append(groupAdds[ev.User], groupAddHit{Group: ev.Group, Time: ev.Time})
				}
				return
			} else if t == "session_open" {
				if _, ok := openByPid[ev.PID]; !ok {
					openByPid[ev.PID] = pidOpen{user: ev.User, t: ev.Time}
					pidOrder = append(pidOrder, ev.PID)
				}
				return
			} else if t == "session_close" {
				if _, ok := closeByPid[ev.PID]; !ok {
					closeByPid[ev.PID] = ev.Time
				}
				return
			}

			if failClass[t] && ev.IP != "" {
				failTimes[ev.IP] = append(failTimes[ev.IP], ev.Time.Unix())
				oc, ok := a.failByDate[ev.Date]
				if !ok {
					oc = newOcounter()
					a.failByDate[ev.Date] = oc
				}
				oc.add(ev.IP)
			}

			ip := ev.IP
			if ip == "" {
				return
			}
			p := prof(ip)
			if failClass[t] {
				p.Failed++
				if t == "invalid_user" {
					p.Invalid++
				}
			} else if t == "accepted" {
				p.Accepted++
			}
			if ev.User != "" {
				p.Users.add(ev.User)
			}
			if ev.Port > 0 {
				p.Ports[ev.Port] = true
			}
			if p.First.IsZero() || ev.Time.Before(p.First) {
				p.First = ev.Time
			}
			if p.Last.IsZero() || ev.Time.After(p.Last) {
				p.Last = ev.Time
			}
		})
		a.perSource = append(a.perSource, srcCount{label: src.Label, count: cnt})
	}

	for _, times := range failTimes {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	}

	// 暴力破解 IP：失败类合计超过阈值
	for _, p := range a.profiles {
		if p.Failed > threshold {
			a.bruteIPs = append(a.bruteIPs, ipCnt{p.IP, p.Failed})
		}
	}
	sort.SliceStable(a.bruteIPs, func(i, j int) bool { return a.bruteIPs[i].n > a.bruteIPs[j].n })

	// 内网攻击：私网来源（10/8、172.16/12、192.168/16）且存在失败类事件，
	// 提示失陷内网主机横向移动或本机误操作，按失败次数降序
	for _, p := range a.profiles {
		if addr, err := netip.ParseAddr(p.IP); err == nil && addr.IsPrivate() && p.Failed > 0 {
			a.lanHits = append(a.lanHits, ipCnt{p.IP, p.Failed})
		}
	}
	sort.SliceStable(a.lanHits, func(i, j int) bool { return a.lanHits[i].n > a.lanHits[j].n })

	// 时间窗关联：成功登录前 window 分钟内同 IP 失败达到阈值，判定疑似暴力破解成功
	win := int64(window) * 60
	for _, ev := range a.accepted {
		times := failTimes[ev.IP]
		if len(times) == 0 {
			continue
		}
		at := ev.Time.Unix()
		lo := sort.Search(len(times), func(i int) bool { return times[i] >= at-win })
		hi := sort.Search(len(times), func(i int) bool { return times[i] >= at })
		if hi-lo >= threshold {
			a.suspected = append(a.suspected, suspectHit{
				IP: ev.IP, User: ev.User, Time: ev.Time,
				Date: ev.Date, TimeStr: ev.TimeStr,
				WindowFails: hi - lo, Method: ev.Method,
			})
		}
	}

	// 会话配对：同一 sshd-session 进程号内 opened 与 closed 配对
	for _, pid := range pidOrder {
		o := openByPid[pid]
		s := session{PID: pid, User: o.user, Open: o.t}
		if c, ok := closeByPid[pid]; ok {
			s.Close = c
			s.HasClose = true
			s.Duration = c.Sub(o.t)
			s.HasDur = true
			s.Long = s.Duration > 24*time.Hour
		}
		a.sessions = append(a.sessions, s)
	}
	sort.SliceStable(a.sessions, func(i, j int) bool { return a.sessions[i].Open.Before(a.sessions[j].Open) })

	// useradd 后门检测：UID 0 或加入特权组
	for _, name := range newUserOrder {
		nu := newUsers[name]
		priv := groupAdds[name]
		uid0 := nu.ev.HasUID && nu.ev.UID == 0
		if uid0 || len(priv) > 0 {
			bd := backdoor{
				User: name, UID: nu.ev.UID, Created: nu.ev.Time,
				Groups: priv, UID0: uid0,
			}
			a.backdoors = append(a.backdoors, bd)
		}
	}
	sort.SliceStable(a.backdoors, func(i, j int) bool { return a.backdoors[i].Created.Before(a.backdoors[j].Created) })

	// 黑名单命中
	var hitProfiles []*Profile
	for _, p := range a.profiles {
		if ipInBlacklist(p.IP, blacklistNets) {
			hitProfiles = append(hitProfiles, p)
		}
	}
	sort.SliceStable(hitProfiles, func(i, j int) bool { return hitProfiles[i].Failed > hitProfiles[j].Failed })
	for _, p := range hitProfiles {
		a.blacklistHits = append(a.blacklistHits, p.IP)
	}

	// root 直接登录
	for _, e := range a.accepted {
		if e.User == "root" {
			a.rootLogins = append(a.rootLogins, e)
		}
	}

	// 同一账户短时多 IP 登录
	accByUser := map[string][]*Event{}
	var accUserOrder []string
	for _, e := range a.accepted {
		if e.User == "" {
			continue
		}
		if _, seen := accByUser[e.User]; !seen {
			accUserOrder = append(accUserOrder, e.User)
		}
		accByUser[e.User] = append(accByUser[e.User], e)
	}
	for _, user := range accUserOrder {
		evs := accByUser[user]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
		for i := 0; i+1 < len(evs); i++ {
			x, y := evs[i], evs[i+1]
			if x.IP != "" && y.IP != "" && x.IP != y.IP && y.Time.Sub(x.Time) <= concurrentMinutes*time.Minute {
				a.concurrent = append(a.concurrent, concurHit{
					User: user, IP1: x.IP, Time1: x.Time,
					IP2: y.IP, Time2: y.Time, Delta: y.Time.Sub(x.Time),
				})
			}
		}
	}

	// 非工作时段成功登录
	for _, e := range a.accepted {
		if int(e.Time.Hour()) >= offHoursStart && int(e.Time.Hour()) < offHoursEnd {
			a.offHours = append(a.offHours, e)
		}
	}

	// 新建账户与其后首次成功登录的关联
	firstLogin := map[string]*Event{}
	for _, e := range a.accepted {
		if e.User == "" {
			continue
		}
		if cur, ok := firstLogin[e.User]; !ok || e.Time.Before(cur.Time) {
			firstLogin[e.User] = e
		}
	}
	for _, name := range newUserOrder {
		nu := newUsers[name]
		fl, ok := firstLogin[name]
		if !ok {
			continue
		}
		if !fl.Time.Before(nu.ev.Time) && fl.Time.Sub(nu.ev.Time) <= newUserLoginDays*24*time.Hour {
			a.newUserLogin = append(a.newUserLogin, newuserHit{
				User: name, UID: nu.ev.UID, HasUID: nu.ev.HasUID,
				Created: nu.ev.Time, Login: fl.Time, IP: fl.IP,
				Delta: fl.Time.Sub(nu.ev.Time),
			})
		}
	}
	sort.SliceStable(a.newUserLogin, func(i, j int) bool { return a.newUserLogin[i].Created.Before(a.newUserLogin[j].Created) })

	return a
}

// dateIPKey 日期画像的聚合键：某日的某个来源 IP。
type dateIPKey struct {
	date string
	ip   string
}

// dateIPStat 某日某来源 IP 的登录行为统计。
type dateIPStat struct {
	IP       string
	Failed   int
	Accepted int
	Invalid  int
	Users    *ocounter
	First    time.Time
	Last     time.Time
}

type pidOpen struct {
	user string
	t    time.Time
}

type newuserRaw struct {
	ev *Event
}

// methodClasses 按认证方式归类计数，keyboard-interactive 前缀归入 PAM 类。
func methodClasses(events []*Event) *ocounter {
	c := newOcounter()
	for _, ev := range events {
		m := ev.Method
		if strings.HasPrefix(m, "keyboard-interactive") {
			c.add("keyboard-interactive/PAM")
		} else if m != "" {
			c.add(m)
		}
	}
	return c
}
