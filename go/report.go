package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ==================== 文本报告 ====================

// renderReportTxt 生成文本版综合审计报告（基于流式聚合结果，不依赖事件列表）。
func renderReportTxt(a *analysis, opts *options, outfile string, binary *binaryStats, threshold, window int) error {
	lines := []string{}
	add := func(s string) { lines = append(lines, s) }

	counts := a.eventCounts
	failTotal := sumFailClass(counts)
	add("==================== SSH 访问审计报告 ====================")
	add(fmt.Sprintf("日志文件: %s", opts.logfile))
	if a.hasSpan {
		add(fmt.Sprintf("时间跨度: %s ~ %s", fmtDT(a.spanFirst), fmtDT(a.spanLast)))
	}
	add(fmt.Sprintf("生成时间: %s", time.Now().Format("2006-01-02 15:04:05")))
	add("")

	add("一、总体结论")
	if len(a.bruteIPs) > 0 {
		parts := make([]string, 0, len(a.bruteIPs))
		for _, b := range a.bruteIPs {
			parts = append(parts, fmt.Sprintf("%s（%d次）", b.ip, b.n))
		}
		add(fmt.Sprintf("存在暴力破解行为的 IP（失败 > %d 次）共 %d 个：%s", threshold, len(a.bruteIPs), strings.Join(parts, "，")))
	} else {
		add(fmt.Sprintf("存在暴力破解行为的 IP（失败 > %d 次）：无", threshold))
	}

	if len(a.suspected) > 0 {
		add("疑似暴力破解成功的 IP（时间窗关联）：")
		for _, h := range a.suspected {
			add(fmt.Sprintf("  [%s %s] 用户 %s 经 %s 成功登录，此前 %d 分钟内该 IP 失败 %d 次",
				h.Date, h.TimeStr, h.User, h.Method, window, h.WindowFails))
		}
	} else {
		add("疑似暴力破解成功的 IP（时间窗关联）：无")
	}

	if len(a.backdoors) > 0 {
		add("疑似后门账户：")
		for _, b := range a.backdoors {
			gparts := make([]string, 0, len(b.Groups))
			for _, g := range b.Groups {
				gparts = append(gparts, fmt.Sprintf("%s（%s）", g.Group, fmtDT(g.Time)))
			}
			reason := fmt.Sprintf("加入特权组 %s", strings.Join(gparts, "、"))
			if b.UID0 {
				reason = "UID 为 0，root 级后门"
			}
			add(fmt.Sprintf("  %s（UID %d）创建于 %s，%s", b.User, b.UID, fmtDT(b.Created), reason))
		}
	} else {
		add("疑似后门账户：无")
	}

	if len(a.newUserLogin) > 0 {
		add("新建账户快速登录：")
		for _, x := range a.newUserLogin {
			add(fmt.Sprintf("  %s（UID %d）创建于 %s，%s后从 %s 首次登录",
				x.User, x.UID, fmtDT(x.Created), fmtDuration(x.Delta), x.IP))
		}
	} else {
		add("新建账户快速登录：无")
	}

	if len(a.rootLogins) > 0 {
		ips := newOcounter()
		for _, e := range a.rootLogins {
			if e.IP != "" {
				ips.add(e.IP)
			}
		}
		var parts []string
		for _, p := range ips.mostCommon(-1) {
			parts = append(parts, fmt.Sprintf("%s（%d次）", p.k, p.n))
		}
		add(fmt.Sprintf("root 账户通过 SSH 直接登录 %d 次，来源 %d 个 IP：%s", len(a.rootLogins), ips.length(), strings.Join(parts, "，")))
	} else {
		add("root 账户直接登录：无")
	}

	if len(a.concurrent) > 0 {
		add(fmt.Sprintf("同账户短时多 IP 登录（%d 分钟内不同来源）：", concurrentMinutes))
		for _, x := range a.concurrent {
			add(fmt.Sprintf("  %s：%s 来自 %s，%s 来自 %s",
				x.User, fmtDT(x.Time1), x.IP1, fmtDT(x.Time2), x.IP2))
		}
	} else {
		add("同账户短时多 IP 登录：无")
	}

	if len(a.offHours) > 0 {
		add(fmt.Sprintf("非工作时段（%02d:00～%02d:59）成功登录 %d 条：", offHoursStart, offHoursEnd-1, len(a.offHours)))
		for _, e := range a.offHours {
			add(fmt.Sprintf("  [%s] %s %s（%s）", fmtDT(e.Time), e.IP, e.User, e.Method))
		}
	} else {
		add(fmt.Sprintf("非工作时段（%02d:00～%02d:59）成功登录：无", offHoursStart, offHoursEnd-1))
	}

	priv := a.privilege
	nSudo, nSudoSess := len(priv["sudo_cmd"]), len(priv["sudo_session"])
	nDeny, nSuSess, nSuDeny := len(priv["sudo_deny"]), len(priv["su_session"]), len(priv["su_deny"])
	add(fmt.Sprintf("提权事件：sudo 提权 %d 条，sudo 会话 %d 条，sudo 认证失败 %d 条，su 会话 %d 条，su 认证失败 %d 条",
		nSudo, nSudoSess, nDeny, nSuSess, nSuDeny))
	for _, e := range priv["sudo_cmd"] {
		add(fmt.Sprintf("  sudo [%s] %s → %s 执行 %s", fmtDT(e.Time), e.User, e.Target, e.Command))
	}
	for _, e := range append(append([]*Event{}, priv["sudo_deny"]...), priv["su_deny"]...) {
		tgt := ""
		if e.Target != "" {
			tgt = " → " + e.Target
		}
		add(fmt.Sprintf("  认证失败 [%s] %s%s", fmtDT(e.Time), e.User, tgt))
	}

	bh := "无"
	if len(a.blacklistHits) > 0 {
		bh = strings.Join(a.blacklistHits, "，")
	}
	add(fmt.Sprintf("黑名单命中：%s", bh))

	if len(a.lanHits) > 0 {
		add(fmt.Sprintf("内网攻击（私网来源且存在失败）：共 %d 个 IP，按失败次数降序", len(a.lanHits)))
		for _, h := range a.lanHits {
			p := a.profileMap[h.ip]
			add(fmt.Sprintf("  %s：失败 %d，成功 %d，尝试用户名 %s", h.ip, p.Failed, p.Accepted, usernamesFull(p.Users)))
		}
	} else {
		add("内网攻击（私网来源且存在失败）：无")
	}
	add("")

	add("二、IP 画像（按失败次数降序）")
	sorted := a.sortedProfiles()
	if len(sorted) > 0 {
		ipW := dispWidth("IP")
		failW, accW, invW := dispWidth("失败"), dispWidth("成功"), dispWidth("无效用户")
		for _, p := range sorted {
			if len(p.IP) > ipW {
				ipW = len(p.IP)
			}
			if w := numWidth(p.Failed); w > failW {
				failW = w
			}
			if w := numWidth(p.Accepted); w > accW {
				accW = w
			}
			if w := numWidth(p.Invalid); w > invW {
				invW = w
			}
		}
		const dtW = 19 // "2006-01-02 15:04:05" 的显示宽度
		add(tableRow([]string{
			padWidth("IP", ipW),
			padLeftWidth("失败", failW), padLeftWidth("成功", accW), padLeftWidth("无效用户", invW),
			padWidth("首次出现", dtW), padWidth("末次出现", dtW), "尝试用户名",
		}))
		for _, p := range sorted {
			add(tableRow([]string{
				padWidth(p.IP, ipW),
				padLeftWidth(strconv.Itoa(p.Failed), failW),
				padLeftWidth(strconv.Itoa(p.Accepted), accW),
				padLeftWidth(strconv.Itoa(p.Invalid), invW),
				padWidth(fmtDT(p.First), dtW), padWidth(fmtDT(p.Last), dtW), usernamesFull(p.Users),
			}))
		}
	} else {
		add("无")
	}
	add("")

	add("三、按日时间线")
	accByDate := map[string][]*Event{}
	var accDateSeen []string
	accDateSet := map[string]bool{}
	for _, e := range a.accepted {
		if !accDateSet[e.Date] {
			accDateSet[e.Date] = true
			accDateSeen = append(accDateSeen, e.Date)
		}
		accByDate[e.Date] = append(accByDate[e.Date], e)
	}
	sessionsByDate := map[string][]session{}
	sessDateSet := map[string]bool{}
	var sessDateSeen []string
	for _, s := range a.sessions {
		if s.Open.IsZero() {
			continue
		}
		d := s.Open.Format("2006-01-02")
		if !sessDateSet[d] {
			sessDateSet[d] = true
			sessDateSeen = append(sessDateSeen, d)
		}
		sessionsByDate[d] = append(sessionsByDate[d], s)
	}
	dateSet := map[string]bool{}
	for d := range accDateSet {
		dateSet[d] = true
	}
	for d := range a.failByDate {
		dateSet[d] = true
	}
	for d := range sessDateSet {
		dateSet[d] = true
	}
	allDates := make([]string, 0, len(dateSet))
	for d := range dateSet {
		allDates = append(allDates, d)
	}
	sort.Strings(allDates)
	if len(allDates) == 0 {
		add("无")
	}
	for _, d := range allDates {
		add(d)
		add("登录成功的记录")
		if evs, ok := accByDate[d]; ok {
			for _, e := range evs {
				add(fmt.Sprintf("[%s] %s %s（%s）", e.TimeStr, e.IP, e.User, e.Method))
			}
		} else {
			add("无")
		}
		add("登录失败的记录")
		if oc, ok := a.failByDate[d]; ok {
			for _, p := range oc.mostCommon(-1) {
				add(fmt.Sprintf("%s - %d 次", p.k, p.n))
			}
		} else {
			add("无")
		}
		if ss, ok := sessionsByDate[d]; ok {
			add("会话记录")
			for _, s := range ss {
				if s.HasClose {
					mark := ""
					if s.Long {
						mark = "（超过 24 小时，注意）"
					}
					add(fmt.Sprintf("[%s ~ %s] %s（时长 %s）%s",
						s.Open.Format("15:04:05"), s.Close.Format("15:04:05"), s.User, fmtDuration(s.Duration), mark))
				} else {
					add(fmt.Sprintf("[%s 开启] %s（未正常关闭）", s.Open.Format("15:04:05"), s.User))
				}
			}
		}
		add("")
	}

	add("四、二进制日志摘要")
	if len(binary.Btmp) > 0 {
		for _, b := range binary.Btmp {
			line := fmt.Sprintf("btmp（%s）：失败记录 %d 条", filepath.Base(b.File), b.Fails)
			if b.Fails > 0 {
				line += fmt.Sprintf("，时间跨度 %s ~ %s", fmtDT(b.First), fmtDT(b.Last))
			}
			add(line)
			for _, p := range b.Hosts.mostCommon(-1) {
				add(fmt.Sprintf("  %s - %d 次", p.k, p.n))
			}
			if b.Users.length() > 0 {
				var us []string
				for _, p := range b.Users.mostCommon(-1) {
					us = append(us, fmt.Sprintf("%s(%d)", p.k, p.n))
				}
				add("  尝试用户名：" + strings.Join(us, "、"))
			}
		}
	} else {
		add("btmp：未采集")
	}
	if len(binary.Wtmp) > 0 {
		for _, w := range binary.Wtmp {
			add(fmt.Sprintf("wtmp（%s）：登录会话 %d 次，系统启动 %d 次", filepath.Base(w.File), len(w.Sessions), w.Boots))
			for _, s := range w.Sessions {
				if s.HasClose {
					add(fmt.Sprintf("  [%s] %s %s 来自 %s，时长 %s",
						fmtDT(s.Open), s.User, s.Line, orEmpty(s.Host, "-"), fmtDuration(s.Duration)))
				} else {
					note := s.Note
					if note == "" {
						note = "未正常关闭"
					}
					add(fmt.Sprintf("  [%s] %s %s 来自 %s（%s）",
						fmtDT(s.Open), s.User, s.Line, orEmpty(s.Host, "-"), note))
				}
			}
		}
	} else {
		add("wtmp：未采集")
	}
	if len(binary.Lastlog) > 0 {
		for _, ll := range binary.Lastlog {
			entries := make([]lastlogEntry, len(ll.Entries))
			copy(entries, ll.Entries)
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
			var shown []lastlogEntry
			for _, e := range entries {
				if e.UID == 0 || e.UID >= 1000 {
					shown = append(shown, e)
				}
			}
			add(fmt.Sprintf("lastlog（%s）：有效登录记录 %d 条", filepath.Base(ll.File), len(shown)))
			for _, e := range shown {
				add(fmt.Sprintf("  %s（UID %d）末次登录 %s %s 来自 %s",
					e.Name, e.UID, fmtDT(e.Time), orEmpty(e.Line, "-"), orEmpty(e.Host, "-")))
			}
		}
	} else {
		add("lastlog：未采集")
	}
	add("")

	add("五、统计与判定规则")
	add(fmt.Sprintf("- 失败统计包含认证失败、无效用户、认证超限、认证中断四类，合计 %d 条", failTotal))
	add("- 无用户的认证中断（Connection closed by IP [preauth] 一类）计入失败，用户名记为未知")
	add("- 认证中断类事件计入失败统计，并保留在本报告与 JSON、CSV 导出明细中")
	add(fmt.Sprintf("- 暴力破解判定阈值: 失败次数 > %d（--threshold 可调）", threshold))
	add(fmt.Sprintf("- 疑似暴力破解成功关联窗口: 成功登录前 %d 分钟内失败达到阈值（--window 可调）", window))
	add(fmt.Sprintf("- 同账户短时多 IP 判定: 相邻两次成功登录来自不同 IP 且间隔 <= %d 分钟", concurrentMinutes))
	add(fmt.Sprintf("- 非工作时段: %02d:00～%02d:59 的成功登录", offHoursStart, offHoursEnd-1))
	add(fmt.Sprintf("- 新建账户关联: useradd 后 %d 天内的首次成功登录", newUserLoginDays))
	add("- btmp/wtmp/lastlog 独立统计，不并入文本日志事件，避免重复计数")
	add(fmt.Sprintf("- journald 提取仅在未选中文本日志时触发，统计最近 %d 天", journalDays))
	add("- 无年份日志按文件修改时间推断年份（月份差 >= 6 视为跨年），跨年场景请人工复核")
	add("- 屏幕输出为摘要视图（省略处有标注），本报告与 JSON、CSV 导出保留完整明细")

	if err := os.WriteFile(outfile, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return err
	}
	fmt.Println(cGreen(fmt.Sprintf("综合排查报告已成功生成至: %s", outfile)))
	return nil
}

// ==================== HTML 报告 ====================

const htmlCSS = `
html{scroll-behavior:smooth}
body{font-family:"Microsoft YaHei",system-ui,sans-serif;margin:0;
color:#1f2933;background:#f5f6f7}
h1{font-size:22px}
h2{font-size:17px;border-left:4px solid #2563eb;padding-left:9px;margin-top:30px;scroll-margin-top:16px}
h2:target{background:#eff6ff}
h3{font-size:15px;margin:18px 0 6px}
.layout{display:flex;gap:24px;align-items:flex-start;max-width:1560px;margin:24px auto;padding:0 16px}
.toc{width:185px;flex-shrink:0;position:sticky;top:24px;max-height:calc(100vh - 48px);overflow-y:auto;
padding:14px 0 8px;font-size:13px;scrollbar-width:thin;scrollbar-color:#c7cdd4 transparent}
.toc::-webkit-scrollbar{width:6px}
.toc::-webkit-scrollbar-thumb{background:#d3d8de;border-radius:3px}
.toc::-webkit-scrollbar-thumb:hover{background:#b9c0c9}
.toc-t{color:#6b7280;font-weight:700;margin:0 0 8px 2px;cursor:pointer}
.toc-t:hover{color:#2563eb}
.toc a{display:block;margin:2px 0;padding:4px 10px;border-radius:6px;color:#374151;
text-decoration:none;border-left:3px solid transparent}
.toc a:hover{background:#eef2f7;color:#2563eb}
.toc a.active{background:#eff6ff;color:#2563eb;border-left-color:#2563eb;font-weight:700}
.toc a.toc-sub{padding:2px 10px 2px 28px;font-size:12px;color:#6b7280;border-left:none}
.toc a.toc-sub:hover{color:#2563eb}
main{flex:1;min-width:0}
@media(max-width:960px){.layout{display:block}.toc{position:static;max-height:none;width:auto;padding:10px 0}
.toc a{display:inline-block;margin:2px 6px 2px 0;border-left:none;border-radius:12px;background:#eef2f7}
.toc a.active{background:#dbeafe}}
@media print{.toc{display:none}.layout{display:block}}
.card{display:inline-block;background:#fff;border-radius:8px;padding:14px 22px;margin:6px 9px 6px 0;
box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:130px;vertical-align:top}
a.card{text-decoration:none;color:inherit;transition:box-shadow .15s}
a.card:hover{box-shadow:0 3px 9px rgba(0,0,0,.16)}
.card .num{font-size:26px;font-weight:700}.card .lbl{font-size:13px;color:#6b7280}
.badge{display:inline-block;border-radius:4px;padding:1px 8px;font-size:12px;color:#fff;white-space:nowrap}
.b-green{background:#16a34a}.b-red{background:#dc2626}.b-amber{background:#d97706}
.b-gray{background:#6b7280}.b-cyan{background:#0891b2}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin-top:9px;
box-shadow:0 1px 2px rgba(15,23,42,.06),0 4px 12px rgba(15,23,42,.07),0 12px 28px rgba(15,23,42,.08)}
th,td{border:1px solid #e5e7eb;padding:5px 9px;text-align:left}
th{background:#f3f4f6}
.bar-row{display:flex;align-items:center;margin:5px 0}
.bar-label{width:150px;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;background:#eef1f4;border-radius:4px}
.bar-fill{height:16px;background:#dc2626;border-radius:4px;min-width:3px}
.bar-num{width:80px;text-align:right;font-size:13px}
.panel{background:#fff;border-radius:8px;padding:12px 16px;
box-shadow:0 1px 2px rgba(15,23,42,.07),0 6px 16px rgba(15,23,42,.09),0 16px 36px rgba(15,23,42,.1)}
.high{color:#dc2626;font-weight:700}.amber{color:#d97706;font-weight:700}
.green{color:#16a34a;font-weight:700}
.meta{color:#6b7280;font-size:13px}ul.notes{font-size:13px;color:#4b5563}
code{background:#eef1f4;padding:1px 5px;border-radius:3px;font-size:12px}
.toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0 2px}
.tlbl{font-size:13px;color:#6b7280;font-weight:700}
.tsel,.tinput{font-family:inherit;font-size:13px;padding:5px 9px;border:1px solid #d1d5db;
border-radius:6px;background:#fff;color:#1f2933}
.tsel:focus,.tinput:focus{outline:none;border-color:#2563eb}
.tcustom{font-size:13px;color:#4b5563}.tcustom[hidden]{display:none}
.tdt{width:152px;cursor:pointer}
.tbtn{font-family:inherit;font-size:13px;padding:4px 16px;border:none;border-radius:6px;
background:#2563eb;color:#fff;cursor:pointer;box-shadow:0 1px 2px rgba(37,99,235,.35)}
.tbtn:hover{background:#1d4ed8;box-shadow:0 2px 6px rgba(37,99,235,.45)}
.tpick{position:fixed;z-index:60;background:#fff;border:1px solid #d1d5db;border-radius:10px;
box-shadow:0 8px 24px rgba(0,0,0,.16);padding:10px 12px;width:272px;font-size:13px;user-select:none}
.tpick[hidden]{display:none}
.tp-h{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.tp-h b{font-size:14px}
.tp-mb{border:none;background:#eef2f7;border-radius:6px;width:24px;height:24px;cursor:pointer;
color:#374151;font-size:14px;line-height:1;margin-left:4px}
.tp-mb:hover{background:#dbeafe;color:#2563eb}
.tp-wd,.tp-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:2px;text-align:center}
.tp-wd{color:#9ca3af;font-size:12px;margin-bottom:2px}
.tp-d{padding:3px 0;border-radius:6px;cursor:pointer}
.tp-d:hover{background:#eef2f7}
.tp-dim{color:#c7cdd4}
.tp-d.tp-sel{background:#2563eb;color:#fff}
.tp-d.tp-sel:hover{background:#2563eb}
.tp-tdy{box-shadow:inset 0 0 0 1px #2563eb;color:#2563eb}
.tp-d.tp-sel.tp-tdy{color:#fff;box-shadow:none}
.tp-time{display:flex;gap:6px;margin:8px 0 2px}
.tp-col{flex:1;height:132px;overflow-y:auto;border:1px solid #e5e7eb;border-radius:6px;
text-align:center;position:relative;scrollbar-width:thin}
.tp-col::-webkit-scrollbar{width:4px}
.tp-tv{display:block;padding:2px 0;cursor:pointer}
.tp-tv:hover{background:#eef2f7}
.tp-tv.tp-sel{background:#2563eb;color:#fff}
.tp-ft{display:flex;align-items:center;gap:8px;margin-top:8px;padding-top:8px;border-top:1px solid #f0f1f3}
.tp-link{border:none;background:none;color:#2563eb;cursor:pointer;font-size:13px;
padding:4px 8px;border-radius:6px;font-family:inherit}
.tp-link:hover{background:#eff6ff}
.tp-gray{color:#6b7280;margin-left:auto}
.tp-gray:hover{background:#f3f4f6;color:#374151}
.tfnote{font-size:12px;color:#6b7280}
.hidden{display:none}.toc a.hidden{display:none}
@media print{.toolbar{display:none}.panel,table{box-shadow:none}}
`

// htmlEscPy HTML 转义：& < > 与单双引号均转义，转义表与 html.escape 一致。
func htmlEscPy(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#x27;",
	)
	return r.Replace(s)
}

// tAttr 行级时间筛选属性：data-t 记录该行完整时间（YYYY-MM-DD HH:MM:SS），
// 供报告内时间范围筛选比较到时分秒；零值时间（如从未登录的账户）不加属性，
// 任何范围下都显示。
func tAttr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf(" data-t=\"%s\"", t.Format("2006-01-02 15:04:05"))
}

// renderReportHTML 生成单文件 HTML 报告，内嵌 CSS，无外部依赖，离线可打开。
func renderReportHTML(a *analysis, opts *options, outfile string, binary *binaryStats,
	threshold, window int, dormant map[string]bool) error {

	esc := htmlEscPy
	counts := a.eventCounts
	failTotal := sumFailClass(counts)
	parts := []string{}
	add := func(s string) { parts = append(parts, s) }

	add("<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"utf-8\">")
	add("<title>SSH 访问审计报告</title>")
	add(fmt.Sprintf("<style>%s</style></head><body>", htmlCSS))
	add("<div class=\"layout\">")

	nBrute := len(a.bruteIPs)
	nHigh := len(a.suspected)
	priv := a.privilege
	privRows := append(append(append(append(append([]*Event{}, priv["sudo_cmd"]...), priv["sudo_session"]...), priv["sudo_deny"]...), priv["su_session"]...), priv["su_deny"]...)
	hasBinary := len(binary.Btmp) > 0 || len(binary.Wtmp) > 0 || len(binary.Lastlog) > 0

	// 小节清单：按应急查看优先级排序（失陷信号在前，攻击面与明细在后），
	// 只收录实际会渲染的小节，目录与标题共用同一份名称
	type sec struct{ id, title string }
	secList := []sec{}
	if len(a.suspected) > 0 {
		secList = append(secList, sec{"s-high", "高危：疑似暴力破解成功"})
	}
	if len(a.lanHits) > 0 {
		secList = append(secList, sec{"s-lan", "内网攻击"})
	}
	if len(a.blacklistHits) > 0 {
		secList = append(secList, sec{"s-blacklist", "黑名单命中"})
	}
	if len(a.backdoors) > 0 {
		secList = append(secList, sec{"s-backdoor", "疑似后门账户"})
	}
	if len(a.newUserLogin) > 0 {
		secList = append(secList, sec{"s-newuser", "新建账户快速登录"})
	}
	if len(a.rootLogins) > 0 {
		secList = append(secList, sec{"s-root", "root 账户直接登录"})
	}
	if len(a.concurrent) > 0 {
		secList = append(secList, sec{"s-concurrent", "同账户短时多 IP 登录"})
	}
	if len(privRows) > 0 {
		secList = append(secList, sec{"s-priv", "提权事件"})
	}
	if len(a.offHours) > 0 {
		secList = append(secList, sec{"s-offhours", "非工作时段成功登录"})
	}
	if len(a.bruteIPs) > 0 {
		secList = append(secList, sec{"s-brute", "暴力破解 IP 排行"})
	}
	if len(a.accepted) > 0 {
		secList = append(secList, sec{"s-accepted", "登录成功"})
	}
	secList = append(secList,
		sec{"s-profile", "IP 画像"},
		sec{"s-daily", "按日明细"})
	if len(a.sessions) > 0 {
		secList = append(secList, sec{"s-sessions", "会话记录"})
	}
	if hasBinary {
		secList = append(secList, sec{"s-binary", "二进制日志"})
	}
	secList = append(secList, sec{"s-notes", "统计与判定规则"})
	secNo := map[string]string{}
	secTitle := map[string]string{}
	for i, s := range secList {
		secNo[s.id] = strconv.Itoa(i + 1)
		secTitle[s.id] = s.title
	}
	// 小节标题写入正文并记录当前小节；日期子标题同时登记为目录子条目，
	// id 用自增序号，避免不同小节出现同一日期时锚点冲突
	curSec := ""
	h2 := func(id string) {
		add(fmt.Sprintf("<h2 id=\"%s\">%s. %s</h2>", id, secNo[id], esc(secTitle[id])))
		curSec = id
	}
	subsBySec := map[string][]string{}
	h3n := 0
	h3d := func(text string) {
		h3n++
		id := fmt.Sprintf("h3-%d", h3n)
		add(fmt.Sprintf("<div class=\"dg\"><h3 id=\"%s\">%s</h3>", id, esc(text)))
		subsBySec[curSec] = append(subsBySec[curSec],
			fmt.Sprintf("<a class=\"toc-sub\" href=\"#%s\">%s</a>", id, esc(text)))
	}
	// h3p 独立子标题（不包日期分组），如二进制日志的文件名小节
	h3p := func(text string) {
		h3n++
		id := fmt.Sprintf("h3-%d", h3n)
		add(fmt.Sprintf("<h3 id=\"%s\">%s</h3>", id, esc(text)))
		subsBySec[curSec] = append(subsBySec[curSec],
			fmt.Sprintf("<a class=\"toc-sub\" href=\"#%s\">%s</a>", id, esc(text)))
	}

	// 侧边目录：粘性悬浮，滚动时高亮当前小节，条目名与小节标题一致；
	// 日期子条目在正文渲染时收集，此处先放占位符，写出前回填
	add("<!--TOC-->")
	add("<main>")
	add("<h1>SSH 访问审计报告</h1>")
	spanS := "无事件"
	if a.hasSpan {
		spanS = fmt.Sprintf("%s ~ %s", fmtDT(a.spanFirst), fmtDT(a.spanLast))
	}
	add(fmt.Sprintf("<p class=\"meta\">日志文件: %s　时间跨度: %s　生成时间: %s</p>",
		esc(opts.logfile), esc(spanS), esc(time.Now().Format("2006-01-02 15:04:05"))))

	// 时间范围筛选条：预设相对最近事件日（最近 N 天，整天对齐）；
	// 自定义起止由自绘弹层选择（日历 + 时分秒三列，底部「今天」「确认」在左、
	// 「清除」在右），点弹层内「确认」写入输入框并应用筛选；
	// 筛选逻辑在页面底部的脚本里，按 data-t 属性显隐明细，仪表卡片同步汇总
	add(`<div class="toolbar"><span class="tlbl">时间范围</span><select id="tsel" class="tsel">` +
		`<option value="all">全部时间</option>` +
		`<option value="1">最近 1 天</option>` +
		`<option value="3">最近 3 天</option>` +
		`<option value="7">最近 7 天</option>` +
		`<option value="30">最近 30 天</option>` +
		`<option value="custom">自定义时间范围</option>` +
		`</select><span id="tcustom" class="tcustom" hidden>` +
		`<input type="text" id="tcstart" class="tinput tdt" readonly> ～ ` +
		`<input type="text" id="tcend" class="tinput tdt" readonly></span>` +
		`<div id="tpick" class="tpick" hidden></div>` +
		`<span id="tfnote" class="tfnote" hidden></span></div>`)

	// 仪表盘卡片：有数据的卡片可点击跳转到对应小节
	type card struct {
		lbl  string
		num  int
		cls  string
		href string
	}
	cards := []card{
		{"疑似暴力破解成功", nHigh, ternary(nHigh > 0, "b-red", "b-gray"), "s-high"},
		{"内网攻击", len(a.lanHits), ternary(len(a.lanHits) > 0, "b-amber", "b-gray"), "s-lan"},
		{"黑名单命中", len(a.blacklistHits), ternary(len(a.blacklistHits) > 0, "b-amber", "b-gray"), "s-blacklist"},
		{"后门账户", len(a.backdoors), ternary(len(a.backdoors) > 0, "b-red", "b-gray"), "s-backdoor"},
		{"root 账户直接登录", len(a.rootLogins), ternary(len(a.rootLogins) > 0, "b-amber", "b-gray"), "s-root"},
		{"暴力破解 IP", nBrute, ternary(nBrute > 0, "b-amber", "b-gray"), "s-brute"},
		{"提权事件", sumPrivTypes(priv), ternary(sumPrivTypes(priv) > 0, "b-amber", "b-gray"), "s-priv"},
		{"登录成功", counts["accepted"], "b-green", "s-accepted"},
		{"登录失败", failTotal, "b-red", "s-profile"},
	}
	for _, c := range cards {
		inner := fmt.Sprintf("<div class=\"num\">%d</div><div class=\"lbl\">%s</div>", c.num, esc(c.lbl))
		if c.num > 0 && secNo[c.href] != "" {
			add(fmt.Sprintf("<a class=\"card\" href=\"#%s\">%s<span class=\"badge %s\">查看</span></a>", c.href, inner, c.cls))
		} else {
			add(fmt.Sprintf("<div class=\"card\">%s<span class=\"badge b-gray\">无</span></div>", inner))
		}
	}

	if len(a.suspected) > 0 {
		h2("s-high")
		susp := make([]suspectHit, len(a.suspected))
		copy(susp, a.suspected)
		sort.SliceStable(susp, func(i, j int) bool { return susp[i].Time.Before(susp[j].Time) })
		for gi, g := range susp {
			if gi == 0 || susp[gi-1].Date != g.Date {
				if gi > 0 {
					add("</div></div>")
				}
				h3d(g.Date)
				add("<div class=\"panel\">")
			}
			add(fmt.Sprintf("<p class=\"high\"%s>%s 用户 %s 于 [%s %s] 成功登录，此前 %d 分钟内该 IP 失败 %d 次</p>",
				tAttr(g.Time), esc(g.IP), esc(g.User), esc(g.Date), esc(g.TimeStr), window, g.WindowFails))
		}
		add("</div></div>")
	}

	if len(a.lanHits) > 0 {
		h2("s-lan")
		add("<table><tr><th>IP</th><th>失败</th><th>成功</th><th>无效用户</th><th>尝试用户名</th><th>首次出现</th><th>末次出现</th></tr>")
		for _, h := range a.lanHits {
			p := a.profileMap[h.ip]
			add(fmt.Sprintf("<tr%s><td class=\"amber\">%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				tAttr(p.Last), esc(p.IP), p.Failed, p.Accepted, p.Invalid, esc(usernamesFull(p.Users)), esc(fmtDT(p.First)), esc(fmtDT(p.Last))))
		}
		add("</table>")
	}

	if len(a.blacklistHits) > 0 {
		h2("s-blacklist")
		add("<table><tr><th>IP</th><th>失败次数</th><th>成功次数</th></tr>")
		for _, ip := range a.blacklistHits {
			p := a.profileMap[ip]
			add(fmt.Sprintf("<tr><td class=\"high\">%s</td><td>%d</td><td>%d</td></tr>", esc(ip), p.Failed, p.Accepted))
		}
		add("</table>")
	}

	if len(a.backdoors) > 0 {
		h2("s-backdoor")
		add("<table><tr><th>用户</th><th>UID</th><th>创建时间</th><th>判定依据</th></tr>")
		for _, b := range a.backdoors {
			reason := "UID 为 0，root 级后门"
			if !b.UID0 {
				gnames := make([]string, 0, len(b.Groups))
				for _, g := range b.Groups {
					gnames = append(gnames, g.Group)
				}
				reason = "加入特权组 " + esc(strings.Join(gnames, "、"))
			}
			add(fmt.Sprintf("<tr%s><td class=\"high\">%s</td><td>%d</td><td>%s</td><td>%s</td></tr>",
				tAttr(b.Created), esc(b.User), b.UID, esc(fmtDT(b.Created)), reason))
		}
		add("</table>")
	}

	if len(a.newUserLogin) > 0 {
		h2("s-newuser")
		add("<table><tr><th>用户</th><th>创建时间</th><th>首次登录</th><th>来源 IP</th><th>间隔</th></tr>")
		for _, x := range a.newUserLogin {
			add(fmt.Sprintf("<tr%s><td class=\"high\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				tAttr(x.Login), esc(x.User), esc(fmtDT(x.Created)), esc(fmtDT(x.Login)), esc(orEmpty(x.IP, "-")), esc(fmtDuration(x.Delta))))
		}
		add("</table>")
	}

	if len(a.rootLogins) > 0 {
		h2("s-root")
		for _, g := range groupEventsByDate(a.rootLogins) {
			h3d(g.Date)
			add("<table><tr><th>时间</th><th>IP</th><th>源端口</th><th>方式</th></tr>")
			for _, e := range g.Items {
				port := "-"
				if e.Port > 0 {
					port = fmt.Sprintf("%d", e.Port)
				}
				add(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
					tAttr(e.Time), esc(fmtDT(e.Time)), esc(orEmpty(e.IP, "-")), port, esc(orEmpty(e.Method, "-"))))
			}
			add("</table></div>")
		}
	}

	if len(a.concurrent) > 0 {
		h2("s-concurrent")
		conc := make([]concurHit, len(a.concurrent))
		copy(conc, a.concurrent)
		sort.SliceStable(conc, func(i, j int) bool { return conc[i].Time1.Before(conc[j].Time1) })
		for gi, x := range conc {
			d := x.Time1.Format("2006-01-02")
			if gi == 0 || conc[gi-1].Time1.Format("2006-01-02") != d {
				if gi > 0 {
					add("</div></div>")
				}
				h3d(d)
				add("<div class=\"panel\">")
			}
			add(fmt.Sprintf("<p class=\"high\"%s>%s 于 %s 来自 %s，%s 后又从 %s 登录</p>",
				tAttr(x.Time1), esc(x.User), esc(fmtDT(x.Time1)), esc(x.IP1), esc(fmtDuration(x.Delta)), esc(x.IP2)))
		}
		add("</div></div>")
	}

	if len(privRows) > 0 {
		h2("s-priv")
		for _, g := range groupEventsByDate(privRows) {
			h3d(g.Date)
			add("<table><tr><th>时间</th><th>类型</th><th>用户</th><th>目标</th><th>命令</th></tr>")
			for _, e := range g.Items {
				mark := ""
				if e.Type == "sudo_deny" || e.Type == "su_deny" {
					mark = " class=\"high\""
				}
				add(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td%s>%s</td><td>%s</td><td><code>%s</code></td></tr>",
					tAttr(e.Time), esc(fmtDT(e.Time)), esc(typeLabel[e.Type]), mark, esc(orEmpty(e.User, "-")),
					esc(orEmpty(e.Target, "-")), esc(e.Command)))
			}
			add("</table></div>")
		}
	}

	if len(a.offHours) > 0 {
		h2("s-offhours")
		for _, g := range groupEventsByDate(a.offHours) {
			h3d(g.Date)
			add("<table><tr><th>时间</th><th>IP</th><th>用户</th><th>方式</th></tr>")
			for _, e := range g.Items {
				add(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
					tAttr(e.Time), esc(fmtDT(e.Time)), esc(orEmpty(e.IP, "-")), esc(orEmpty(e.User, "-")), esc(orEmpty(e.Method, "-"))))
			}
			add("</table></div>")
		}
	}

	if len(a.bruteIPs) > 0 {
		h2("s-brute")
		add("<div class=\"panel\">")
		peak := a.bruteIPs[0].n
		for _, b := range a.bruteIPs {
			w := b.n * 100 / peak
			if w < 2 {
				w = 2
			}
			add(fmt.Sprintf("<div class=\"bar-row\"><div class=\"bar-label\">%s</div><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:%d%%\"></div></div><div class=\"bar-num\">%d 次</div></div>",
				esc(b.ip), w, b.n))
		}
		add("</div>")
	}

	if len(a.accepted) > 0 {
		h2("s-accepted")
		for _, g := range groupEventsByDate(a.accepted) {
			h3d(g.Date)
			add("<table><tr><th>成功时间</th><th>用户</th><th>IP</th><th>源端口</th><th>方式</th></tr>")
			for _, e := range g.Items {
				port := "-"
				if e.Port > 0 {
					port = fmt.Sprintf("%d", e.Port)
				}
				add(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
					tAttr(e.Time), esc(fmtDT(e.Time)), esc(orEmpty(e.User, "-")), esc(orEmpty(e.IP, "-")), port, esc(orEmpty(e.Method, "-"))))
			}
			add("</table></div>")
		}
	}

	h2("s-profile")
	sorted := a.sortedProfiles()
	if len(sorted) > 0 {
		add("<table><tr><th>IP</th><th>失败</th><th>成功</th><th>无效用户</th><th>尝试用户名</th><th>首次出现</th><th>末次出现</th></tr>")
		for _, p := range sorted {
			add(fmt.Sprintf("<tr%s><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				tAttr(p.Last), esc(p.IP), p.Failed, p.Accepted, p.Invalid, esc(usernamesFull(p.Users)), esc(fmtDT(p.First)), esc(fmtDT(p.Last))))
		}
		add("</table>")
	} else {
		add("<p class=\"meta\">无</p>")
	}

	h2("s-daily")
	byDate := map[string][]*dateIPStat{}
	daySet := map[string]bool{}
	for _, k := range a.dateIPOrder {
		ds := a.dateIPStats[k]
		if ds.Failed > 0 || ds.Accepted > 0 {
			daySet[k.date] = true
			byDate[k.date] = append(byDate[k.date], ds)
		}
	}
	allDates := make([]string, 0, len(daySet))
	for d := range daySet {
		allDates = append(allDates, d)
	}
	sort.Strings(allDates)
	if len(allDates) == 0 {
		add("<p class=\"meta\">无</p>")
	}
	for _, d := range allDates {
		h3d(d)
		rows := byDate[d]
		sort.SliceStable(rows, func(i, j int) bool {
			if (rows[i].Accepted > 0) != (rows[j].Accepted > 0) {
				return rows[i].Accepted > 0
			}
			return rows[i].Failed > rows[j].Failed
		})
		add("<table><tr><th>IP</th><th>失败</th><th>成功</th><th>无效用户</th><th>尝试用户名</th><th>首次</th><th>末次</th></tr>")
		for _, ds := range rows {
			add(fmt.Sprintf("<tr%s><td>%s</td><td>%d</td><td%s>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				tAttr(ds.Last), esc(ds.IP), ds.Failed, accCls(ds.Accepted), ds.Accepted, ds.Invalid,
				esc(usernamesFull(ds.Users)), esc(fmtTimeOfDay(ds.First)), esc(fmtTimeOfDay(ds.Last))))
		}
		add("</table></div>")
	}

	if len(a.sessions) > 0 {
		h2("s-sessions")
		for gi, s := range a.sessions {
			d := s.Open.Format("2006-01-02")
			if gi == 0 || a.sessions[gi-1].Open.Format("2006-01-02") != d {
				h3d(d)
				add("<table><tr><th>开启时间</th><th>关闭时间</th><th>用户</th><th>时长</th><th>状态</th></tr>")
			}
			close := "-"
			if s.HasClose {
				close = esc(fmtDT(s.Close))
			}
			dur := "-"
			if s.HasDur && s.Duration > 0 {
				dur = esc(fmtDuration(s.Duration))
			}
			status := "未正常关闭"
			cls := "high"
			if s.HasClose {
				if s.Long {
					status = "超过 24 小时"
				} else {
					status = "正常"
				}
				cls = ""
			}
			add(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td></tr>",
				tAttr(s.Open), esc(fmtDT(s.Open)), close, esc(s.User), dur, cls, status))
			if gi == len(a.sessions)-1 || a.sessions[gi+1].Open.Format("2006-01-02") != d {
				add("</table></div>")
			}
		}
	}

	if hasBinary {
		h2("s-binary")
		for _, b := range binary.Btmp {
			h3p(fmt.Sprintf("btmp 失败登录（%s）", filepath.Base(b.File)))
			if b.Fails > 0 {
				add(fmt.Sprintf("<p class=\"meta\">失败记录 %d 条，%s ~ %s</p>", b.Fails, esc(fmtDT(b.First)), esc(fmtDT(b.Last))))
				add("<table><tr><th>来源 IP</th><th>次数</th></tr>")
				for _, p := range b.Hosts.mostCommon(-1) {
					add(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", esc(p.k), p.n))
				}
				add("</table>")
				if b.Users.length() > 0 {
					var us []string
					for _, p := range b.Users.mostCommon(-1) {
						us = append(us, fmt.Sprintf("%s(%d)", p.k, p.n))
					}
					add("<p class=\"meta\">尝试用户名：" + esc(strings.Join(us, "、")) + "</p>")
				}
			} else {
				add("<p class=\"meta\">无失败登录记录</p>")
			}
		}
		for _, w := range binary.Wtmp {
			h3p(fmt.Sprintf("wtmp 登录会话（%s）", filepath.Base(w.File)))
			if len(w.Sessions) > 0 {
				add("<table><tr><th>开启</th><th>关闭</th><th>用户</th><th>终端</th><th>来源</th><th>时长</th><th>状态</th></tr>")
				for _, s := range w.Sessions {
					close := "-"
					if s.HasClose {
						close = esc(fmtDT(s.Close))
					}
					dur := "-"
					if s.HasDur && s.Duration > 0 {
						dur = esc(fmtDuration(s.Duration))
					}
					note := "未正常关闭"
					if s.Note != "" {
						note = s.Note
					} else if s.HasClose {
						note = "正常"
					}
					cls := ""
					if !s.HasClose || s.Long {
						cls = " class=\"high\""
					}
					add(fmt.Sprintf("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td%s>%s</td></tr>",
						tAttr(s.Open), esc(fmtDT(s.Open)), close, esc(s.User), esc(s.Line), esc(orEmpty(s.Host, "-")), dur, cls, esc(note)))
				}
				add("</table>")
			} else {
				add("<p class=\"meta\">无登录会话</p>")
			}
		}
		for _, ll := range binary.Lastlog {
			h3p(fmt.Sprintf("lastlog 末次登录（%s）", filepath.Base(ll.File)))
			entries := make([]lastlogEntry, len(ll.Entries))
			copy(entries, ll.Entries)
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
			var shown []lastlogEntry
			for _, e := range entries {
				if e.UID == 0 || e.UID >= 1000 {
					shown = append(shown, e)
				}
			}
			if len(shown) > 0 {
				add("<table><tr><th>用户</th><th>UID</th><th>末次登录</th><th>终端</th><th>来源</th></tr>")
				for _, e := range shown {
					mark := ""
					if dormant[e.Name] {
						mark = " class=\"high\""
					}
					add(fmt.Sprintf("<tr%s><td%s>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
						tAttr(e.Time), mark, esc(e.Name), e.UID, esc(fmtDT(e.Time)), esc(orEmpty(e.Line, "-")), esc(orEmpty(e.Host, "-"))))
				}
				add("</table>")
			} else {
				add("<p class=\"meta\">无记录</p>")
			}
		}
	}

	h2("s-notes")
	add("<ul class=\"notes\">")
	add(fmt.Sprintf("<li>失败统计包含认证失败、无效用户、认证超限、认证中断四类，合计 %d 条</li>", failTotal))
	add("<li>无用户的认证中断（Connection closed by IP [preauth] 一类）计入失败，用户名记为未知</li>")
	add("<li>认证中断类事件计入失败统计，并保留在本报告与 JSON、CSV 导出明细中</li>")
	add(fmt.Sprintf("<li>暴力破解判定阈值: 失败次数 &gt; %d（--threshold 可调）</li>", threshold))
	add(fmt.Sprintf("<li>疑似暴力破解成功关联窗口: 成功登录前 %d 分钟内失败达到阈值（--window 可调）</li>", window))
	add("<li>内网攻击: 来源 IP 属于私网段（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）且存在失败类事件即列出，提示失陷内网主机横向移动或本机误操作</li>")
	add(fmt.Sprintf("<li>同账户短时多 IP 判定: 相邻两次成功登录来自不同 IP 且间隔 &lt;= %d 分钟</li>", concurrentMinutes))
	add(fmt.Sprintf("<li>非工作时段: %02d:00～%02d:59 的成功登录</li>", offHoursStart, offHoursEnd-1))
	add(fmt.Sprintf("<li>新建账户关联: useradd 后 %d 天内的首次成功登录</li>", newUserLoginDays))
	add("<li>btmp/wtmp/lastlog 独立统计，不并入文本日志事件，避免重复计数</li>")
	add(fmt.Sprintf("<li>journald 提取仅在未选中文本日志时触发，统计最近 %d 天</li>", journalDays))
	add("<li>无年份日志按文件修改时间推断年份（月份差 &gt;= 6 视为跨年），跨年场景请人工复核</li>")
	add("<li>屏幕输出为摘要视图（省略处有标注），本报告与 JSON、CSV 导出保留完整明细</li>")
	add("<li>报告内时间范围筛选作用于事件明细与按日、按行数据，比较精确到时分秒，最近 N 天以报告中最近事件日为终点整天对齐；仪表卡片按所选范围汇总（登录失败按日粒度），无日期的聚合明细小节保持全量列表</li>")
	add("</ul>")
	add("</main></div>")
	// 滚动高亮当前小节：跳过被时间筛选隐藏的小节（display:none 元素 offsetParent 为 null）；
	// 点击「目录」标题回到页面顶部
	add(`<script>(function(){var links=document.querySelectorAll(".toc a");if(!links.length)return;var tt=document.querySelector(".toc-t");if(tt){tt.title="回到顶部";tt.addEventListener("click",function(){window.scrollTo(0,0)})}var heads=document.querySelectorAll("main h2[id]");var lastY=-1;function update(){var y=Math.round(window.scrollY);if(y===lastY)return;lastY=y;var cur=null;if(heads.length&&window.innerHeight+y>=document.documentElement.scrollHeight-40){for(var i=heads.length-1;i>=0;i--){if(heads[i].offsetParent!==null){cur=heads[i].id;break}}}else{for(var i=0;i<heads.length;i++){if(heads[i].offsetParent===null)continue;if(heads[i].getBoundingClientRect().top<=120)cur=heads[i].id;else break}}links.forEach(function(a){a.classList.toggle("active",!!cur&&a.getAttribute("href")==="#"+cur)});if(cur){var act=document.querySelector('.toc a[href="#'+cur+'"]');var box=document.querySelector(".toc");if(act&&box&&box.scrollHeight>box.clientHeight){var vr=act.getBoundingClientRect(),br=box.getBoundingClientRect();var tp=vr.top-br.top+box.scrollTop,bot=tp+vr.height;if(tp<box.scrollTop+8)box.scrollTop=tp-8;else if(bot>box.scrollTop+box.clientHeight-8)box.scrollTop=bot-box.clientHeight+8}}}window.addEventListener("scroll",update,{passive:true});window.addEventListener("hashchange",update);window.addEventListener("resize",function(){lastY=-1;update()});setInterval(update,400);update()})();</script>`)
	// 时间范围筛选：按 data-t（YYYY-MM-DD HH:MM:SS）显隐明细行，比较到时分秒；
	// 「最近 N 天」取整日对齐（起点 00:00:00，终点 23:59:59），以报告中最近事件日为终点；
	// 自定义起止空值表示该侧不设限，选自定义后需点「确认」或回车才应用；
	// 日期分组、表格与小节可见性由内部行派生，目录子条目随锚点小节同步显隐；
	// 仪表卡片按所选范围汇总：事件卡片数可见行，登录失败按按日表失败列求和
	// （失败类事件解析时必带来源 IP，按日合计恒等于全量失败总数），
	// 暴力破解 IP 与黑名单命中以画像表可见行（末次出现在范围内）判定；
	// 无日期的聚合明细保持全量列表
	add(`<script>(function(){var sel=document.getElementById("tsel");if(!sel)return;var cst=document.getElementById("tcstart"),cen=document.getElementById("tcend"),cus=document.getElementById("tcustom"),note=document.getElementById("tfnote");var items=[].slice.call(document.querySelectorAll("main [data-t]"));var maxT="",minT="";items.forEach(function(el){var d=el.getAttribute("data-t");if(d>maxT)maxT=d;if(!minT||d<minT)minT=d});if(!maxT){sel.disabled=true;return}var maxD=maxT.slice(0,10);function pad(n){return(n<10?"0":"")+n}function shiftDay(ds,n){var t=new Date(+ds.slice(0,4),+ds.slice(5,7)-1,+ds.slice(8,10)-n);return t.getFullYear()+"-"+pad(t.getMonth()+1)+"-"+pad(t.getDate())}function norm(v){if(!v)return"";v=v.replace("T"," ");if(v.length===16)v+=":00";return v}function inR(d,r){if(r[0]&&d<r[0])return false;if(r[1]&&d>r[1])return false;return true}function vis(el){return !el.classList.contains("hidden")}function anyTagVis(root){var list=root.querySelectorAll("[data-t]");for(var i=0;i<list.length;i++){if(vis(list[i]))return true}return false}function curRange(){var v=sel.value;if(v==="all")return null;if(v==="custom"){var a=norm(cst.value),b=norm(cen.value);if(a&&b&&a>b){var t=a;a=b;b=t}return[a,b]}return[shiftDay(maxD,v-1)+" 00:00:00",maxD+" 23:59:59"]}function apply(){var r=curRange();items.forEach(function(el){el.classList.toggle("hidden",r!==null&&!inR(el.getAttribute("data-t"),r))});[].slice.call(document.querySelectorAll("main table")).forEach(function(tb){if(tb.querySelector("[data-t]"))tb.classList.toggle("hidden",!anyTagVis(tb))});[].slice.call(document.querySelectorAll("main .dg")).forEach(function(dg){dg.classList.toggle("hidden",!anyTagVis(dg))});[].slice.call(document.querySelectorAll("main h3")).forEach(function(h){if(h.closest(".dg"))return;var any=false,allHidden=true,el=h.nextElementSibling;while(el&&el.tagName!=="H2"&&el.tagName!=="H3"){if(el.querySelector("[data-t]")){any=true;if(vis(el))allHidden=false}el=el.nextElementSibling}if(any)h.classList.toggle("hidden",allHidden)});[].slice.call(document.querySelectorAll("main h2[id]")).forEach(function(h){var anyVis=false,el=h.nextElementSibling;while(el&&el.tagName!=="H2"){if(vis(el)){anyVis=true;break}el=el.nextElementSibling}h.classList.toggle("hidden",!anyVis);var link=document.querySelector('.toc a[href="#'+h.id+'"]');if(link)link.classList.toggle("hidden",!anyVis)});[].slice.call(document.querySelectorAll(".toc a.toc-sub")).forEach(function(a){var tgt=document.querySelector(a.getAttribute("href"));var box=tgt?(tgt.closest(".dg")||tgt):null;a.classList.toggle("hidden",!box||!vis(box))});updateCards(r);if(r===null){note.hidden=true}else{note.hidden=false;note.textContent="筛选范围: "+(r[0]||"最早")+" ～ "+(r[1]||"最晚")+"，统计卡片已按范围汇总"}}function secWalk(id,fn){var h=document.getElementById(id);if(!h)return;var el=h.nextElementSibling;while(el&&el.tagName!=="H2"){fn(el);el=el.nextElementSibling}}function secTagged(id){var out=[];secWalk(id,function(el){if(el.hasAttribute&&el.hasAttribute("data-t"))out.push(el);if(el.querySelectorAll)[].push.apply(out,el.querySelectorAll("[data-t]"))});return out}function countVis(id){var n=0;secTagged(id).forEach(function(e){if(!e.classList.contains("hidden"))n++});return n}function secTables(id){var out=[];secWalk(id,function(el){if(el.tagName==="TABLE")out.push(el);else if(el.querySelectorAll)out.push.apply(out,el.querySelectorAll("table"))});return out}function atoi(s){var n=parseInt(s,10);return isNaN(n)?0:n}function sumDailyFails(){var n=0;secTables("s-daily").forEach(function(tb){[].slice.call(tb.querySelectorAll("tr[data-t]")).forEach(function(r){if(r.classList.contains("hidden"))return;n+=atoi(r.children[1].textContent)})});return n}function visProfileSet(){var s={};secTables("s-profile").forEach(function(tb){[].slice.call(tb.querySelectorAll("tr[data-t]")).forEach(function(r){if(!r.classList.contains("hidden"))s[r.children[0].textContent]=1})});return s}function secEls(id,q){var out=[];secWalk(id,function(el){if(el.matches&&el.matches(q))out.push(el);if(el.querySelectorAll)[].push.apply(out,el.querySelectorAll(q))});return out}function updateCards(r){var set=visProfileSet();var vals={};vals["s-accepted"]=countVis("s-accepted");vals["s-profile"]=sumDailyFails();vals["s-high"]=countVis("s-high");vals["s-backdoor"]=countVis("s-backdoor");vals["s-root"]=countVis("s-root");vals["s-priv"]=countVis("s-priv");vals["s-lan"]=countVis("s-lan");var nb=0;secEls("s-brute",".bar-row").forEach(function(bar){var l=bar.querySelector(".bar-label");if(l&&set[l.textContent])nb++});vals["s-brute"]=nb;var nbl=0;secEls("s-blacklist","tr").forEach(function(tr){if(set[tr.children[0].textContent])nbl++});vals["s-blacklist"]=nbl;for(var k in vals){var num=document.querySelector('a.card[href="#'+k+'"] .num');if(num)num.textContent=vals[k]}}sel.addEventListener("change",function(){if(sel.value==="custom"){if(!cst.value&&minT)cst.value=minT;if(!cen.value&&maxT)cen.value=maxT;cus.hidden=false;return}cus.hidden=true;apply()});
// 自绘时间选择弹层：日历 + 时/分/秒三列，底部「今天」在左、「确认」在其右、「清除」靠右；
// 点「确认」写入输入框并应用筛选，「清除」置空该侧（不限）并应用；点弹层外、滚动或 Esc 关闭
var pop=document.getElementById("tpick"),pcur=null,pview=null,pwork=null;
var WD=["一","二","三","四","五","六","日"];
function pparse(v){if(!v)return null;v=v.replace("T"," ");var m=v.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})(?::(\d{2}))?$/);if(!m)return null;return{y:+m[1],mo:+m[2],d:+m[3],h:+m[4],mi:+m[5],s:+(m[6]||0)}}
function pfmt(w){return w.y+"-"+pad(w.mo)+"-"+pad(w.d)+" "+pad(w.h)+":"+pad(w.mi)+":"+pad(w.s)}
function pcol(k,from,to){var h='<div class="tp-col">';for(var i=from;i<=to;i++)h+='<span class="tp-tv'+(i===pwork[k]?" tp-sel":"")+'" data-tk="'+k+'" data-v="'+i+'">'+pad(i)+"</span>";return h+"</div>"}
function prender(){
 var first=new Date(pview.y,pview.m,1),shift=(first.getDay()+6)%7,days=new Date(pview.y,pview.m+1,0).getDate(),pd=new Date(pview.y,pview.m,0).getDate();
 var now=new Date(),ty=now.getFullYear(),tm=now.getMonth(),td=now.getDate();
 var h='<div class="tp-h"><b>'+pview.y+"年"+(pview.m+1)+'月</b><span><button type="button" class="tp-mb" data-nav="-1">‹</button><button type="button" class="tp-mb" data-nav="1">›</button></span></div><div class="tp-wd">'+WD.map(function(w){return "<span>"+w+"</span>"}).join("")+'</div><div class="tp-grid">';
 for(var i=0;i<42;i++){var d,off,cls="tp-d";
  if(i<shift){d=pd-shift+1+i;off=-1}else if(i<shift+days){d=i-shift+1;off=0}else{d=i-shift-days+1;off=1}
  if(off)cls+=" tp-dim";
  var mo=pview.m+off+1;
  if(off===0&&d===pwork.d&&mo===pwork.mo&&pview.y===pwork.y)cls+=" tp-sel";
  if(off===0&&d===td&&pview.m===tm&&pview.y===ty)cls+=" tp-tdy";
  h+='<span class="'+cls+'" data-day="'+d+'" data-off="'+off+'">'+d+"</span>"}
 h+='</div><div class="tp-time">'+pcol("h",0,23)+pcol("mi",0,59)+pcol("s",0,59)+'</div><div class="tp-ft"><button type="button" class="tp-link" data-act="today">今天</button><button type="button" class="tbtn" data-act="ok">确认</button><button type="button" class="tp-link tp-gray" data-act="clear">清除</button></div>';
 pop.innerHTML=h;
 ["h","mi","s"].forEach(function(k){var el=pop.querySelector('.tp-tv.tp-sel[data-tk="'+k+'"]');if(!el)return;var c=el.parentElement;c.scrollTop=el.offsetTop-(c.clientHeight-el.offsetHeight)/2});
 pop.hidden=false;pposition()}
function pposition(){var r=pcur.getBoundingClientRect(),w=pop.offsetWidth||270;pop.style.left=Math.max(8,Math.min(r.left,window.innerWidth-w-10))+"px";pop.style.top=(r.bottom+6)+"px"}
function popen(inp){pcur=inp;var v=pparse(inp.value);var base=v||{y:+maxD.slice(0,4),mo:+maxD.slice(5,7),d:+maxD.slice(8,10),h:12,mi:0,s:0};pwork=base;pview={y:base.y,m:base.mo-1};prender()}
function pclose(){pop.hidden=true;pcur=null}
function papply(){if(sel.value==="custom")apply()}
pop.addEventListener("click",function(ev){
 ev.stopPropagation();
 var t=ev.target;
 if(t.classList.contains("tp-mb")){pview.m+=+t.getAttribute("data-nav");var d=new Date(pview.y,pview.m,1);pview.y=d.getFullYear();pview.m=d.getMonth();prender();return}
 var tv=t.closest?t.closest(".tp-tv"):null;
 if(tv){pwork[tv.getAttribute("data-tk")]=+tv.getAttribute("data-v");prender();return}
 var dd=t.closest?t.closest(".tp-d"):null;
 if(dd){var off=+dd.getAttribute("data-off");if(off){pview.m+=off;var d2=new Date(pview.y,pview.m,1);pview.y=d2.getFullYear();pview.m=d2.getMonth()}
  pwork.d=+dd.getAttribute("data-day");pwork.mo=pview.m+1;pwork.y=pview.y;prender();return}
 var act=t.closest?t.closest("[data-act]"):null;
 if(!act)return;
 var a=act.getAttribute("data-act");
 if(a==="today"){var n=new Date();pwork={y:n.getFullYear(),mo:n.getMonth()+1,d:n.getDate(),h:pwork.h,mi:pwork.mi,s:pwork.s};pview={y:pwork.y,m:pwork.mo-1};prender()}
 else if(a==="ok"){pcur.value=pfmt(pwork);pclose();papply()}
 else if(a==="clear"){pcur.value="";pclose();papply()}});
document.addEventListener("click",function(ev){if(!pop.hidden&&pcur&&!pop.contains(ev.target)&&ev.target!==pcur)pclose()});
window.addEventListener("scroll",function(ev){if(!pop.hidden&&!pop.contains(ev.target))pclose()},true);
window.addEventListener("resize",function(){if(!pop.hidden)pclose()});
document.addEventListener("keydown",function(ev){if(ev.key==="Escape"&&!pop.hidden)pclose()});
[cst,cen].forEach(function(inp){inp.addEventListener("click",function(){if(pcur===inp&&!pop.hidden){pclose();return}popen(inp)})});
})();</script>`)
	add("</body></html>")

	// 回填侧边目录：主条目按小节顺序，日期子条目缩进挂在所属小节下
	var toc strings.Builder
	toc.WriteString("<nav class=\"toc\"><div class=\"toc-t\">目录</div>")
	for _, s := range secList {
		fmt.Fprintf(&toc, "<a href=\"#%s\">%s. %s</a>", s.id, secNo[s.id], esc(s.title))
		for _, sub := range subsBySec[s.id] {
			toc.WriteString(sub)
		}
	}
	toc.WriteString("</nav>")
	out := strings.Replace(strings.Join(parts, ""), "<!--TOC-->", toc.String(), 1)
	if err := os.WriteFile(outfile, []byte(out), 0644); err != nil {
		return err
	}
	fmt.Println(cGreen(fmt.Sprintf("HTML 审计报告已成功生成至: %s", outfile)))
	return nil
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// accCls 成功次数大于 0 时返回绿色高亮样式（按日明细的成功列）。
func accCls(n int) string {
	if n > 0 {
		return " class=\"green\""
	}
	return ""
}

// dateGroup 报告里按日期分子标题的一组事件。
type dateGroup struct {
	Date  string
	Items []*Event
}

// groupEventsByDate 事件按日期升序分组，组内按时间升序，供小节内输出日期子标题。
func groupEventsByDate(evs []*Event) []dateGroup {
	sorted := make([]*Event, len(evs))
	copy(sorted, evs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Time.Before(sorted[j].Time) })
	var out []dateGroup
	for _, e := range sorted {
		if len(out) == 0 || out[len(out)-1].Date != e.Date {
			out = append(out, dateGroup{Date: e.Date})
		}
		out[len(out)-1].Items = append(out[len(out)-1].Items, e)
	}
	return out
}
