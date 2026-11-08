package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ==================== 终端输出 ====================

func printHeader(a *analysis, opts *options, srcLines []string) {
	fmt.Println(cCyan(cBold("=== SSH 日志分析 ===")))
	fmt.Printf("分析文件: %s\n", opts.logfile)
	for _, s := range srcLines {
		fmt.Printf("  %s\n", s)
	}
	total := a.totalEvents()
	if total > 0 {
		failTotal := sumFailClass(a.eventCounts)
		privTotal := sumPrivTypes(a.privilege)
		accTotal := a.eventCounts["accepted"]
		other := total - failTotal - privTotal - accTotal
		fmt.Printf("解析事件共 %s 条：登录成功 %d，登录失败 %d，提权事件 %d，其他 %d\n",
			cBold(fmt.Sprintf("%d", total)), accTotal, failTotal, privTotal, other)
		fmt.Printf("时间跨度: %s ~ %s\n", fmtDT(a.spanFirst), fmtDT(a.spanLast))
	} else {
		fmt.Println("解析事件 0 条")
	}
}

func sumFailClass(counts map[string]int) int {
	n := 0
	for t := range failClass {
		n += counts[t]
	}
	return n
}

func sumPrivTypes(priv map[string][]*Event) int {
	n := 0
	for _, evs := range priv {
		n += len(evs)
	}
	return n
}

// ==================== 总体结论 ====================

// truncateWidth 按显示宽度截断，超宽以 … 结尾（省略号按 1 个显示单元计，
// 截断体加省略号恰好占满 w，与未截断行保持列对齐）。
func truncateWidth(s string, w int) string {
	if dispWidth(s) <= w {
		return s
	}
	var out strings.Builder
	cw := 0
	for _, ch := range s {
		rw := runeWidth(ch)
		if cw+rw > w-1 {
			break
		}
		out.WriteRune(ch)
		cw += rw
	}
	out.WriteString("…")
	return out.String()
}

// printColumns 多列输出：各列按最宽条目对齐，列间距 3 格，按终端宽度自动换行。
func printColumns(items []string, indent string) {
	width := terminalWidth() - dispWidth(indent)
	if width < 20 {
		width = 20
	}
	maxW := 0
	for _, s := range items {
		if w := dispWidth(s); w > maxW {
			maxW = w
		}
	}
	cols := width / (maxW + 3)
	if cols < 1 {
		cols = 1
	}
	for i, s := range items {
		if i%cols == 0 {
			fmt.Print(indent)
		}
		fmt.Print(s)
		if i%cols == cols-1 || i == len(items)-1 {
			fmt.Println()
		} else {
			fmt.Print(strings.Repeat(" ", maxW+3-dispWidth(s)))
		}
	}
}

// secTitle 输出带前导空行的节标题，各节之间以空行分隔。
func secTitle(s string) {
	fmt.Println("\n" + cCyan(cBold(s)))
}

// padLeftWidth 按显示宽度在左侧补空格到 w（用于右对齐的中文表头）。
func padLeftWidth(s string, w int) string {
	if d := dispWidth(s); d < w {
		return strings.Repeat(" ", w-d) + s
	}
	return s
}

func printConclusion(a *analysis, threshold, window int, dormant map[string]bool) {
	fmt.Println("\n" + cCyan(cBold("--- 总体结论 ---")))

	// 暴力破解判定
	fmt.Println(cBold("【暴力破解】"))
	if len(a.bruteIPs) > 0 {
		fmt.Println(cRed(fmt.Sprintf("  存在暴力破解行为的 IP 共 %d 个（失败 > %d 次）：", len(a.bruteIPs), threshold)))
		items := make([]string, 0, 10)
		for i, b := range a.bruteIPs {
			if i >= 10 {
				break
			}
			items = append(items, fmt.Sprintf("%s（%d次）", b.ip, b.n))
		}
		printColumns(items, "    ")
		if len(a.bruteIPs) > 10 {
			fmt.Println("    （仅显示失败次数 Top 10）")
		}
	} else {
		fmt.Printf("  暴力破解来源 IP（失败 > %d 次）：无\n", threshold)
	}
	fmt.Println()
	if len(a.suspected) > 0 {
		fmt.Println(cHRed(fmt.Sprintf("  高危·疑似暴力破解成功 %d 起（成功前 %d 分钟内同 IP 失败达阈值）：", len(a.suspected), window)))
		for i, h := range a.suspected {
			if i >= 10 {
				fmt.Printf("    （共 %d 起，已省略 %d 起）\n", len(a.suspected), len(a.suspected)-10)
				break
			}
			fmt.Println(cHRed(fmt.Sprintf("    · %s 用户 %s 于 [%s %s] 成功登录，此前 %d 分钟内该 IP 失败 %d 次",
				h.IP, h.User, h.Date, h.TimeStr, window, h.WindowFails)))
		}
	} else {
		fmt.Println("  高危·疑似暴力破解成功：无")
	}
	fmt.Println()

	// 账户风险
	fmt.Println(cBold("【账户风险】"))
	if len(a.backdoors) > 0 {
		for _, b := range a.backdoors {
			groupNames := make([]string, 0, len(b.Groups))
			for _, g := range b.Groups {
				groupNames = append(groupNames, g.Group)
			}
			reason := fmt.Sprintf("加入特权组 %s", strings.Join(groupNames, "、"))
			if b.UID0 {
				reason = "UID 为 0"
			}
			extra := ""
			if dormant[b.User] {
				extra = "，且无任何登录记录"
			}
			fmt.Println(cHRed(fmt.Sprintf("  疑似后门账户：%s（UID %d，创建于 %s，%s%s）",
				b.User, b.UID, fmtDT(b.Created), reason, extra)))
		}
	} else {
		fmt.Println("  疑似后门账户：无")
	}
	fmt.Println()
	if len(a.newUserLogin) > 0 {
		for _, x := range a.newUserLogin {
			fmt.Println(cHRed(fmt.Sprintf("  新建账户快速登录：%s（UID %d）创建于 %s，%s后从 %s 首次登录",
				x.User, x.UID, fmtDT(x.Created), fmtDuration(x.Delta), x.IP)))
		}
	} else {
		fmt.Println("  新建账户快速登录：无")
	}
	fmt.Println()

	// 登录行为
	fmt.Println(cBold("【登录行为】"))
	if len(a.rootLogins) > 0 {
		ips := newOcounter()
		for _, e := range a.rootLogins {
			if e.IP != "" {
				ips.add(e.IP)
			}
		}
		fmt.Println(cYellow(fmt.Sprintf("  root 账户通过 SSH 直接登录 %d 次，来源 %d 个 IP，需确认是否为预期行为：",
			len(a.rootLogins), ips.length())))
		items := make([]string, 0, 10)
		for _, p := range ips.mostCommon(10) {
			items = append(items, fmt.Sprintf("%s（%d次）", p.k, p.n))
		}
		printColumns(items, "    ")
		if ips.length() > 10 {
			fmt.Println("    （仅显示来源 Top 10）")
		}
	} else {
		fmt.Println("  root 账户直接登录：无")
	}
	fmt.Println()
	if len(a.concurrent) > 0 {
		fmt.Println(cHRed(fmt.Sprintf("  同账户短时多 IP 登录 %d 组（凭证可能泄露或共享）：", len(a.concurrent))))
		for i, x := range a.concurrent {
			if i >= 10 {
				fmt.Printf("    （共 %d 组，已省略 %d 组）\n", len(a.concurrent), len(a.concurrent)-10)
				break
			}
			fmt.Println(cHRed(fmt.Sprintf("    · %s 于 %s 来自 %s，%s后又从 %s 登录",
				x.User, fmtDT(x.Time1), x.IP1, fmtDuration(x.Delta), x.IP2)))
		}
	} else {
		fmt.Println("  同账户短时多 IP 登录：无")
	}
	fmt.Println()
	if len(a.offHours) > 0 {
		fmt.Println(cYellow(fmt.Sprintf("  非工作时段（%02d:00～%02d:59）成功登录 %d 条：",
			offHoursStart, offHoursEnd-1, len(a.offHours))))
		items := make([]string, 0, 10)
		for i, e := range a.offHours {
			if i >= 10 {
				break
			}
			items = append(items, fmt.Sprintf("[%s] %s %s", fmtDT(e.Time), e.IP, e.User))
		}
		printColumns(items, "    ")
		if len(a.offHours) > 10 {
			fmt.Printf("    （共 %d 条，已省略 %d 条）\n", len(a.offHours), len(a.offHours)-10)
		}
	} else {
		fmt.Printf("  非工作时段（%02d:00～%02d:59）成功登录：无\n", offHoursStart, offHoursEnd-1)
	}
	fmt.Println()

	// 提权事件
	fmt.Println(cBold("【提权事件】"))
	priv := a.privilege
	nSudo := len(priv["sudo_cmd"])
	nSudoSess := len(priv["sudo_session"])
	nDeny := len(priv["sudo_deny"])
	nSuSess := len(priv["su_session"])
	nSuDeny := len(priv["su_deny"])
	if nSudo > 0 || nSudoSess > 0 || nDeny > 0 || nSuSess > 0 || nSuDeny > 0 {
		fmt.Println(cYellow(fmt.Sprintf("  sudo 提权 %d 条，sudo 会话 %d 条，sudo 认证失败 %d 条，su 会话 %d 条，su 认证失败 %d 条",
			nSudo, nSudoSess, nDeny, nSuSess, nSuDeny)))
		rows := append(append([]*Event{}, priv["sudo_deny"]...), priv["su_deny"]...)
		for i, e := range rows {
			if i >= privRecent {
				break
			}
			tgt := ""
			if e.Target != "" {
				tgt = " → " + e.Target
			}
			fmt.Println(cHRed(fmt.Sprintf("    提权认证失败：[%s] %s%s", fmtDT(e.Time), e.User, tgt)))
		}
		if len(rows) > privRecent {
			fmt.Printf("    （其余 %d 条提权认证失败已省略，完整记录见导出）\n", len(rows)-privRecent)
		}
		shown := 0
		for _, e := range priv["sudo_cmd"] {
			if shown >= privRecent {
				fmt.Printf("    （其余 %d 条提权命令已省略，完整记录见导出）\n", nSudo-shown)
				break
			}
			tgt := ""
			if e.Target != "" {
				tgt = fmt.Sprintf("（目标 %s）", e.Target)
			}
			cmd := e.Command
			if r := []rune(cmd); len(r) > 80 {
				cmd = string(r[:80]) + "…"
			}
			rootMark := ""
			if e.Target == "root" {
				rootMark = cHRed(" [root]")
			}
			fmt.Printf("    [%s] %s%s%s 执行 %s\n", fmtDT(e.Time), e.User, tgt, rootMark, cmd)
			shown++
		}
	} else {
		fmt.Println("  无")
	}
	fmt.Println()

	// 黑名单
	fmt.Println(cBold("【黑名单】"))
	if len(a.blacklistHits) > 0 {
		fmt.Println(cRed(fmt.Sprintf("  命中 %d 个：", len(a.blacklistHits))))
		printColumns(a.blacklistHits, "    ")
	} else {
		fmt.Println("  命中：无")
	}
	fmt.Println()

	// 内网攻击
	fmt.Println(cBold("【内网攻击】"))
	if len(a.lanHits) > 0 {
		fmt.Println(cYellow(fmt.Sprintf("  攻击 IP 共 %d 个（按失败次数降序）：", len(a.lanHits))))
		for i, h := range a.lanHits {
			if i >= 10 {
				fmt.Printf("  （仅显示失败次数 Top 10，其余 %d 个见报告）\n", len(a.lanHits)-10)
				break
			}
			p := a.profileMap[h.ip]
			fmt.Println(cYellow(fmt.Sprintf("    %s（失败 %d 次，成功 %d 次，尝试账户 %s）",
				h.ip, p.Failed, p.Accepted, usernamesFull(p.Users))))
		}
	} else {
		fmt.Println("  内网来源无攻击行为")
	}
}

// ==================== IP 画像表 ====================

// numWidth 十进制整数的字符宽度。
func numWidth(n int) int {
	return len(strconv.Itoa(n))
}

// tableRow 拼接画像表的一行：前 4 列（标题列与三个数值列）单空格分隔，
// 用户名列与两个时间列之间双空格分隔，保证截断内容与时间不紧贴。
func tableRow(cells []string) string {
	return strings.Join(cells[:4], " ") + "  " + strings.Join(cells[4:], "  ")
}

func printProfileTable(a *analysis, topN int) {
	sorted := a.sortedProfiles()
	var rows []*Profile
	for _, p := range sorted {
		if p.Failed > 0 || p.Accepted > 0 {
			rows = append(rows, p)
		}
		if len(rows) >= topN {
			break
		}
	}
	if len(rows) == 0 {
		secTitle("--- IP 画像 ---")
		fmt.Println("无有效记录")
		return
	}
	if len(rows) < topN {
		secTitle(fmt.Sprintf("--- IP 画像（按失败次数降序，共 %d 个）---", len(rows)))
	} else {
		secTitle(fmt.Sprintf("--- IP 画像 Top %d（按失败次数降序）---", len(rows)))
	}
	ipW := dispWidth("IP")
	failW, accW, invW := dispWidth("失败"), dispWidth("成功"), dispWidth("无效")
	for _, p := range rows {
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
	const userW = 30
	const dtW = 19 // "2006-01-02 15:04:05" 的显示宽度
	header := tableRow([]string{
		padWidth("IP", ipW),
		padLeftWidth("失败", failW), padLeftWidth("成功", accW), padLeftWidth("无效", invW),
		padWidth("尝试用户名（前5）", userW),
		padWidth("首次", dtW), "末次",
	})
	fmt.Println(header)
	for _, p := range rows {
		users := "-"
		if p.Users.length() > 0 {
			users = topUsernames(p.Users, 5)
		}
		fmt.Println(tableRow([]string{
			padWidth(p.IP, ipW),
			padLeftWidth(strconv.Itoa(p.Failed), failW),
			padLeftWidth(strconv.Itoa(p.Accepted), accW),
			padLeftWidth(strconv.Itoa(p.Invalid), invW),
			padWidth(truncateWidth(users, userW), userW),
			padWidth(fmtDT(p.First), dtW), fmtDT(p.Last),
		}))
	}
}

// ==================== 日期画像 ====================

// printDateProfile 按日期分组展示各来源 IP 的登录行为统计，格式与 IP 画像一致：
// 默认显示最近几天，各天最多数条，有成功登录的 IP 排前并标绿，多余以省略号收尾。
func printDateProfile(a *analysis) {
	byDate := map[string][]*dateIPStat{}
	var dateSeq []string
	for _, k := range a.dateIPOrder {
		ds := a.dateIPStats[k]
		if ds.Failed == 0 && ds.Accepted == 0 {
			continue
		}
		if _, ok := byDate[k.date]; !ok {
			dateSeq = append(dateSeq, k.date)
		}
		byDate[k.date] = append(byDate[k.date], ds)
	}
	if len(dateSeq) == 0 {
		secTitle("--- 日期画像 ---")
		fmt.Println("无记录")
		return
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dateSeq)))
	shown := dateSeq
	title := fmt.Sprintf("--- 日期画像（共 %d 天）---", len(dateSeq))
	if len(dateSeq) > dateProfileDays {
		shown = dateSeq[:dateProfileDays]
		title = fmt.Sprintf("--- 日期画像（共 %d 天，显示最近 %d 天）---", len(dateSeq), dateProfileDays)
	}
	secTitle(title)

	// 各日排序（有成功登录的排前，其后按失败次数降序）并截取展示行，统一计算列宽
	days := make([][]*dateIPStat, 0, len(shown))
	for _, d := range shown {
		rows := byDate[d]
		sort.SliceStable(rows, func(i, j int) bool {
			if (rows[i].Accepted > 0) != (rows[j].Accepted > 0) {
				return rows[i].Accepted > 0
			}
			return rows[i].Failed > rows[j].Failed
		})
		if len(rows) > dateProfileRows {
			rows = rows[:dateProfileRows]
		}
		days = append(days, rows)
	}
	ipW, failW, accW, invW := dispWidth("IP"), dispWidth("失败"), dispWidth("成功"), dispWidth("无效")
	for _, rows := range days {
		for _, ds := range rows {
			if len(ds.IP) > ipW {
				ipW = len(ds.IP)
			}
			if w := numWidth(ds.Failed); w > failW {
				failW = w
			}
			if w := numWidth(ds.Accepted); w > accW {
				accW = w
			}
			if w := numWidth(ds.Invalid); w > invW {
				invW = w
			}
		}
	}
	const userW = 30
	const todW = 8 // "15:04:05" 的显示宽度
	header := tableRow([]string{
		padWidth("IP", ipW),
		padLeftWidth("失败", failW), padLeftWidth("成功", accW), padLeftWidth("无效", invW),
		padWidth("尝试用户名（前5）", userW),
		padWidth("首次", todW), "末次",
	})
	for di, d := range shown {
		if di > 0 {
			fmt.Println()
		}
		dayTitle := cBold(d)
		for _, ds := range days[di] {
			if ds.Accepted > 0 {
				dayTitle = cBold(cGreen(d))
				break
			}
		}
		fmt.Println(dayTitle)
		fmt.Println(header)
		for _, ds := range days[di] {
			users := "-"
			if ds.Users.length() > 0 {
				users = topUsernames(ds.Users, 5)
			}
			accCell := padLeftWidth(strconv.Itoa(ds.Accepted), accW)
			if ds.Accepted > 0 {
				accCell = cGreen(accCell) // 有成功登录的行，成功次数标绿
			}
			fmt.Println(tableRow([]string{
				padWidth(ds.IP, ipW),
				padLeftWidth(strconv.Itoa(ds.Failed), failW),
				accCell,
				padLeftWidth(strconv.Itoa(ds.Invalid), invW),
				padWidth(truncateWidth(users, userW), userW),
				padWidth(fmtTimeOfDay(ds.First), todW), fmtTimeOfDay(ds.Last),
			}))
		}
		if len(byDate[d]) > len(days[di]) {
			fmt.Println("……")
		}
	}
	if len(dateSeq) > len(shown) {
		fmt.Println()
		fmt.Println("……")
	}
}

// ==================== 二进制日志各节 ====================

func printBtmpSection(list []*btmpStats) {
	for _, b := range list {
		secTitle(fmt.Sprintf("--- btmp 失败登录（%s）---", filepath.Base(b.File)))
		if b.Fails == 0 {
			fmt.Println("无失败登录记录")
			continue
		}
		fmt.Printf("失败记录 %d 条，时间跨度 %s ~ %s\n", b.Fails, fmtDT(b.First), fmtDT(b.Last))
		hosts := b.Hosts.mostCommon(10)
		fmt.Println("Top 来源 IP：")
		for _, p := range hosts {
			fmt.Printf("  %-20s %d 次\n", p.k, p.n)
		}
		if b.Hosts.length() > len(hosts) {
			fmt.Println("    （仅显示 Top 10，完整列表见导出）")
		}
		var topUsers []string
		for _, p := range b.Users.mostCommon(5) {
			topUsers = append(topUsers, fmt.Sprintf("%s(%d)", p.k, p.n))
		}
		fmt.Println("尝试用户名 Top5：" + strings.Join(topUsers, "、"))
	}
}

func printWtmpSection(list []*wtmpStats) {
	for _, w := range list {
		secTitle(fmt.Sprintf("--- wtmp 登录会话（%s）---", filepath.Base(w.File)))
		n := len(w.Sessions)
		if n == 0 {
			fmt.Println("无登录会话记录")
			continue
		}
		recent := w.Sessions
		if len(recent) > recentRows {
			recent = recent[len(recent)-recentRows:]
		}
		fmt.Printf("共 %d 次登录会话，系统启动 %d 次；最近 %d 条：\n", n, w.Boots, len(recent))
		for _, s := range recent {
			printWtmpRow(s)
		}
	}
}

func printWtmpRow(s wtmpSession) {
	if s.HasClose {
		mark := ""
		if s.Long {
			mark = cYellow("（超过 24 小时，注意）")
		}
		fmt.Printf("  [%s] %s %s 来自 %s，时长 %s%s\n",
			fmtDT(s.Open), s.User, s.Line, orEmpty(s.Host, "-"), fmtDuration(s.Duration), mark)
	} else {
		note := "，未正常关闭"
		if s.Note != "" {
			note = "，" + s.Note
		}
		fmt.Println(cYellow(fmt.Sprintf("  [%s] %s %s 来自 %s%s",
			fmtDT(s.Open), s.User, s.Line, orEmpty(s.Host, "-"), note)))
	}
}

func printLastlogSection(list []*lastlogStats, backdoorNames map[string]bool) {
	for _, ll := range list {
		secTitle(fmt.Sprintf("--- lastlog 末次登录（%s）---", filepath.Base(ll.File)))
		entries := make([]lastlogEntry, len(ll.Entries))
		copy(entries, ll.Entries)
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
		var shown []lastlogEntry
		for _, e := range entries {
			if e.UID == 0 || e.UID >= 1000 {
				shown = append(shown, e)
			}
		}
		if len(shown) == 0 {
			fmt.Println("无可显示的登录记录")
			continue
		}
		for i, e := range shown {
			if i >= recentRows {
				break
			}
			mark := ""
			if backdoorNames[e.Name] {
				mark = cHRed("  [疑似后门账户]")
			}
			fmt.Printf("  %-16s UID %-6d %s  %s 来自 %s%s\n",
				e.Name, e.UID, fmtDT(e.Time), orEmpty(e.Line, "-"), orEmpty(e.Host, "-"), mark)
		}
		if len(shown) > recentRows {
			fmt.Printf("  （共 %d 条，已省略 %d 条）\n", len(shown), len(shown)-recentRows)
		}
	}
}

// ==================== -a / -f 明细 ====================

func printAcceptedDetail(events []*Event, top int) {
	if len(events) == 0 {
		fmt.Println("\n登录成功明细：无记录")
		return
	}
	counts := methodClasses(events)
	fmt.Println("\n" + cCyan(cBold("=== 登录成功明细 ===")))
	summary := "概要: 共 " + cGreen(fmt.Sprintf("%d", len(events))) + " 条成功登录"
	if counts.length() > 0 {
		var parts []string
		for _, p := range counts.mostCommon(-1) {
			parts = append(parts, fmt.Sprintf("%s %d 条", p.k, p.n))
		}
		summary += "（" + strings.Join(parts, "，") + "）"
	}
	fmt.Println(summary)
	list := events
	if top > 0 && len(events) > top {
		list = events[:top]
	}
	for _, e := range list {
		fmt.Println(cGreen(e.Raw))
	}
	if top > 0 && len(events) > top {
		fmt.Printf("（共 %d 条，已省略 %d 条）\n", len(events), len(events)-top)
	}
}

func printFailedDetail(a *analysis, sources []source, top int) {
	failTotal := sumFailClass(a.eventCounts)
	fmt.Println("\n" + cCyan(cBold("=== 登录失败明细 ===")))
	if failTotal == 0 {
		fmt.Println("无记录")
		return
	}
	sorted := a.sortedProfiles()
	var topLine []string
	taken := 0
	for _, p := range sorted {
		if taken >= 3 {
			break
		}
		taken++
		if p.Failed > 0 {
			topLine = append(topLine, fmt.Sprintf("%s（%d次）", p.IP, p.Failed))
		}
	}
	summary := "概要: 共 " + cRed(fmt.Sprintf("%d", failTotal)) + " 条失败记录"
	if len(topLine) > 0 {
		summary += "，攻击最多: " + strings.Join(topLine, "，")
	}
	fmt.Println(summary)
	if top > 0 {
		fmt.Printf("Top %d 攻击 IP 汇总:\n", top)
		rank := 0
		for _, p := range sorted {
			if rank >= top || p.Failed <= 0 {
				break
			}
			rank++
			fmt.Println(cRed(fmt.Sprintf("%-4d %-18s %6d 次", rank, p.IP, p.Failed)))
		}
		fmt.Println("\n(汇总模式：明细已省略，去掉 --top 查看全部)")
		return
	}
	iterAllEvents(sources, func(ev *Event) {
		if ev.Type == "failed" {
			fmt.Println(cRed(ev.Raw))
		} else if failClass[ev.Type] {
			fmt.Println(cYellow(ev.Raw))
		}
	})
}
