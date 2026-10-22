#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH-Access-Auditor：SSH 日志应急审计工具。

支持 Debian/Ubuntu 的 /var/log/auth.log 与 RHEL/CentOS 的 /var/log/secure。
兼容英文旧格式（sshd[pid]）与中文新格式（sshd-session[pid]，如 Kali 2024+）。
事件覆盖：Accepted、Failed、Invalid user、maximum authentication exceeded、
认证中断（Connection closed / Disconnected by authenticating user）、
session opened/closed、useradd 新建账号与特权组添加。
"""

import argparse
import bisect
import csv
import html
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ==================== 常量 ====================

EN_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
MONTH_ABBR = {v: k for k, v in EN_MONTHS.items()}

# 失败类事件：计入失败统计与爆破计数
FAIL_CLASS = {"failed", "invalid_user", "max_auth", "preauth_close"}

# 特权组：加入即判定为疑似后门账号
PRIV_GROUPS = {"sudo", "wheel", "adm", "admin", "root"}

TIME_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{1,2}月\s*\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
SSH_PREFIX_RE = re.compile(r"sshd(?:-session)?\[(\d+)\]:\s*")

IP_PART = r"(\d{1,3}(?:\.\d{1,3}){3})"
P_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from " + IP_PART + r"(?: port (\d+))?")
P_FAILED = re.compile(
    r"Failed (\S+) for (invalid user ?)?(\S*) from " + IP_PART + r"(?: port (\d+))?"
)
P_INVALID = re.compile(r"Invalid user (\S*) from " + IP_PART + r"(?: port (\d+))?")
P_MAXAUTH = re.compile(
    r"maximum authentication attempts exceeded for (invalid user ?)?(\S*) from "
    + IP_PART
    + r"(?: port (\d+))?"
)
P_PREAUTH_CLOSE = re.compile(
    r"(?:Connection closed by|Disconnected from) authenticating user (\S+) "
    + IP_PART
    + r"(?: port (\d+))?"
)
P_SESSION = re.compile(
    r"pam_unix\(sshd(?:-session)?:session\): session (opened|closed) for user ([^\s(]+)"
)
P_NEWUSER = re.compile(r"useradd\[\d+\]: new user: name=([^,]+), UID=(\d+)")
P_GROUPADD = re.compile(r"(?:useradd|usermod)\[\d+\]: add '([^']+)' to group '([^']+)'")

TYPE_LABEL = {
    "accepted": "登录成功",
    "failed": "认证失败",
    "invalid_user": "无效用户",
    "max_auth": "认证超限",
    "preauth_close": "认证中断",
    "session_open": "会话开启",
    "session_close": "会话关闭",
    "useradd_new": "新建账号",
    "group_add": "组添加",
}

# ==================== CLI ====================


def parse_args():
    examples = """
使用示例:
  1. 生成综合审计报告 (文本):
     python SSH-Access-Auditor.py ./auth.log -o report.txt

  2. 生成 HTML 可视化报告 (按扩展名自动识别):
     python SSH-Access-Auditor.py ./auth.log -o report.html

  3. 筛选登录成功的记录:
     python SSH-Access-Auditor.py ./auth.log -a

  4. 筛选登录失败的记录:
     python SSH-Access-Auditor.py ./auth.log -f

  5. 大日志下只看 Top 10 攻击 IP 汇总:
     python SSH-Access-Auditor.py ./auth.log -f --top 10

  6. 筛选特定时间段内以 password 方式登录的尝试:
     python SSH-Access-Auditor.py ./auth.log -a -f -p -ts "12/24 03:00:00" -te "12/24 23:00:00"

  7. 导出 JSON 与 CSV 事件明细:
     python SSH-Access-Auditor.py ./auth.log --export json,csv

  8. 自定义爆破阈值与时间窗，加载本地 IP 黑名单:
     python SSH-Access-Auditor.py ./auth.log --threshold 20 --window 60 --blacklist iplist.txt

  9. 查看最近 7 天的失败记录:
     python SSH-Access-Auditor.py ./auth.log -f -tr 7
"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples,
        description="SSH 日志应急审计工具：爆破检测、时间窗关联、IP 画像、后门账号检测",
    )
    parser.add_argument("logfile", help="指定要分析的日志文件路径 (例如: ./auth.log)")

    # 屏幕输出（与旧版一致）
    parser.add_argument("-a", "--accepted", action="store_true",
                        help="在屏幕显示认证成功的登录记录及统计信息")
    parser.add_argument("-f", "--failed", action="store_true",
                        help="在屏幕显示认证失败的登录尝试及统计信息")

    # 认证方式过滤（仅影响屏幕输出，报告始终完整画像）
    parser.add_argument("-k", "--key", action="store_true",
                        help="仅在屏幕输出中过滤基于公钥 (publickey) 的认证")
    parser.add_argument("-p", "--password", action="store_true",
                        help="仅在屏幕输出中过滤基于密码 (password) 的认证")
    parser.add_argument("-P", "--pam", action="store_true",
                        help="仅在屏幕输出中过滤基于键盘交互/PAM 的认证")

    # 时间过滤（与旧版一致）
    parser.add_argument("-t", "--time", dest="exact_date",
                        help='按指定日期筛选 (例如: -t "12/23")')
    parser.add_argument("-ts", "--time-start", dest="time_start",
                        help='按起始时间筛选 (例如: -ts "12/23 03:00:00")')
    parser.add_argument("-te", "--time-end", dest="time_end",
                        help='按结束时间筛选 (例如: -te "12/23 23:00:00")')
    parser.add_argument("-tr", "--time-recent", dest="time_recent", type=int,
                        help="显示最近 X 天的记录 (例如: -tr 7 显示近 7 天)")

    # 报告与导出
    parser.add_argument("-o", "--output", dest="outfile",
                        help="生成审计报告并输出到指定文件（.html 后缀自动生成 HTML 报告）")
    parser.add_argument("--export", dest="export", default=None,
                        help="导出结构化事件，格式 json 或 csv，逗号分隔可复选 (例如: --export json,csv)")
    parser.add_argument("--top", dest="top", type=int, default=None,
                        help="汇总模式：失败明细只显示 Top N 攻击 IP (例如: --top 10)")
    parser.add_argument("--threshold", dest="threshold", type=int, default=10,
                        help="爆破判定阈值：失败类次数超过该值判定为爆破 (默认 10)")
    parser.add_argument("--window", dest="window", type=int, default=30,
                        help="爆破成功关联窗口：成功登录前 N 分钟内失败达到阈值即高危 (默认 30)")
    parser.add_argument("--blacklist", dest="blacklist", default=None,
                        help="本地 IP 黑名单文件，每行一个 IP 或 CIDR，命中在报告中高亮")
    parser.add_argument("--no-color", dest="no_color", action="store_true",
                        help="关闭颜色输出")

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold 必须 >= 1")
    if args.window < 1:
        parser.error("--window 必须 >= 1")
    if args.top is not None and args.top < 1:
        parser.error("--top 必须 >= 1")
    if args.export:
        fmts = [x.strip().lower() for x in args.export.split(",") if x.strip()]
        bad = [x for x in fmts if x not in ("json", "csv")]
        if bad:
            parser.error(f"不支持的导出格式: {', '.join(bad)}（可选 json、csv）")
        args.export = fmts
    return args


# ==================== 工具函数 ====================

USE_COLOR = False


def init_color(no_color):
    global USE_COLOR
    if no_color:
        USE_COLOR = False
        return
    if not sys.stdout.isatty():
        USE_COLOR = False
        return
    if os.name == "nt":
        os.system("")  # 触发 Windows 控制台启用 VT 转义序列
    USE_COLOR = True


def _c(text, code):
    if USE_COLOR:
        return f"\x1b[{code}m{text}\x1b[0m"
    return text


def c_green(t):
    return _c(t, "32")


def c_red(t):
    return _c(t, "31")


def c_yellow(t):
    return _c(t, "33")


def c_hred(t):
    return _c(t, "91")


def c_cyan(t):
    return _c(t, "36")


def c_bold(t):
    return _c(t, "1")


def fmt_date(dt):
    """统一日期显示，规避 strftime 的本地化差异，如 Feb 11。"""
    return f"{MONTH_ABBR[dt.month]} {dt.day}"


def fmt_dt(dt):
    return f"{fmt_date(dt)} {dt.strftime('%H:%M:%S')}"


def parse_user_time(t_str, is_exact_date=False):
    """解析命令行输入时间，统一以 1900 年为基准年；手工解析避免 strptime 缺省年份的弃用告警。"""
    if is_exact_date:
        m = re.match(r"^(\d{1,2})/(\d{1,2})$", t_str)
        if m:
            try:
                return datetime(1900, int(m.group(1)), int(m.group(2)))
            except ValueError:
                pass
    else:
        m = re.match(r"^(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$", t_str)
        if m:
            try:
                return datetime(1900, int(m.group(1)), int(m.group(2)),
                                int(m.group(3)), int(m.group(4)), int(m.group(5)))
            except ValueError:
                pass
    print(f"错误: 时间格式不正确 '{t_str}'，应为 \"月/日\" 或 \"月/日 时:分:秒\"")
    sys.exit(1)


def parse_log_time(t_str):
    """解析日志时间戳，支持英文 Feb 11 与中文 2月 11 两种格式，返回 1900 基准年。"""
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", t_str)
    if m and m.group(1) in EN_MONTHS:
        month, day = EN_MONTHS[m.group(1)], int(m.group(2))
    else:
        m = re.match(r"^(\d{1,2})月\s*(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", t_str)
        if not m:
            return None
        month, day = int(m.group(1)), int(m.group(2))
    try:
        return datetime(1900, month, day, int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None


def read_log_text(path):
    """按 UTF-8 优先、GBK 回退读取日志，两档均失败则显式报错，不掩盖损坏。"""
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    print(f"错误: 无法解码日志文件 '{path}'（已尝试 UTF-8 与 GBK）")
    sys.exit(1)


def fmt_duration(td):
    """会话时长的人读格式。"""
    total = int(td.total_seconds())
    if total < 60:
        return f"{total} 秒"
    if total < 3600:
        return f"{total // 60} 分钟"
    if total < 86400:
        return f"{total // 3600} 小时 {total % 3600 // 60} 分"
    return f"{total // 86400} 天 {total % 86400 // 3600} 小时"


def top_usernames(users_counter, limit=5):
    """按出现频次取前 N 个用户名，超出部分以等 N 个收尾。"""
    common = users_counter.most_common(limit)
    names = [u for u, _ in common]
    suffix = f" 等{len(users_counter)}个" if len(users_counter) > limit else ""
    return "、".join(names) + suffix


# ==================== 解析层 ====================


def make_event(ev_type, dt, raw, user=None, ip=None, port=None, method=None,
               invalid=False, pid=None, uid=None, group=None):
    return {
        "type": ev_type,
        "time": dt,
        "date": fmt_date(dt),
        "time_str": dt.strftime("%H:%M:%S"),
        "user": user,
        "ip": ip,
        "port": int(port) if port else None,
        "method": method,
        "invalid": invalid,
        "pid": pid,
        "uid": uid,
        "group": group,
        "raw": raw,
    }


def parse_line(line):
    """把一行日志解析为事件字典，未命中任何已知模式时返回 None。"""
    tm = TIME_RE.match(line)
    if not tm:
        return None
    dt = parse_log_time(tm.group(1))
    if not dt:
        return None

    if "useradd" in line or "usermod" in line:
        m = P_NEWUSER.search(line)
        if m:
            return make_event("useradd_new", dt, line, user=m.group(1).strip(),
                              uid=int(m.group(2)))
        m = P_GROUPADD.search(line)
        if m:
            return make_event("group_add", dt, line, user=m.group(1), group=m.group(2))
        return None

    if "sshd" not in line:
        return None
    pm = SSH_PREFIX_RE.search(line)
    pid = pm.group(1) if pm else None
    rest = line[pm.end():] if pm else line

    if "session opened" in rest or "session closed" in rest:
        m = P_SESSION.search(rest)
        if m:
            ev_type = "session_open" if m.group(1) == "opened" else "session_close"
            return make_event(ev_type, dt, line, user=m.group(2), pid=pid)
        return None

    m = P_ACCEPT.search(rest)
    if m:
        return make_event("accepted", dt, line, user=m.group(2), ip=m.group(3),
                          port=m.group(4), method=m.group(1), pid=pid)

    m = P_FAILED.search(rest)
    if m:
        return make_event("failed", dt, line, user=m.group(3) or "(空)",
                          ip=m.group(4), port=m.group(5), method=m.group(1),
                          invalid=bool(m.group(2)), pid=pid)

    m = P_INVALID.search(rest)
    if m:
        return make_event("invalid_user", dt, line, user=m.group(1) or "(空)",
                          ip=m.group(2), port=m.group(3), invalid=True, pid=pid)

    m = P_MAXAUTH.search(rest)
    if m:
        return make_event("max_auth", dt, line, user=m.group(2) or "(空)",
                          ip=m.group(3), port=m.group(4),
                          invalid=bool(m.group(1)), pid=pid)

    m = P_PREAUTH_CLOSE.search(rest)
    if m:
        return make_event("preauth_close", dt, line, user=m.group(1),
                          ip=m.group(2), port=m.group(3), pid=pid)

    return None


def parse_logfile(path):
    """读入日志并解析全部事件，保持文件原始顺序。返回 (事件列表, 实际编码)。"""
    text, enc = read_log_text(path)
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        ev = parse_line(line)
        if ev:
            events.append(ev)
    return events, enc


def apply_time_filters(events, args):
    """对全部事件统一应用时间过滤，-tr 基于日志内最大时间单遍完成。"""
    target_date = parse_user_time(args.exact_date, is_exact_date=True) if args.exact_date else None
    start_time = parse_user_time(args.time_start) if args.time_start else None
    end_time = parse_user_time(args.time_end) if args.time_end else None

    max_time = None
    if args.time_recent:
        for ev in events:
            if max_time is None or ev["time"] > max_time:
                max_time = ev["time"]

    recent_delta = timedelta(days=args.time_recent) if args.time_recent else None
    kept = []
    for ev in events:
        t = ev["time"]
        if target_date and (t.month, t.day) != (target_date.month, target_date.day):
            continue
        if start_time and t < start_time:
            continue
        if end_time and t > end_time:
            continue
        if recent_delta and max_time and (max_time - t) > recent_delta:
            continue
        kept.append(ev)
    return kept


# ==================== 统计层 ====================


def load_blacklist(path):
    """加载本地 IP 黑名单，每行一个 IP 或 CIDR，非法行警告并跳过。"""
    nets = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for no, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                print(f"警告: 黑名单第 {no} 行无法解析，已跳过: {s}")
    return nets


def ip_in_blacklist(ip, nets):
    if not nets or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def analyze(events, args, blacklist_nets):
    """基于过滤后事件产出全部统计结果。"""
    profiles = {}

    def prof(ip):
        p = profiles.get(ip)
        if p is None:
            p = {
                "ip": ip, "failed": 0, "accepted": 0, "invalid": 0,
                "users": Counter(), "ports": set(), "first": None, "last": None,
            }
            profiles[ip] = p
        return p

    for ev in events:
        t = ev["type"]
        if t in ("session_open", "session_close", "useradd_new", "group_add"):
            continue
        if ev["ip"] is None:
            continue
        p = prof(ev["ip"])
        if t in FAIL_CLASS:
            p["failed"] += 1
            if t == "invalid_user":
                p["invalid"] += 1
        elif t == "accepted":
            p["accepted"] += 1
        if ev["user"]:
            p["users"][ev["user"]] += 1
        if ev["port"]:
            p["ports"].add(ev["port"])
        if p["first"] is None or ev["time"] < p["first"]:
            p["first"] = ev["time"]
        if p["last"] is None or ev["time"] > p["last"]:
            p["last"] = ev["time"]

    # 爆破 IP：失败类合计超过阈值
    brute_ips = {
        ip: p["failed"] for ip, p in profiles.items() if p["failed"] > args.threshold
    }

    # 时间窗关联：成功登录前 window 分钟内，同 IP 失败类事件达到阈值，判定疑似爆破成功
    fail_times = defaultdict(list)
    for ev in events:
        if ev["type"] in FAIL_CLASS:
            fail_times[ev["ip"]].append(ev["time"])
    for times in fail_times.values():
        times.sort()

    window = timedelta(minutes=args.window)
    suspected = []
    for ev in events:
        if ev["type"] != "accepted":
            continue
        times = fail_times.get(ev["ip"])
        if not times:
            continue
        lo = bisect.bisect_left(times, ev["time"] - window)
        hi = bisect.bisect_left(times, ev["time"])
        if hi - lo >= args.threshold:
            suspected.append({
                "ip": ev["ip"], "user": ev["user"], "time": ev["time"],
                "date": ev["date"], "time_str": ev["time_str"],
                "window_fails": hi - lo, "method": ev["method"],
            })

    # 会话配对：同一 sshd-session 进程号内 opened 与 closed 配对
    open_by_pid, close_by_pid = {}, {}
    for ev in events:
        if ev["type"] == "session_open" and ev["pid"] not in open_by_pid:
            open_by_pid[ev["pid"]] = ev
        elif ev["type"] == "session_close" and ev["pid"] not in close_by_pid:
            close_by_pid[ev["pid"]] = ev
    sessions = []
    for pid, o in open_by_pid.items():
        c = close_by_pid.get(pid)
        dur = (c["time"] - o["time"]) if c else None
        sessions.append({
            "pid": pid, "user": o["user"], "open": o["time"],
            "close": c["time"] if c else None,
            "duration": dur, "long": dur is not None and dur > timedelta(hours=24),
        })
    sessions.sort(key=lambda s: s["open"])

    # useradd 后门检测：UID 0 或加入特权组
    new_users, group_adds = {}, defaultdict(list)
    for ev in events:
        if ev["type"] == "useradd_new":
            new_users.setdefault(ev["user"], ev)
        elif ev["type"] == "group_add" and ev["group"] in PRIV_GROUPS:
            group_adds[ev["user"]].append(ev)
    backdoors = []
    for name, ev in new_users.items():
        priv = group_adds.get(name, [])
        uid0 = ev.get("uid") == 0
        if uid0 or priv:
            backdoors.append({
                "user": name, "uid": ev.get("uid"), "created": ev["time"],
                "groups": [(g["group"], g["time"]) for g in priv], "uid0": uid0,
            })
    backdoors.sort(key=lambda b: b["created"])

    # 异常端口：成功登录端口非 22
    abnormal_ports = [
        ev for ev in events
        if ev["type"] == "accepted" and ev["port"] and ev["port"] != 22
    ]

    # 黑名单命中
    blacklist_hits = sorted(
        (ip for ip in profiles if ip_in_blacklist(ip, blacklist_nets)),
        key=lambda ip: profiles[ip]["failed"], reverse=True,
    )

    return {
        "profiles": profiles,
        "brute_ips": brute_ips,
        "suspected": suspected,
        "sessions": sessions,
        "backdoors": backdoors,
        "abnormal_ports": abnormal_ports,
        "blacklist_hits": blacklist_hits,
    }


def method_classes(events):
    """按认证方式归类计数，keyboard-interactive 前缀一律归入 PAM 类。"""
    counts = Counter()
    for ev in events:
        m = ev["method"] or ""
        if m.startswith("keyboard-interactive"):
            counts["keyboard-interactive/PAM"] += 1
        elif m:
            counts[m] += 1
    return counts


def method_selected(ev, sel):
    """认证方式筛选谓词：sel 为 None 表示不筛选。"""
    if sel is None:
        return True
    m = ev["method"] or ""
    if "pam" in sel and m.startswith("keyboard-interactive"):
        return True
    return m in sel


def build_method_selector(args):
    sel = []
    if args.key:
        sel.append("publickey")
    if args.password:
        sel.append("password")
    if args.pam:
        sel.append("pam")
    return sel if sel else None


# ==================== 输出层：终端 ====================


def render_accepted(events, args, analysis):
    sel = build_method_selector(args)
    shown = [e for e in events if method_selected(e, sel)]
    counts = method_classes(shown)

    print("\n" + c_cyan(c_bold("=================================== 登录成功 ===================================")))
    summary = "概要: 共 " + c_green(str(len(shown))) + " 条成功登录"
    if counts:
        summary += "（" + "，".join(f"{k} {v} 条" for k, v in counts.most_common()) + "）"
    print(summary)
    abnormal = [e for e in analysis["abnormal_ports"] if method_selected(e, sel)]
    if abnormal:
        ports = "，".join(sorted({str(e["port"]) for e in abnormal}))
        print(c_yellow(f"提示: 存在非 22 端口的成功登录（端口 {ports}），注意隐藏服务可能"))

    print("明细:")
    limit = args.top
    for e in shown[:limit] if limit else shown:
        print(c_green(e["raw"]))
    if limit and len(shown) > limit:
        print(f"... 其余 {len(shown) - limit} 条已省略")

    cond = "Accepted" + ("" if sel is None else " " + ", ".join(sel))
    print(f"\n总计: {len(shown)} 条成功的 SSH 登录记录 (过滤条件: {cond})\n")

    method_map = {"password": "password", "publickey": "publicKey"}
    for raw_method, zh in method_map.items():
        group = [e for e in shown if e["method"] == raw_method]
        if not group:
            continue
        print(f"基于 {zh} 登录的共 {len(group)} 条：")
        _print_date_user_group(group)
    pam_group = [e for e in shown if (e["method"] or "").startswith("keyboard-interactive")]
    if pam_group:
        print(f"基于 键盘PAM交互 登录的共 {len(pam_group)} 条：")
        _print_date_user_group(pam_group)
    print("")


def _print_date_user_group(events):
    """按日期分组后输出 [时间] IP 用户 行。"""
    groups = defaultdict(list)
    for e in events:
        groups[e["date"]].append(e)
    for d in sorted(groups, key=lambda s: (EN_MONTHS[s.split()[0]], int(s.split()[1]))):
        print(f"{d}：")
        for e in groups[d]:
            print(f"[{e['time_str']}] {e['ip']} {e['user']}")
    print("")


def render_failed(events, args, analysis):
    sel = build_method_selector(args)
    fail_events = [e for e in events if e["type"] in FAIL_CLASS]
    shown_fail = [e for e in fail_events if method_selected(e, sel)]
    by_type = Counter(e["type"] for e in shown_fail)
    profiles = analysis["profiles"]

    print("\n" + c_cyan(c_bold("=================================== 登录失败 ===================================")))

    top_ips = sorted(
        profiles.items(), key=lambda kv: kv[1]["failed"], reverse=True
    )
    top_line = "，".join(
        f"{ip}（{p['failed']}次）" for ip, p in top_ips[:3] if p["failed"] > 0
    )
    summary = "概要: 共 " + c_red(str(len(shown_fail))) + " 条失败类记录"
    if top_line:
        summary += "，攻击最多: " + top_line
    print(summary)

    if not args.accepted:
        print(f"--- SSH日志分析结果 ({args.logfile}) ---")

    if args.top:
        print(f"Top {args.top} 攻击 IP 汇总 (按全部失败类计数排序，不受 -k/-p/-P 影响):")
        print(f"{'排名':<4} {'IP':<18} {'失败':>6} {'用户名数':>8} {'首次出现':>18} {'末次出现':>18}")
        for rank, (ip, p) in enumerate(top_ips[: args.top], 1):
            print(c_red(f"{rank:<4} {ip:<18} {p['failed']:>6} {len(p['users']):>8} "
                        f"{fmt_dt(p['first']):>18} {fmt_dt(p['last']):>18}"))
        print("\n(汇总模式：明细已省略，去掉 --top 查看全部)")
    else:
        for e in shown_fail:
            if e["type"] == "failed":
                print(c_red(e["raw"]))
            else:
                print(c_yellow(e["raw"]))

    cond = "Failed" + ("" if sel is None else " " + ", ".join(sel))
    print(
        f"\n总计: {len(shown_fail)} 条失败类记录 "
        f"(Failed {by_type.get('failed', 0)} / Invalid user {by_type.get('invalid_user', 0)} / "
        f"认证超限 {by_type.get('max_auth', 0)} / 认证中断 {by_type.get('preauth_close', 0)}) "
        f"(过滤条件: {cond})"
    )

    if not args.top:
        date_ip_counts = defaultdict(lambda: defaultdict(int))
        for e in shown_fail:
            date_ip_counts[e["date"]][e["ip"]] += 1
        for d in sorted(date_ip_counts,
                        key=lambda s: (EN_MONTHS[s.split()[0]], int(s.split()[1]))):
            print(f"{d}：")
            for ip, count in sorted(date_ip_counts[d].items(), key=lambda x: x[1], reverse=True):
                print(f"{ip} - {count} 次")
            print("")
    print("")


def render_overview(events, analysis, args):
    """无 -a/-f/-o/--export 时的默认精简概要。"""
    by_type = Counter(e["type"] for e in events)
    print(c_cyan(c_bold(f"=== SSH 日志概要: {args.logfile} ===")))
    if not events:
        print("未解析到任何已知 SSH 事件，请确认日志格式。")
        return
    print(f"登录成功 {by_type.get('accepted', 0)} 条，失败类 {sum(by_type[t] for t in FAIL_CLASS)} 条"
          f"（Failed {by_type.get('failed', 0)} / Invalid user {by_type.get('invalid_user', 0)} / "
          f"认证超限 {by_type.get('max_auth', 0)} / 认证中断 {by_type.get('preauth_close', 0)}）")
    print(f"时间跨度: {fmt_dt(events[0]['time'])} ~ {fmt_dt(events[-1]['time'])}")
    _print_conclusion_block(analysis, args)
    print("提示: 使用 -h 查看全部功能；-a/-f 查看成功/失败明细；-o 生成报告")


def _print_conclusion_block(analysis, args):
    """总体结论：爆破 IP、高危爆破成功、黑名单、后门账号、异常端口。"""
    brute = analysis["brute_ips"]
    if brute:
        s = "，".join(f"{ip}（{n}次）" for ip, n in sorted(brute.items(), key=lambda x: x[1], reverse=True))
        print(c_red(f"存在爆破行为的 IP（失败 > {args.threshold} 次）：{s}"))
    else:
        print(f"存在爆破行为的 IP（失败 > {args.threshold} 次）：无")

    suspected = analysis["suspected"]
    if suspected:
        for h in suspected:
            print(c_hred(f"高危·疑似爆破成功：{h['ip']} 用户 {h['user']} 于 [{h['time_str']} {h['date']}] 成功登录，"
                         f"此前 {args.window} 分钟内该 IP 失败 {h['window_fails']} 次"))
    else:
        print("疑似爆破成功的 IP（时间窗关联）：无")

    hits = analysis["blacklist_hits"]
    print(f"黑名单命中：{'，'.join(hits) if hits else '无'}")

    backdoors = analysis["backdoors"]
    if backdoors:
        for b in backdoors:
            groups = "、".join(g for g, _ in b["groups"])
            reason = "UID 为 0" if b["uid0"] else f"加入特权组 {groups}"
            print(c_hred(f"疑似后门账号：{b['user']}（UID {b['uid']}，创建于 {fmt_dt(b['created'])}，{reason}）"))
    else:
        print("疑似后门账号：无")

    abnormal = analysis["abnormal_ports"]
    if abnormal:
        s = "，".join(f"[{fmt_dt(e['time'])}] {e['ip']} {e['user']} 端口 {e['port']}" for e in abnormal)
        print(c_yellow(f"异常端口成功登录（非 22）：{s}"))
    else:
        print("异常端口成功登录（非 22）：无")


# ==================== 输出层：文本报告 ====================


def render_report_txt(events, analysis, args, outfile):
    """生成文本版综合审计报告。"""
    lines = []
    by_type = Counter(e["type"] for e in events)
    lines.append("==================== SSH 访问审计报告 ====================")
    lines.append(f"日志文件: {args.logfile}")
    if events:
        lines.append(f"时间跨度: {fmt_dt(events[0]['time'])} ~ {fmt_dt(events[-1]['time'])}")
        if events[-1]["time"].month < events[0]["time"].month:
            lines.append("注意: 日志月份出现回落，可能跨年，时间线按月日排序，请人工核对年份")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("一、总体结论")
    _append_conclusion_lines(lines, analysis, args)
    lines.append("")
    _append_profile_lines(lines, analysis)
    lines.append("")
    _append_timeline_lines(lines, events, analysis)
    lines.append("")
    lines.append("四、计数口径说明")
    lines.append(f"- 失败统计包含认证失败、无效用户、认证超限、认证中断四类，合计 {sum(by_type[t] for t in FAIL_CLASS)} 条")
    lines.append("- 认证中断类事件（Connection closed / Disconnected by authenticating user）计入统计，明细不逐条展示")
    lines.append(f"- 爆破判定阈值: 失败类次数 > {args.threshold}（--threshold 可调）")
    lines.append(f"- 爆破成功关联窗口: 成功登录前 {args.window} 分钟内失败达到阈值（--window 可调）")

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"综合排查报告已成功生成至: {outfile}")


def _append_conclusion_lines(lines, analysis, args):
    """报告第一节：与旧版前两行保持同一措辞。"""
    brute = analysis["brute_ips"]
    if brute:
        s = "，".join(f"{ip}（{n}次）" for ip, n in sorted(brute.items(), key=lambda x: x[1], reverse=True))
        lines.append(f"存在爆破行为的 IP：{s}")
    else:
        lines.append(f"存在爆破行为的 IP：无")

    suspected = analysis["suspected"]
    if suspected:
        ips = "，".join(sorted({h["ip"] for h in suspected}))
        lines.append(f"疑似爆破成功的 IP（时间窗关联）：{ips}")
        for h in suspected:
            lines.append(f"  命中详情: [{h['date']} {h['time_str']}] 用户 {h['user']} 经 {h['method']} 成功登录，"
                         f"此前 {args.window} 分钟内该 IP 失败 {h['window_fails']} 次")
    else:
        lines.append("疑似爆破成功的 IP：无")

    lines.append(f"黑名单命中：{'，'.join(analysis['blacklist_hits']) if analysis['blacklist_hits'] else '无'}")

    if analysis["backdoors"]:
        lines.append("疑似后门账号：")
        for b in analysis["backdoors"]:
            groups = "、".join(f"{g}（{fmt_dt(t)}）" for g, t in b["groups"])
            reason = "UID 为 0，root 级后门" if b["uid0"] else f"加入特权组 {groups}"
            lines.append(f"  {b['user']}（UID {b['uid']}）创建于 {fmt_dt(b['created'])}，{reason}")
    else:
        lines.append("疑似后门账号：无")

    if analysis["abnormal_ports"]:
        lines.append("异常端口成功登录（非 22）：")
        for e in analysis["abnormal_ports"]:
            lines.append(f"  [{e['date']} {e['time_str']}] {e['ip']} {e['user']} 端口 {e['port']}（{e['method']}）")
    else:
        lines.append("异常端口成功登录（非 22）：无")


def _append_profile_lines(lines, analysis):
    """报告第二节：IP 画像表。"""
    lines.append("二、IP 画像（按失败次数降序，Top 20）")
    profiles = sorted(analysis["profiles"].items(), key=lambda kv: kv[1]["failed"], reverse=True)
    if not profiles:
        lines.append("无")
        return
    header = (f"{'IP':<16}{'失败':>6}{'成功':>6}{'无效用户':>8}  "
              f"{'尝试用户名（前5）':<28}{'首次出现':>18}{'末次出现':>18}")
    lines.append(header)
    for ip, p in profiles[:20]:
        users = top_usernames(p["users"]) if p["users"] else "-"
        lines.append(
            f"{ip:<16}{p['failed']:>6}{p['accepted']:>6}{p['invalid']:>8}  "
            f"{users:<28}{fmt_dt(p['first']):>18} {fmt_dt(p['last']):>18}"
        )


def _append_timeline_lines(lines, events, analysis):
    """报告第三节：按日时间线，成功明细、失败统计、会话。"""
    lines.append("三、按日时间线")
    acc_by_date = defaultdict(list)
    fail_by_date = defaultdict(list)
    sessions_by_date = defaultdict(list)
    for e in events:
        if e["type"] == "accepted":
            acc_by_date[e["date"]].append(e)
        elif e["type"] in FAIL_CLASS:
            fail_by_date[e["date"]].append(e)
    for s in analysis["sessions"]:
        sessions_by_date[fmt_date(s["open"])].append(s)

    all_dates = sorted(
        set(acc_by_date) | set(fail_by_date) | set(sessions_by_date),
        key=lambda s: (EN_MONTHS[s.split()[0]], int(s.split()[1])),
    )
    if not all_dates:
        lines.append("无")
        return
    for d in all_dates:
        lines.append(d)
        lines.append("登录成功的记录")
        if d in acc_by_date:
            for e in acc_by_date[d]:
                lines.append(f"[{e['time_str']}] {e['ip']} {e['user']}（{e['method']}）")
        else:
            lines.append("无")
        lines.append("")
        lines.append("登录失败的记录")
        if d in fail_by_date:
            day_fails = Counter(e["ip"] for e in fail_by_date[d])
            for ip, n in day_fails.most_common():
                lines.append(f"{ip} - {n} 次")
        else:
            lines.append("无")
        lines.append("")
        if d in sessions_by_date:
            lines.append("会话记录")
            for s in sessions_by_date[d]:
                if s["close"]:
                    dur = fmt_duration(s["duration"])
                    mark = "（超过 24 小时，注意）" if s["long"] else ""
                    lines.append(f"[{s['open'].strftime('%H:%M:%S')} ~ {s['close'].strftime('%H:%M:%S')}] "
                                 f"{s['user']}（时长 {dur}）{mark}")
                else:
                    lines.append(f"[{s['open'].strftime('%H:%M:%S')} 开启] {s['user']}（未正常关闭）")
            lines.append("")


# ==================== 输出层：HTML 报告 ====================

HTML_CSS = """
body{font-family:"Microsoft YaHei",system-ui,sans-serif;max-width:1100px;margin:24px auto;
color:#1f2933;background:#f5f6f7;padding:0 16px}
h1{font-size:22px}h2{font-size:17px;border-left:4px solid #2563eb;padding-left:9px;margin-top:30px}
.card{display:inline-block;background:#fff;border-radius:8px;padding:14px 22px;margin:6px 9px 6px 0;
box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:130px;vertical-align:top}
.card .num{font-size:26px;font-weight:700}.card .lbl{font-size:13px;color:#6b7280}
.badge{display:inline-block;border-radius:4px;padding:1px 8px;font-size:12px;color:#fff;white-space:nowrap}
.b-green{background:#16a34a}.b-red{background:#dc2626}.b-amber{background:#d97706}
.b-gray{background:#6b7280}.b-cyan{background:#0891b2}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin-top:9px}
th,td{border:1px solid #e5e7eb;padding:5px 9px;text-align:left}
th{background:#f3f4f6}
.bar-row{display:flex;align-items:center;margin:5px 0}
.bar-label{width:150px;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;background:#eef1f4;border-radius:4px}
.bar-fill{height:16px;background:#dc2626;border-radius:4px;min-width:3px}
.bar-num{width:80px;text-align:right;font-size:13px}
.panel{background:#fff;border-radius:8px;padding:12px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.high{color:#dc2626;font-weight:700}.amber{color:#d97706;font-weight:700}
.meta{color:#6b7280;font-size:13px}ul.notes{font-size:13px;color:#4b5563}
"""


def render_report_html(events, analysis, args, outfile):
    """生成单文件 HTML 报告，内嵌 CSS，无外部依赖，离线可打开。"""
    by_type = Counter(e["type"] for e in events)
    fail_total = sum(by_type[t] for t in FAIL_CLASS)
    esc = html.escape
    parts = []
    parts.append("<!DOCTYPE html><html lang=\"zh\"><head><meta charset=\"utf-8\">")
    parts.append("<title>SSH 访问审计报告</title>")
    parts.append(f"<style>{HTML_CSS}</style></head><body>")
    parts.append("<h1>SSH 访问审计报告</h1>")
    span = (f"{fmt_dt(events[0]['time'])} ~ {fmt_dt(events[-1]['time'])}" if events else "无事件")
    cross = ""
    if events and events[-1]["time"].month < events[0]["time"].month:
        cross = "（日志月份回落，可能跨年，请人工核对）"
    parts.append(f"<p class=\"meta\">日志文件: {esc(args.logfile)}　时间跨度: {esc(span)}{esc(cross)}　"
                 f"生成时间: {esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>")

    n_brute = len(analysis["brute_ips"])
    n_high = len(analysis["suspected"])
    cards = [
        ("登录成功", by_type.get("accepted", 0), "b-green"),
        ("失败类合计", fail_total, "b-red"),
        ("爆破 IP", n_brute, "b-amber" if n_brute else "b-gray"),
        ("疑似爆破成功", n_high, "b-red" if n_high else "b-gray"),
        ("后门账号", len(analysis["backdoors"]), "b-red" if analysis["backdoors"] else "b-gray"),
        ("黑名单命中", len(analysis["blacklist_hits"]), "b-amber" if analysis["blacklist_hits"] else "b-gray"),
    ]
    parts.append("<div>")
    for lbl, num, cls in cards:
        parts.append(f"<div class=\"card\"><div class=\"num\">{num}</div>"
                     f"<div class=\"lbl\">{lbl}</div><div class=\"badge {cls}\">{lbl}</div></div>")
    parts.append("</div>")

    if analysis["suspected"]:
        parts.append("<h2>高危：疑似爆破成功（时间窗关联）</h2><div class=\"panel\">")
        for h in analysis["suspected"]:
            parts.append(f"<p class=\"high\">{esc(h['ip'])} 用户 {esc(h['user'])} 于 "
                         f"[{esc(h['date'])} {esc(h['time_str'])}] 成功登录，"
                         f"此前 {args.window} 分钟内该 IP 失败 {h['window_fails']} 次</p>")
        parts.append("</div>")

    brute_sorted = sorted(analysis["brute_ips"].items(), key=lambda x: x[1], reverse=True)[:15]
    if brute_sorted:
        parts.append("<h2>爆破 IP 排行（失败类次数，Top 15）</h2><div class=\"panel\">")
        peak = brute_sorted[0][1]
        for ip, n in brute_sorted:
            w = max(int(n / peak * 100), 2)
            parts.append(f"<div class=\"bar-row\"><div class=\"bar-label\">{esc(ip)}</div>"
                         f"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{w}%\"></div></div>"
                         f"<div class=\"bar-num\">{n} 次</div></div>")
        parts.append("</div>")

    if analysis["backdoors"]:
        parts.append("<h2>疑似后门账号</h2><table><tr><th>用户</th><th>UID</th><th>创建时间</th>"
                     "<th>判定依据</th></tr>")
        for b in analysis["backdoors"]:
            reason = "UID 为 0，root 级后门" if b["uid0"] else \
                "加入特权组 " + esc("、".join(g for g, _ in b["groups"]))
            parts.append(f"<tr><td class=\"high\">{esc(b['user'])}</td><td>{b['uid']}</td>"
                         f"<td>{esc(fmt_dt(b['created']))}</td><td>{reason}</td></tr>")
        parts.append("</table>")

    if analysis["blacklist_hits"]:
        parts.append("<h2>黑名单命中</h2><table><tr><th>IP</th><th>失败类次数</th><th>成功次数</th></tr>")
        for ip in analysis["blacklist_hits"]:
            p = analysis["profiles"][ip]
            parts.append(f"<tr><td class=\"high\">{esc(ip)}</td><td>{p['failed']}</td>"
                         f"<td>{p['accepted']}</td></tr>")
        parts.append("</table>")

    if analysis["abnormal_ports"]:
        parts.append("<h2>异常端口成功登录（非 22）</h2><table><tr><th>时间</th><th>IP</th>"
                     "<th>用户</th><th>端口</th><th>方式</th></tr>")
        for e in analysis["abnormal_ports"]:
            parts.append(f"<tr><td>[{esc(e['date'])} {esc(e['time_str'])}]</td><td>{esc(e['ip'])}</td>"
                         f"<td>{esc(e['user'])}</td><td class=\"amber\">{e['port']}</td>"
                         f"<td>{esc(e['method'])}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>IP 画像（按失败次数降序，Top 20）</h2>")
    profiles = sorted(analysis["profiles"].items(), key=lambda kv: kv[1]["failed"], reverse=True)
    if profiles:
        parts.append("<table><tr><th>IP</th><th>失败</th><th>成功</th><th>无效用户</th>"
                     "<th>尝试用户名（前5）</th><th>首次出现</th><th>末次出现</th></tr>")
        for ip, p in profiles[:20]:
            users = esc(top_usernames(p["users"])) if p["users"] else "-"
            parts.append(f"<tr><td>{esc(ip)}</td><td>{p['failed']}</td><td>{p['accepted']}</td>"
                         f"<td>{p['invalid']}</td><td>{users}</td><td>{esc(fmt_dt(p['first']))}</td>"
                         f"<td>{esc(fmt_dt(p['last']))}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class=\"meta\">无</p>")

    parts.append("<h2>按日时间线</h2>")
    abnormal_keys = {(e["time_str"], e["ip"], e["user"]) for e in analysis["abnormal_ports"]}
    acc_by_date, fail_by_date = defaultdict(list), defaultdict(list)
    for e in events:
        if e["type"] == "accepted":
            acc_by_date[e["date"]].append(e)
        elif e["type"] in FAIL_CLASS:
            fail_by_date[e["date"]].append(e)
    all_dates = sorted(
        set(acc_by_date) | set(fail_by_date),
        key=lambda s: (EN_MONTHS[s.split()[0]], int(s.split()[1])),
    )
    if not all_dates:
        parts.append("<p class=\"meta\">无</p>")
    for d in all_dates:
        parts.append(f"<h3>{esc(d)}</h3>")
        parts.append("<table><tr><th>时间</th><th>结果</th><th>用户</th><th>IP</th>"
                     "<th>端口</th><th>方式</th></tr>")
        for e in acc_by_date.get(d, []):
            port = e["port"] if e["port"] else ""
            td_cls = " class=\"amber\"" if (e["time_str"], e["ip"], e["user"]) in abnormal_keys else ""
            parts.append(f"<tr><td>{esc(e['time_str'])}</td>"
                         f"<td><span class=\"badge b-green\">成功</span></td>"
                         f"<td>{esc(e['user'])}</td><td>{esc(e['ip'])}</td>"
                         f"<td{td_cls}>{port}</td>"
                         f"<td>{esc(e['method'])}</td></tr>")
        for ip, n in Counter(e["ip"] for e in fail_by_date.get(d, [])).most_common():
            parts.append(f"<tr><td colspan=\"1\">-</td>"
                         f"<td><span class=\"badge b-red\">失败 ×{n}</span></td>"
                         f"<td>-</td><td>{esc(ip)}</td><td colspan=\"2\">当日合计</td></tr>")
        parts.append("</table>")

    if analysis["sessions"]:
        parts.append("<h2>会话记录</h2><table><tr><th>开启时间</th><th>关闭时间</th>"
                     "<th>用户</th><th>时长</th><th>状态</th></tr>")
        for s in analysis["sessions"]:
            close = esc(fmt_dt(s["close"])) if s["close"] else "-"
            dur = esc(fmt_duration(s["duration"])) if s["duration"] else "-"
            status = ("超过 24 小时" if s["long"] else "正常") if s["close"] else "未正常关闭"
            cls = "high" if (s["long"] or not s["close"]) else ""
            parts.append(f"<tr><td>{esc(fmt_dt(s['open']))}</td><td>{close}</td>"
                         f"<td>{esc(s['user'])}</td><td>{dur}</td>"
                         f"<td class=\"{cls}\">{status}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>计数口径说明</h2><ul class=\"notes\">")
    parts.append(f"<li>失败统计包含认证失败、无效用户、认证超限、认证中断四类，合计 {fail_total} 条</li>")
    parts.append("<li>认证中断类事件计入统计，明细不逐条展示，JSON 导出保留完整事件</li>")
    parts.append(f"<li>爆破判定阈值: 失败类次数 &gt; {args.threshold}（--threshold 可调）</li>")
    parts.append(f"<li>爆破成功关联窗口: 成功登录前 {args.window} 分钟内失败达到阈值（--window 可调）</li>")
    parts.append("</ul>")
    parts.append("</body></html>")

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"HTML 审计报告已成功生成至: {outfile}")


# ==================== 输出层：JSON / CSV ====================


def export_json(events, analysis, args, outfile):
    """导出完整结构化结果：meta、summary、ip_profiles、events。"""
    by_type = Counter(e["type"] for e in events)
    doc = {
        "meta": {
            "logfile": args.logfile,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time_start": fmt_dt(events[0]["time"]) if events else None,
            "time_end": fmt_dt(events[-1]["time"]) if events else None,
            "params": {
                "threshold": args.threshold, "window_minutes": args.window,
                "top": args.top, "blacklist": args.blacklist,
            },
            "event_counts": {t: by_type.get(t, 0) for t in TYPE_LABEL},
        },
        "summary": {
            "brute_force_ips": [
                {"ip": ip, "failed": n}
                for ip, n in sorted(analysis["brute_ips"].items(), key=lambda x: x[1], reverse=True)
            ],
            "suspected_compromised": [
                {"ip": h["ip"], "user": h["user"], "time": f"{h['date']} {h['time_str']}",
                 "window_fails": h["window_fails"], "method": h["method"]}
                for h in analysis["suspected"]
            ],
            "backdoor_users": [
                {"user": b["user"], "uid": b["uid"], "created": fmt_dt(b["created"]),
                 "uid0": b["uid0"], "groups": [g for g, _ in b["groups"]]}
                for b in analysis["backdoors"]
            ],
            "blacklist_hits": analysis["blacklist_hits"],
            "abnormal_ports": [
                {"time": f"{e['date']} {e['time_str']}", "ip": e["ip"], "user": e["user"],
                 "port": e["port"], "method": e["method"]}
                for e in analysis["abnormal_ports"]
            ],
            "sessions": [
                {"user": s["user"], "open": fmt_dt(s["open"]),
                 "close": fmt_dt(s["close"]) if s["close"] else None,
                 "duration_seconds": int(s["duration"].total_seconds()) if s["duration"] else None,
                 "over_24h": s["long"]}
                for s in analysis["sessions"]
            ],
        },
        "ip_profiles": [
            {"ip": ip, "failed": p["failed"], "accepted": p["accepted"],
             "invalid": p["invalid"], "users": dict(p["users"]),
             "ports": sorted(p["ports"]), "first": fmt_dt(p["first"]), "last": fmt_dt(p["last"])}
            for ip, p in sorted(analysis["profiles"].items(),
                                key=lambda kv: kv[1]["failed"], reverse=True)
        ],
        "events": [
            {k: (e[k] if k != "time" else e["time"].strftime("%Y-%m-%d %H:%M:%S"))
             for k in ("type", "time", "date", "time_str", "user", "ip", "port",
                       "method", "invalid", "pid", "uid", "group", "raw")}
            for e in events
        ],
    }
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"JSON 事件导出已完成: {outfile}")


CSV_FIELDS = ["日期", "时间", "类型", "用户", "IP", "端口", "方式", "无效用户", "进程号", "原始行"]


def export_csv(events, args, outfile):
    """导出事件级明细 CSV（UTF-8 无 BOM）。"""
    with open(outfile, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_FIELDS)
        for e in events:
            w.writerow([
                e["date"], e["time_str"], TYPE_LABEL.get(e["type"], e["type"]),
                e["user"] or "", e["ip"] or "",
                e["port"] if e["port"] else "",
                e["method"] or "", "是" if e["invalid"] else "否",
                e["pid"] or "", e["raw"],
            ])
    print(f"CSV 事件导出已完成: {outfile}")


# ==================== 主流程 ====================


def main():
    args = parse_args()
    init_color(args.no_color)

    if not os.path.isfile(args.logfile):
        print(f"错误: 找不到日志文件 '{args.logfile}'")
        sys.exit(1)
    if args.blacklist and not os.path.isfile(args.blacklist):
        print(f"错误: 找不到黑名单文件 '{args.blacklist}'")
        sys.exit(1)

    try:
        events, enc_used = parse_logfile(args.logfile)
    except SystemExit:
        raise
    except Exception as e:
        print(f"读取或解析日志文件时发生错误: {e}")
        sys.exit(1)

    events = apply_time_filters(events, args)
    blacklist_nets = load_blacklist(args.blacklist) if args.blacklist else []
    analysis = analyze(events, args, blacklist_nets)

    did_output = False
    if args.accepted:
        render_accepted([e for e in events if e["type"] == "accepted"], args, analysis)
        did_output = True
    if args.failed:
        render_failed(events, args, analysis)
        did_output = True
    if args.outfile:
        try:
            if args.outfile.lower().endswith(".html"):
                render_report_html(events, analysis, args, args.outfile)
            else:
                render_report_txt(events, analysis, args, args.outfile)
        except Exception as e:
            print(f"写入报告文件时发生错误: {e}")
            sys.exit(1)
        did_output = True
    if args.export:
        stem = os.path.splitext(args.outfile)[0] if args.outfile else \
            os.path.splitext(args.logfile)[0] + "_audit"
        if "json" in args.export:
            export_json(events, analysis, args, stem + ".json")
        if "csv" in args.export:
            export_csv(events, args, stem + ".csv")
        did_output = True

    if not did_output:
        render_overview(events, analysis, args)


if __name__ == "__main__":
    main()
