# SSH-Access-Auditor

## 一、介绍

对 SSH 日志的访问登录事件进行分析，面向应急排查场景。

支持日志：

- `/var/log/auth.log`（Debian/Ubuntu 系统）
- `/var/log/secure`（RHEL/CentOS 系统）

兼容两种格式：英文旧格式 `sshd[pid]`，中文新格式 `sshd-session[pid]`（Kali 2024+ 等），中文日期（`2月 11`）与英文日期（`Feb 11`）均可解析。编码按 UTF-8 优先、GBK 回退。

事件覆盖 9 类：登录成功（Accepted）、认证失败（Failed）、无效用户（Invalid user）、认证超限（maximum authentication attempts exceeded）、认证中断（Connection closed / Disconnected by authenticating user）、会话开启与关闭（session opened/closed）、useradd 新建账号、特权组添加。

核心能力：

- 爆破 IP 判定：失败类合计超过阈值（`--threshold`，默认 10）
- 高危「疑似爆破成功」：成功登录前 `--window` 分钟（默认 30）内同 IP 失败达到阈值，替代旧版全局交集判定
- IP 画像：失败、成功、无效用户计数，尝试过的用户名，首次与末次出现
- 后门账号检测：useradd 新建账号中 UID 为 0 或加入 sudo、wheel、adm、admin、root 组的记录
- 会话时长：按进程号配对 session opened/closed，未正常关闭与超 24 小时会话提示
- 异常端口提示：非 22 端口的成功登录单独标记
- 离线黑名单：`--blacklist` 指定本地 IP 名单文件，命中高亮
- 四种输出：彩色终端、文本报告、单文件 HTML 报告（内嵌 CSS，离线可打开）、JSON 与 CSV 导出

参考：[pizslacker/sshlog: Log-parser script for ssh-auditing - server-side tool.](https://github.com/pizslacker/sshlog)

## 二、使用方法

### 2.1 方法介绍

- `logfile`（必选）：指定要分析的日志文件路径（例如：`./auth.log`）。
- `-h, --help`：查看帮助。
- `-a, --accepted`：在屏幕显示认证成功的登录记录及统计信息。
- `-f, --failed`：在屏幕显示认证失败的登录尝试及统计信息。
- `-k, --key`：仅在屏幕输出中过滤基于公钥（publicKey）的认证。
- `-p, --password`：仅在屏幕输出中过滤基于密码（password）的认证。
- `-P, --pam`：仅在屏幕输出中过滤基于键盘交互/PAM 的认证。
- `-t`：按指定日期筛选（例如：`-t "12/23"`）。
- `-ts`：按起始时间筛选（例如：`-ts "12/23 03:00:00"`）。
- `-te`：按结束时间筛选（例如：`-te "12/23 23:00:00"`）。
- `-tr`：显示最近 X 天的记录（例如：`-tr 7` 显示近 7 天）。
- `-o`：生成审计报告，`.html` 后缀自动生成 HTML 报告，其余为文本报告。
- `--export json,csv`：导出结构化事件，逗号分隔可复选。
- `--top N`：汇总模式，失败明细只显示 Top N 攻击 IP。
- `--threshold N`：爆破判定阈值，失败类次数超过该值判定为爆破（默认 10）。
- `--window N`：爆破成功关联窗口分钟数（默认 30）。
- `--blacklist FILE`：本地 IP 黑名单文件，每行一个 IP 或 CIDR。
- `--no-color`：关闭颜色输出。

不带 `-a`、`-f`、`-o`、`--export` 任何一项时，输出精简概要（爆破 IP、高危标记、后门账号、异常端口）。

### 2.2 快速使用

- 基础分析报告：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -o report.txt
  ```

  <img src="./笔记图片/image-20260502231427165.png" alt="基础分析报告输出" style="zoom:67%;" />

- 筛选登录成功的记录：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -a
  ```

  <img src="./笔记图片/image-20260502231802700.png" alt="登录成功筛选输出" style="zoom:67%;" />

- 筛选登录失败的记录：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -f
  ```

  <img src="./笔记图片/image-20260502231823124.png" alt="登录失败筛选输出" style="zoom:67%;" />

- 筛选以 publicKey 方式登录成功的记录：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -a -k
  ```

  <img src="./笔记图片/image-20260502231901855.png" alt="公钥认证筛选输出" style="zoom:67%;" />

- 生成 HTML 可视化报告：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -o report.html
  ```

- 大日志下只看 Top 10 攻击 IP 汇总：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -f --top 10
  ```

- 导出 JSON 与 CSV 事件明细：

  ```shell
  python SSH-Access-Auditor.py ./auth.log --export json,csv
  ```

- 自定义爆破阈值与时间窗，加载本地 IP 黑名单：

  ```shell
  python SSH-Access-Auditor.py ./auth.log --threshold 20 --window 60 --blacklist iplist.txt
  ```

- 筛选特定时间段内，以 password 方式登录的尝试：

  ```shell
  python SSH-Access-Auditor.py ./auth.log -a -f -p -ts "12/24 03:00:00" -te "12/24 23:00:00"
  ```
