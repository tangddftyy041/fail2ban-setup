# fail2ban-setup.sh

通用的 **Fail2ban SSH 防护一键部署脚本**，自动适配各种 Linux 发行版与现代日志/防火墙栈。

## 为什么需要它？

网上流传的老脚本（如 `FunctionClub/Fail2ban`）在现代系统上**装完不生效**，典型原因有三个：

| 老脚本的问题 | 后果 |
|---|---|
| 写死 `logpath = /var/log/auth.log` | Debian 12 / RHEL 9 默认只有 journald，**该文件根本不存在** → 读不到任何日志 → 永不封禁 |
| 写死 `action = ... port=ssh` | `ssh` 在 `/etc/services` 里 = **22**，而你的 SSH 可能监听 20225 → 封错端口 |

> 补充一个**很容易踩的坑**：只写 `port = 20225` 是**不够的**。
> fail2ban 的 `action` 参数**不会**自动继承 jail 段里的 `port`；
> 若写成裸 `action = nftables-multiport`，它会用 action 自带的默认端口，
> 最终仍退化成 `ssh`（=22），封禁规则封错端口、形同虚设。
> 本脚本因此显式写成 `nftables-multiport[port="20225", protocol="tcp"]`。
| 只支持老发行版 + `service` 命令 | 无法适配 systemd / nftables |

本脚本针对以上三点做了**自动探测**，并内置**部署后自检**（真的封一个保留测试 IP 再解封），确保装完确实生效。

## 特性

- ✅ **日志后端自动识别**：systemd-journald ⇄ `/var/log/auth.log` ⇄ `/var/log/secure`
  - 若选文件但文件不存在而 journald 可用，**自动回退** journald
  - 自动探测 SSH 单元名（`ssh.service` / `sshd.service`），并校验 journal 里确实有 sshd 日志
- ✅ **SSH 端口自动探测**：`sshd -T` → `sshd_config` → 实际监听 socket，三级兜底
- ✅ **防火墙自动选择**：nftables ⇄ iptables（含 firewalld 冲突提示）
- ✅ **初始化系统适配**：systemd ⇄ OpenRC ⇄ SysV service
- ✅ **运行前交互式询问**：可现场修改 SSH 端口、最大失败次数、封禁时长、统计窗口
  - 改端口会**自动备份** `sshd_config` 并做 `sshd -t` 校验，失败自动回滚
  - **绝不会自动重启 sshd**（避免把自己关在门外），只提示你新开终端验证
- ✅ **默认永久封禁**：`bantime = -1`，封住就不再自动放行
  - 永久条目**不会被 `dbpurgeage` 清理**，fail2ban 重启后也会从数据库恢复
  - 想恢复按时长封禁：`-b 8760`（365 天）或 `--permanent` 之外的任意小时数
- ✅ **防自锁**：自动把当前 SSH 登录来源 IP 加入白名单（**IPv4 / IPv6 都支持**）
  - 接管既有配置时会**继承**里面已有的白名单，不会把老白名单弄丢
- ✅ **幂等 + 安全**：写配置前自动备份，`fail2ban-client -t` 校验失败则**回滚**
- ✅ **自动接管既有配置**：发现已存在含 `[sshd]` 的配置文件时，直接改写优先级最高的那一个，
  并把其它同类文件的 `[sshd]` 段清空（只留 `enabled = false`），避免被"静默覆盖"
- ✅ **部署后自检**：封禁 RFC5737 保留地址 `203.0.113.77` 后全防火墙搜索确认，再自动解封

## 用法

### 一行免下载（推荐）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tangddftyy041/fail2ban-setup/main/fail2ban-setup.sh)
```

带参数：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tangddftyy041/fail2ban-setup/main/fail2ban-setup.sh) -p 20225 -r 6
```

### 先下载再执行

```bash
wget https://raw.githubusercontent.com/tangddftyy041/fail2ban-setup/main/fail2ban-setup.sh
bash fail2ban-setup.sh
```

带参数：

```bash
sudo bash fail2ban-setup.sh -p 20225 -r 6 -f 21600          # 默认永久封禁
sudo bash fail2ban-setup.sh -p 20225 -r 6 -f 21600 -b 8760 # 改为封 365 天
```

### 其它用法

```bash
# 强制使用文件日志后端
sudo bash fail2ban-setup.sh --backend file

# 强制使用 iptables
sudo bash fail2ban-setup.sh --action iptables
```

### 交互式询问

不加参数直接运行会进入交互模式，依次询问（**直接回车 = 保持默认值**）：

```
---- 参数确认 (直接回车 = 使用括号内默认值) ----
  > 新的 SSH 端口 (直接回车保持 20225):
  > 最大失败次数 [2-10] (默认 6):
  > 封禁时长[小时] (默认 永久 ; 输入 p/-1/0 也是永久):
  > 统计窗口[秒] (默认 21600s ≈ 6 小时):
--------------------------------------------------
```

> ⚠️ **修改 SSH 端口有风险**：脚本会备份 `sshd_config` 并用 `sshd -t` 校验，
> 但**不会自动重启 sshd**。请务必**先新开一个终端**用新端口测试能连上，再断开当前连接。

若要跳过询问（例如用于自动化）：

```bash
bash fail2ban-setup.sh -y     # 全部采用默认值
bash fail2ban-setup.sh -n     # 完全非交互，纯命令行模式
```

注意：`curl URL | bash` 这类管道方式下 stdin 不是终端，脚本会**自动跳过询问**，
此时请用 `-p/-r/-f/-b` 显式传参。

### 关于 `bash https://...`

**不能**写成 `bash https://raw.githubusercontent.com/...` —— bash 只接受本地文件路径，会直接报：

```
bash: https://...: No such file or directory
```

要用上面的一行式 `bash <(curl -fsSL URL)`（进程替换，需 bash，不能用 sh）。

管道式 `curl -fsSL URL | bash` 也能跑，但**传参必须写成** `bash -s -- -p 20225`，且脚本占用 stdin，不如 `<(...)` 方便。

### 参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `-p, --port PORT` | SSH 端口 | 自动探测 |
| `-r, --maxretry N` | 失败几次后封禁 | `6` |
| `-f, --findtime SEC` | 统计窗口秒数 | `21600`（6 小时，可防慢速爆破） |
| `-b, --bantime HOURS` | 封禁时长（小时） | **永久**（`bantime = -1`） |
| `--permanent` | 强制永久封禁（与 `-b` 同时给时以此为准） | 是 |
| `-i, --ignoreip IP` | 额外白名单，可重复 | 无 |
| `--backend TYPE` | 强制后端 `systemd`\|`file` | 自动 |
| `--action TYPE` | 强制 `nftables`\|`iptables` | 自动 |
| `--no-test` | 跳过封禁链路自检 | 否 |
| `-y, --yes` | 交互式询问全部采用默认值 | 否 |
| `-n, --no-interactive` | 完全跳过所有询问 | 否 |
| `-h, --help` | 帮助 | |
| `-v, --version` | 版本 | |

## 关于 findtime（慢速爆破）

有些攻击会刻意**每 2 小时来 2–3 次**，卡在 `findtime=7200`（2 小时）窗口边缘，导致永远凑不满 `maxretry`，怎么都封不掉。

把 `findtime` 放宽到 `21600`（6 小时）即可让**跨波次的失败累计**，这类规避手法就失效了。本脚本默认值已按此设置。

## 验证部署结果

```bash
fail2ban-client status sshd                    # 查看状态
fail2ban-client status sshd | grep 'Banned IP' # 查看被封 IP
fail2ban-client set sshd unbanip <IP>          # 手动解封
fail2ban-client set sshd banip <IP>            # 手动封禁
```

## 支持的系统

Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux / Amazon Linux / Alpine / openSUSE / Arch
（任何带 bash 与常见包管理器的 Linux）

## 配置文件位置

**首次部署**：生成 `/etc/fail2ban/jail.d/zzz-sshd-auto.local`（`zzz-` 前缀保证在
`*.local` 中排最后，从而优先级最高），旧文件自动备份为 `*.bak.<时间戳>`。

**已有配置时**：fail2ban 的读取顺序是

```
jail.conf → jail.d/*.conf(字母序) → jail.local → jail.d/*.local(字母序)
```

**后读的覆盖先读的**。因此若已存在一个文件名排在我们之后、且含 `[sshd]` 段的文件，
我们写的内容会被静默覆盖（脚本却照样报"部署完成"）。为此脚本会：

1. 找出所有含 `[sshd]` 段的既有文件，**直接接管优先级最高的那一个**（覆写它）
2. 把其它同类文件的 `[sshd]` 段**清空**，只留 `enabled = false`（只置 `enabled=false`
   是不够的，残留的 `logpath`/`port` 等仍会被合并进最终配置）
3. **继承**被接管文件里已有的 `ignoreip` 白名单，与新增 IP 合并去重

同时会显式关闭旧脚本遗留的 `[ssh-iptables]`（其 logpath/port 常不正确）。

## 关于永久封禁

默认 `bantime = -1`，即**永久**。fail2ban 内部对 `-1` 有专门处理：

- `ticket.py`：`isTimedOut()` 恒为 `False`，永不到期
- `database.py`：仅清理 `bantime != -1` 的条目，永久条目**不会被 `dbpurgeage` 清掉**

重启 fail2ban 后永久条目会从数据库恢复，仍在封禁状态。

> ⚠️ **永久封禁是双刃剑**：误封只能手动解封，且需要**能连上服务器**才能解。
> 强烈建议用 `-i` 把常用出口 IP 加入白名单：
>
> ```bash
> sudo bash fail2ban-setup.sh -i 1.2.3.4 -i 5.6.7.8
> ```
>
> 万一真把自己封在外面，只能通过 VPS 控制台 / 带外管理进去执行
> `fail2ban-client set sshd unbanip <IP>`。

## 许可

MIT
