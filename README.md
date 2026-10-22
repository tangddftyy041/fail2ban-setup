# fail2ban-setup.sh

通用的 **Fail2ban SSH 防护一键部署脚本**，自动适配各种 Linux 发行版与现代日志/防火墙栈。

## 为什么需要它？

网上流传的老脚本（如 `FunctionClub/Fail2ban`）在现代系统上**装完不生效**，典型原因有三个：

| 老脚本的问题 | 后果 |
|---|---|
| 写死 `logpath = /var/log/auth.log` | Debian 12 / RHEL 9 默认只有 journald，**该文件根本不存在** → 读不到任何日志 → 永不封禁 |
| 写死 `action = ... port=ssh` | `ssh` 在 `/etc/services` 里 = **22**，而你的 SSH 可能监听 20225 → 封错端口 |
| 只支持老发行版 + `service` 命令 | 无法适配 systemd / nftables |

本脚本针对以上三点做了**自动探测**，并内置**部署后自检**（真的封一个保留测试 IP 再解封），确保装完确实生效。

## 特性

- ✅ **日志后端自动识别**：systemd-journald ⇄ `/var/log/auth.log` ⇄ `/var/log/secure`
  - 若选文件但文件不存在而 journald 可用，**自动回退** journald
  - 自动探测 SSH 单元名（`ssh.service` / `sshd.service`），并校验 journal 里确实有 sshd 日志
- ✅ **SSH 端口自动探测**：`sshd -T` → `sshd_config` → 实际监听 socket，三级兜底
- ✅ **防火墙自动选择**：nftables ⇄ iptables（含 firewalld 冲突提示）
- ✅ **初始化系统适配**：systemd ⇄ OpenRC ⇄ SysV service
- ✅ **防自锁**：自动把当前 SSH 登录来源 IP 加入白名单
- ✅ **幂等 + 安全**：写配置前自动备份，`fail2ban-client -t` 校验失败则**回滚**
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
sudo bash fail2ban-setup.sh -p 20225 -r 6 -f 21600 -b 8760
```

### 其它用法

```bash
# 强制使用文件日志后端
sudo bash fail2ban-setup.sh --backend file

# 强制使用 iptables
sudo bash fail2ban-setup.sh --action iptables
```

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
| `-b, --bantime HOURS` | 封禁时长（小时） | `8760`（365 天） |
| `-i, --ignoreip IP` | 额外白名单，可重复 | 无 |
| `--backend TYPE` | 强制后端 `systemd`\|`file` | 自动 |
| `--action TYPE` | 强制 `nftables`\|`iptables` | 自动 |
| `--no-test` | 跳过封禁链路自检 | 否 |
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

脚本生成 `/etc/fail2ban/jail.d/zz-sshd-auto.local`，并自动备份同名旧文件为
`zz-sshd-auto.local.bak.<时间戳>`。

同时会显式关闭旧脚本遗留的 `[ssh-iptables]`（其 logpath/port 常不正确）。

## 许可

MIT
