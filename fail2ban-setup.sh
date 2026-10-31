#!/usr/bin/env bash
# ============================================================================
# fail2ban-setup.sh - 通用 Fail2ban SSH 防护一键部署脚本
# ----------------------------------------------------------------------------
# 适用系统 : Debian/Ubuntu/CentOS/RHEL/Rocky/Alma/AmazonLinux/Alpine/openSUSE/Arch
#            (任何有 bash + 常见包管理器的 Linux)
# 自动适配 : 1) 日志后端  systemd-journald  <->  /var/log/auth.log|secure
#            2) SSH 端口  实际监听端口(非写死 22)
#            3) 防火墙    nftables <-> iptables
#            4) 初始化    systemd <-> OpenRC <-> SysV service
#            5) 配置落点  自动接管既有的 sshd jail 文件(避免被高优先级文件静默覆盖)
#
# 默认策略: 永久封禁 (bantime = -1)。永久条目不会被 dbpurgeage 清理，
#           重启后由 fail2ban 数据库自动恢复，需手动解封。
#
# 用法     : bash fail2ban-setup.sh [选项]
#            sudo bash fail2ban-setup.sh -p 20225 -r 6 -f 21600 -b 8760
# ============================================================================
set -uo pipefail

VERSION="1.3.0"
JAIL_DIR="${JAIL_D:-/etc/fail2ban/jail.d}"                 # 可用 JAIL_D 覆盖，仅用于测试
OWN_JAIL_FILE="$JAIL_DIR/zzz-sshd-auto.local"                # zzz- 保证在 *.local 中排最后
JAIL_FILE=""                                                  # 实际落点(由 detect_existing_jail 决定)
ADOPTED=0
TEST_IP="203.0.113.77"      # RFC5737 保留测试地址，绝不会是真实主机

C_R='\033[0m'; C_G='\033[32m'; C_Y='\033[33m'; C_B='\033[36m'; C_E='\033[31m'
info(){ printf "${C_B}[INFO]${C_R} %s\n" "$*"; }
ok(){   printf "${C_G}[ OK ]${C_R} %s\n" "$*"; }
warn(){ printf "${C_Y}[WARN]${C_R} %s\n" "$*" >&2; }
die(){  printf "${C_E}[FAIL]${C_R} %s\n" "$*" >&2; exit 1; }

# ---------------------------- 默认参数 ----------------------------
PORT=""; MAXRETRY=3; FINDTIME=21600
BANTIME_HOURS=8760; PERMANENT=1        # PERMANENT=1 -> bantime=-1(永久); 传 -b 则转为按时长封禁
PORT_MANUAL=0                             # 用户是否用 -p 显式指定了端口
EXTRA_IGNORE=""; FORCE_BACKEND=""; FORCE_ACTION=""; SKIP_TEST=0
ASSUME_YES=0; NO_INTERACTIVE=0; CHANGE_SSHD_PORT=0

usage(){ cat <<'USAGE'
用法: bash fail2ban-setup.sh [选项]

  -p, --port PORT      SSH 端口 (默认自动探测实际监听端口)
  -r, --maxretry N     失败几次后封禁 (默认 3)
  -f, --findtime SEC   统计窗口秒数 (默认 21600=6小时, 可防慢速爆破)
  -b, --bantime HOURS  封禁时长小时 (默认: 永久封禁 bantime=-1)
      --permanent      强制永久封禁 (与 -b 同时给时以此为准)
  -i, --ignoreip IP    额外白名单 IP/CIDR, 可重复指定
      --backend TYPE   强制后端: systemd | file
      --action TYPE    强制动作: nftables | iptables
      --no-test        跳过封禁链路自检
  -y, --yes           交互式询问全部采用默认值(非交互)
  -n, --no-interactive 完全跳过所有询问(纯命令行模式)
  -h, --help           显示本帮助
  -v, --version        显示版本

示例:
  bash fail2ban-setup.sh                      # 全自动
  bash fail2ban-setup.sh -p 20225 -r 5        # 指定端口与阈值
  bash fail2ban-setup.sh --backend file       # 强制用文件日志
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port)      PORT="${2:-}"; PORT_MANUAL=1; shift 2;;
    -r|--maxretry)  MAXRETRY="${2:-}";    shift 2;;
    -f|--findtime)  FINDTIME="${2:-}";    shift 2;;
    -b|--bantime)   BANTIME_HOURS="${2:-}"; PERMANENT=0; shift 2;;
    --permanent)    PERMANENT=1;           shift;;
    -i|--ignoreip)  EXTRA_IGNORE="$EXTRA_IGNORE ${2:-}"; shift 2;;
    --backend)      FORCE_BACKEND="${2:-}"; shift 2;;
    --action)       FORCE_ACTION="${2:-}";  shift 2;;
    --no-test)      SKIP_TEST=1;          shift;;
    -y|--yes)       ASSUME_YES=1;         shift;;
    -n|--no-interactive) NO_INTERACTIVE=1; shift;;
    -h|--help)      usage; exit 0;;
    -v|--version)   echo "fail2ban-setup.sh v$VERSION"; exit 0;;
    *)              echo "未知参数: $1"; usage; exit 1;;
  esac
done

# ---------------------------- 0. 前置检查 ----------------------------
[ "$(id -u)" = "0" ] || die "需要 root 权限运行 (请先 sudo -i 或 sudo $0)"

# ---------------------------- 1. 识别包管理器并安装 ----------------------------
PKG=""
detect_pm(){
  for pm in apt-get dnf yum apk zypper pacman; do
    command -v "$pm" >/dev/null 2>&1 && { PKG="$pm"; return 0; }
  done
  return 1
}

install_fail2ban(){
  if command -v fail2ban-client >/dev/null 2>&1; then
    ok "fail2ban 已安装: $(fail2ban-client --version 2>/dev/null | head -n1)"
    return 0
  fi
  detect_pm || die "未识别的包管理器，请手动安装 fail2ban 后重跑本脚本"
  info "使用包管理器 $PKG 安装 fail2ban ..."
  case "$PKG" in
    apt-get) export DEBIAN_FRONTEND=noninteractive
             apt-get -qq update >/dev/null 2>&1
             apt-get -y -qq install fail2ban >/dev/null 2>&1;;
    dnf|yum) "$PKG" -y install epel-release >/dev/null 2>&1
             "$PKG" -y install fail2ban     >/dev/null 2>&1;;
    apk)     apk add --no-cache fail2ban    >/dev/null 2>&1;;
    zypper)  zypper -n install fail2ban     >/dev/null 2>&1;;
    pacman)  pacman -S --noconfirm fail2ban >/dev/null 2>&1;;
  esac
  command -v fail2ban-client >/dev/null 2>&1 \
    && ok "fail2ban 安装完成" \
    || die "fail2ban 安装失败，请检查软件源后手动安装"
}

# ---------------------------- 2. 探测 SSH 实际端口 ----------------------------
detect_ssh_port(){
  local p=""
  # 2.1 最权威: sshd 自己输出的生效配置
  if command -v sshd >/dev/null 2>&1; then
    p="$(sshd -T 2>/dev/null | awk '/^port /{printf "%s%s",s,$2; s=","}')"
  fi
  # 2.2 配置文件
  [ -z "$p" ] && p="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]/{printf "%s%s",s,$2; s=","}' /etc/ssh/sshd_config 2>/dev/null)"
  # 2.3 实际监听 socket
  if [ -z "$p" ]; then
    if command -v ss >/dev/null 2>&1; then
      p="$(ss -tlnp 2>/dev/null | awk '/sshd/ && $4 ~ /:[0-9]+$/{n=split($4,a,":"); printf "%s%s",s,a[n]; s=","}')"
    elif command -v netstat >/dev/null 2>&1; then
      p="$(netstat -tlnp 2>/dev/null | awk '/sshd/ && $4 ~ /:[0-9]+$/{n=split($4,a,":"); printf "%s%s",s,a[n]; s=","}')"
    fi
  fi
  [ -z "$p" ] && p="22"
  printf '%s' "$p"
}

# ---------------------------- 3. 探测 systemd 单元名 ----------------------------
have_systemd(){ [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

detect_ssh_unit(){
  command -v systemctl >/dev/null 2>&1 || { printf ''; return; }
  local u
  # 1) 优先: 该单元确实是 active 的
  for u in ssh.service sshd.service; do
    systemctl is-active "$u" >/dev/null 2>&1 && { printf '%s' "$u"; return; }
  done
  # 2) 其次: 单元文件存在(即使当前未运行)
  for u in ssh.service sshd.service; do
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u" \
      && { printf '%s' "$u"; return; }
  done
  # 3) 兜底: 按发行版惯例猜
  [ -f /etc/debian_version ] && { printf 'ssh.service'; return; }
  printf 'sshd.service'
}

# 该单元的 journal 里是否真有 sshd 日志
journal_has_sshd(){
  local u="$1"
  command -v journalctl >/dev/null 2>&1 || return 1
  [ -n "$(journalctl -u "$u" -n 200 --no-pager 2>/dev/null | grep -a 'sshd')" ]
}

# ---------------------------- 4. 决定日志后端 ----------------------------
detect_backend(){
  local unit="$1"
  if [ "$FORCE_BACKEND" = "systemd" ]; then printf 'systemd'; return; fi
  if [ "$FORCE_BACKEND" = "file" ];    then printf 'file';     return; fi

  # 有 systemd + journal 里确实有 sshd 日志 -> 用 journald
  if have_systemd && [ -n "$unit" ] && journal_has_sshd "$unit"; then
    printf 'systemd'; return
  fi
  # 若选文件但文件不存在，而 journald 可用 -> 强制回退 systemd（避免装完不生效）
  if have_systemd && [ -n "$unit" ] && [ ! -f "$(detect_logpath)" ]; then
    printf 'systemd'; return
  fi
  # 否则用文件日志
  printf 'file'
}

detect_logpath(){
  # RHEL 系用 secure，Debian 系用 auth.log
  for f in /var/log/secure /var/log/auth.log; do
    [ -f "$f" ] && { printf '%s' "$f"; return; }
  done
  printf '/var/log/auth.log'
}

# ---------------------------- 4.5 识别并接管既有的 sshd jail 文件 ----------------------------
# 背景(关键): fail2ban 读取顺序为
#     jail.conf -> jail.d/*.conf(字母序) -> jail.local -> jail.d/*.local(字母序)
#   后读的覆盖先读的。若已存在一个文件名排在我们之后且含 [sshd] 段的文件，
#   我们写的内容会被静默覆盖(脚本却照样报成功)。
# 对策: 找出所有含 [sshd] 段的既有文件，直接接管其中"优先级最高"的那一个(覆写它)，
#       并把其它同类文件里的 [sshd] 段禁用，避免残留的 logpath/port 等干扰。
#
# 输出: 优先级最高的既有文件路径；没有则输出空
detect_existing_jail(){
  local f best=""
  [ -d "$JAIL_DIR" ] || { printf ''; return; }
  # 严格按 fail2ban 的读取顺序遍历：*.conf 先(低优先级)，jail.local 居中，*.local 后(高优先级)
  for f in $( { ls -1 "$JAIL_DIR"/*.conf 2>/dev/null; ls -1 /etc/fail2ban/jail.local 2>/dev/null; ls -1 "$JAIL_DIR"/*.local 2>/dev/null; } | sort -u); do
    [ -f "$f" ] || continue
    grep -qE '^[[:space:]]*\[sshd\]' "$f" 2>/dev/null && best="$f"
  done
  printf '%s' "$best"
}

# 把"其它"含 [sshd] 段的既有文件里的 sshd 段关掉，只保留我们接管的那一个
neutralize_other_jails(){
  local keep="$1" f
  [ -d "$JAIL_DIR" ] || return 0
  for f in "$JAIL_DIR"/*.conf "$JAIL_DIR"/*.local /etc/fail2ban/jail.local; do
    [ -f "$f" ] || continue
    [ "$f" = "$keep" ] && continue
    grep -qE '^[[:space:]]*\[sshd\]' "$f" 2>/dev/null || continue
    cp -a "$f" "${f}.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null
    # 彻底清空该 [sshd] 段内的所有键，只保留 enabled=false。
    # 只写 enabled=false 是不够的: 残留的 logpath/port/maxretry 等仍会被
    # fail2ban 合并进最终配置(后读覆盖先读)，可能盖掉我们接管文件里的正确值。
    # 另外绝不能"额外插入一行 enabled"，否则与既有的 enabled 重复，
    # configparser 会抛 DuplicateOptionError 导致 fail2ban 起不来。
    awk -v K="$keep" '
      /^[[:space:]]*\[/ { insec = ($0 ~ /^[[:space:]]*\[sshd\]/) ? 1 : 0
                           if (insec && !done) { print; print "enabled = false   # fail2ban-setup.sh: sshd 段已由 " K " 接管"; done=1; next }
                           print; next }
      { if (!insec) print }
    ' "$f" > "${f}.tmp.$$" 2>/dev/null \
      && mv "${f}.tmp.$$" "$f" \
      && info "已禁用旧文件 [sshd] 段: $f (原文件已备份为 *.bak.*)"
  done
  return 0
}

# ---------------------------- 5. 决定封禁动作 ----------------------------
detect_action(){
  case "$FORCE_ACTION" in
    nftables) printf 'nftables-multiport'; return;;
    iptables) printf 'iptables-multiport'; return;;
  esac
  # nftables 优先（Debian 10+/RHEL 8+ 默认）
  if command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1 \
     && [ -f /etc/fail2ban/action.d/nftables-multiport.conf ]; then
    printf 'nftables-multiport'; return
  fi
  printf 'iptables-multiport'
}

# ---------------------------- 6. 收集白名单 ----------------------------
detect_own_ip(){
  # 当前 SSH 登录来源 IP (用于防自锁)。IPv4/IPv6 通吃
  printf '%s' "${SSH_CONNECTION:-}" | awk '{print $1}'
}

build_ignoreip(){
  local list="127.0.0.1/8 ::1"
  # 防自锁: 把当前 SSH 登陆来源 IP 加进白名单
  local cur
  cur="$(detect_own_ip)"
  # 注意: 本函数在 $( ) 中被调用，绝不能往 stdout 打印任何内容
  # IPv4 与 IPv6 都要能进白名单，否则 IPv6 来源登录时"防自锁"失效
  case "$cur" in
    *[0-9].*[0-9].*[0-9].*[0-9]) list="$list $cur";;   # IPv4
    *:*)                         list="$list $cur";;   # IPv6
  esac
  [ -n "$EXTRA_IGNORE" ] && list="$list $EXTRA_IGNORE"
  printf '%s' "$list"
}

# ---------------------------- 6.5 继承既有 jail 中的用户自定义值 ----------------------------
# 接管一个既有文件时，"接管"不等于"丢弃": 必须先把里面用户手工维护的
# ignoreip 白名单(以及 port/logpath 等)读出来，合并进我们要写的内容，
# 否则等于把用户原有的白名单静默删掉 —— 这正是防自锁功能最怕的情况。
#
# 用法: inherit_from_existing <file> <key>   输出该文件中 [sshd] 段 <key> 的值(无则空)
inherit_from_existing(){
  local f="$1" key="$2" v=""
  [ -f "$f" ] || { printf ''; return; }
  # 只取 [sshd] 段内的 key，取最后一个(同段内后写覆盖先写，与 fail2ban 语义一致)
  v="$(awk -v K="$key" '
    /^[[:space:]]*\[/ { sec = ($0 ~ /^[[:space:]]*\[sshd\]/) ? 1 : 0; next }
    sec == 1 {
      line = $0
      sub(/[[:space:]]*#.*$/, "", line)
      sub(/[[:space:]]*;.*$/, "", line)
      if (line ~ "^[[:space:]]*" K "[[:space:]]*=") {
        sub("^[[:space:]]*" K "[[:space:]]*=", "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "") val = line
      }
    }
    END { if (val != "") print val }
  ' "$f" 2>/dev/null)"
  printf '%s' "$v"
}

# 合并两段空格分隔的 IP 列表，去重且保持顺序(既有在前，新增在后)
merge_ip_list(){
  local a="$1" b="$2" x out=""
  for x in $a $b; do
    [ -z "$x" ] && continue
    case " $out " in
      *" $x "*) continue;;
      *) out="${out:+$out }$x";;
    esac
  done
  printf '%s' "$out"
}

# ---------------------------- 7. 写入 jail 配置 ----------------------------
write_jail(){
  local port="$1" backend="$2" action="$3" unit="$4" ignore="$5"
  # 合并后的白名单写回全局变量，供结尾摘要显示真实生效值
  # (IGNORE 是 build_ignoreip 的原始值，不含 write_jail 内继承合并的 IP)
  # 永久封禁: bantime = -1。fail2ban 内部对 -1 有专门处理:
  #   ticket.py   -> isTimedOut() 恒为 False(永不到期)
  #   database.py -> bantime != -1 才清理(永久条目不会被 dbpurgeage 清掉)
  # 重启后由数据库自动恢复，需手动 unbanip 解除。
  local bantime
  if [ "$PERMANENT" = "1" ]; then
    bantime="-1"
  else
    bantime=$(( BANTIME_HOURS * 3600 ))
  fi

  # 决定落点: 若已存在含 [sshd] 的高优先级文件则接管它，否则用我们自己的(排最后)
  if [ -z "$JAIL_FILE" ]; then
    local exist
    exist="$(detect_existing_jail)"
    if [ -n "$exist" ] && [ "$exist" != "$OWN_JAIL_FILE" ]; then
      JAIL_FILE="$exist"; ADOPTED=1
      info "检测到既有 sshd 配置 $exist，将直接接管(避免被其覆盖)"
      neutralize_other_jails "$exist"
    else
      JAIL_FILE="$OWN_JAIL_FILE"
    fi
  fi

  # 继承: 把所有既有 sshd 文件里的用户自定义值合并进来(尤其是白名单，绝不能丢)
  if [ "$ADOPTED" = "1" ] || [ -d "$JAIL_DIR" ]; then
    local f inherited
    for f in "$JAIL_DIR"/*.conf "$JAIL_DIR"/*.local /etc/fail2ban/jail.local; do
      [ -f "$f" ] || continue
      grep -qE '^[[:space:]]*\[sshd\]' "$f" 2>/dev/null || continue
      inherited="$(inherit_from_existing "$f" ignoreip)"
      if [ -n "$inherited" ]; then
        local merged
        merged="$(merge_ip_list "$inherited" "$ignore")"
        if [ "$merged" != "$ignore" ]; then
          info "继承 $f 中的白名单: $inherited"
          ignore="$merged"
        fi
      fi
      # 未显式指定端口时，也继承既有配置里的端口
      if [ -z "$PORT_MANUAL" ]; then
        local p2; p2="$(inherit_from_existing "$f" port)"
        case "$p2" in
          ''|*[!0-9,]*) ;;
          *) port="$p2";;
        esac
      fi
    done
  fi

  [ -f "$JAIL_FILE" ] && cp -a "$JAIL_FILE" "${JAIL_FILE}.bak.$(date +%Y%m%d-%H%M%S)" \
    && info "已备份旧配置 -> ${JAIL_FILE}.bak.*"

  # 防御性清理: 剔除变量中可能混入的控制字符(如 ANSI 转义)
  ignore="$(printf '%s' "$ignore" | tr -d '\033' | sed 's/\[[0-9;]*[A-Za-z]//g')"
  port="$(printf '%s' "$port"   | tr -d '\033' | sed 's/\[[0-9;]*[A-Za-z]//g')"
  unit="$(printf '%s' "$unit"   | tr -d '\033' | sed 's/\[[0-9;]*[A-Za-z]//g')"

  {
    echo "# 由 fail2ban-setup.sh v$VERSION 于 $(date '+%F %T') 生成"
    echo "[DEFAULT]"
    echo "ignoreip  = $ignore"
    echo "bantime   = $bantime"
    echo "findtime  = $FINDTIME"
    echo "maxretry  = $MAXRETRY"
    echo "banaction = $action"
    # 注意: action 的 port 不会自动继承 [sshd] 段的 port。
    # 若写成裸 "action = nftables-multiport"，fail2ban 会用 action 自带的默认 port，
    # 最终退化成 ssh(=22)，导致 SSH 跑在 20225 时封禁规则封错端口、形同虚设。
    # 必须显式传入 port="..."。
    echo
    echo "[sshd]"
    echo "enabled   = true"
    echo "filter    = sshd"
    # ignoreip 同时写在本段: [sshd] 显式值优先于 [DEFAULT]，
    # 可防止被其它文件的 [sshd].ignoreip(含旧白名单)覆盖后丢失防自锁条目
    echo "ignoreip  = $ignore"
    # 显式绑定 action 并强制带上真实端口(见上方说明)
    echo "action    = $action[port=\"$port\", protocol=\"tcp\"]"
    echo "mode      = aggressive"
    echo "port      = $port"
    echo "maxretry  = $MAXRETRY"
    echo "findtime  = $FINDTIME"
    echo "bantime   = $bantime"
    if [ "$backend" = "systemd" ]; then
      echo "backend   = systemd"
      echo "journalmatch = _SYSTEMD_UNIT=$unit"
    else
      echo "backend   = auto"
      echo "logpath   = $(detect_logpath)"
    fi
    echo
    echo "# 关闭旧脚本遗留的 [ssh-iptables] (其 logpath/port 常不正确)"
    echo "[ssh-iptables]"
    echo "enabled = false"
  } > "$JAIL_FILE"

  # 语法校验，失败则回滚
  if ! fail2ban-client -t >/dev/null 2>&1; then
    rm -f "$JAIL_FILE"
    fail2ban-client -t 2>&1 | tail -n 5
    die "配置语法校验失败，已撤销写入"
  fi
  ok "配置已写入 $JAIL_FILE (语法校验通过)"
  IGNORE="$ignore"   # 回传真实生效的白名单(含继承合并的部分)
}

# ---------------------------- 7.5 交互式询问 ----------------------------
# 读一行输入；非交互或 stdin 不可用时直接返回默认值
ask(){
  local prompt="$1" default="$2" ans
  if [ "$NO_INTERACTIVE" = "1" ] || [ ! -t 0 ]; then
    printf '%s' "$default"; return 0
  fi
  if [ "$ASSUME_YES" = "1" ]; then
    printf '%s' "$default"; return 0
  fi
  printf '%s' "$prompt" >&2
  IFS= read -r ans || ans=""
  [ -z "$ans" ] && ans="$default"
  printf '%s' "$ans"
}

# 校验并(可选)修改 sshd 端口。改端口有把自己锁在门外的风险，故:
#   1) 备份 sshd_config  2) sshd -t 校验  3) 绝不自动重启 sshd，只提示用户
maybe_change_sshd_port(){
  local cur="$1" newport
  newport="$(ask "  > 新的 SSH 端口 (直接回车保持 ${cur}): " "$cur")"
  [ "$newport" = "$cur" ] && { info "SSH 端口保持 $cur 不变"; return 0; }

  # 校验: 必须是 1-65535 的纯数字
  case "$newport" in
    ''|*[!0-9]*) warn "端口 '$newport' 非法(需为纯数字)，保持 $cur 不变"; return 0;;
  esac
  if [ "$newport" -lt 1 ] 2>/dev/null || [ "$newport" -gt 65535 ] 2>/dev/null; then
    warn "端口 $newport 超出 1-65535，保持 $cur 不变"; return 0
  fi

  [ -f /etc/ssh/sshd_config ] || { warn "未找到 /etc/ssh/sshd_config，跳过改端口"; return 0; }

  # 备份
  local bak="/etc/ssh/sshd_config.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a /etc/ssh/sshd_config "$bak" || { warn "备份失败，跳过改端口"; return 0; }
  info "已备份 sshd_config -> $bak"

  # 写入: 已有 ^Port 则替换，否则追加
  if grep -qE '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config; then
    sed -i -E "s@^[[:space:]]*Port[[:space:]]+[0-9]+@Port $newport@" /etc/ssh/sshd_config
  else
    printf '\n# 由 fail2ban-setup.sh 设置\nPort %s\n' "$newport" >> /etc/ssh/sshd_config
  fi

  # 语法校验，失败即回滚
  if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/dev/null; then
      cp -a "$bak" /etc/ssh/sshd_config
      warn "sshd 配置校验失败，已回滚，端口保持 $cur"
      return 0
    fi
  fi

  CHANGE_SSHD_PORT=1
  NEW_SSHD_PORT="$newport"
  ok "SSH 端口已改为 $newport (备份: $bak)"
  warn "注意: 脚本不会自动重启 sshd。请**新开一个终端**用端口 $newport 测试能连上后，再断开当前连接。"
  warn "      重启命令: systemctl restart ssh   (或 sshd，视发行版而定)"
  return 0
}

NEW_SSHD_PORT=""

# ---------------------------- 8. 启动服务 ----------------------------
start_service(){
  if have_systemd; then
    systemctl restart fail2ban >/dev/null 2>&1
    systemctl enable  fail2ban >/dev/null 2>&1
    systemctl is-active fail2ban >/dev/null 2>&1 || die "fail2ban 未能启动，请查看 journalctl -u fail2ban"
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service fail2ban restart >/dev/null 2>&1
    command -v rc-update >/dev/null 2>&1 && rc-update add fail2ban default >/dev/null 2>&1
  elif command -v service >/dev/null 2>&1; then
    service fail2ban restart >/dev/null 2>&1
    command -v chkconfig >/dev/null 2>&1 && chkconfig fail2ban on >/dev/null 2>&1
  else
    die "未找到服务管理器，请手动启动 fail2ban"
  fi
  sleep 3
  ok "fail2ban 已启动"
}

# ---------------------------- 9. 封禁链路自检 ----------------------------
# 在任何防火墙中搜索 IP: 先 nft 全表搜，再 iptables 搜
# 注意: 不能硬编码表/链 —— 实际落点可能是:
#   nft     : ip filter/f2b-sshd (iptables 兼容层) 或 inet f2b-table/f2b-chain (纯 nft action)
#   iptables: -L f2b-sshd
fw_has_ip(){
  local ip="$1"
  command -v nft >/dev/null 2>&1 \
    && nft list ruleset 2>/dev/null | grep -q -- "$ip" && return 0
  command -v iptables >/dev/null 2>&1 \
    && iptables -S 2>/dev/null | grep -q -- "$ip" && return 0
  return 1
}

verify_ban(){
  fail2ban-client set sshd banip "$TEST_IP" >/dev/null 2>&1 || return 1
  # 等待最多 10 秒让规则真正落地(服务刚重启时存在竞态)
  local i found=0
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if fw_has_ip "$TEST_IP"; then found=1; break; fi
  done
  # 解封必须确认成功: 现在是永久封禁，解封失败会留下一个"永久"残留条目
  fail2ban-client set sshd unbanip "$TEST_IP" >/dev/null 2>&1
  # 复核: 从 fail2ban 与防火墙两侧确认测试 IP 确实已消失
  local still=1
  for _i in 1 2 3 4 5; do
    if fail2ban-client status sshd 2>/dev/null | tr ' ' '\n' | grep -Fxq "$TEST_IP"; then
      sleep 1; continue
    fi
    if fw_has_ip "$TEST_IP"; then sleep 1; continue; fi
    still=0; break
  done
  if [ "$still" = "1" ]; then
    # 强制再解一次并告警 —— 永久封禁下残留条目不会自动过期
    fail2ban-client set sshd unbanip "$TEST_IP" >/dev/null 2>&1
    warn "自检解封未能确认，已重试一次；请手动执行: fail2ban-client set sshd unbanip $TEST_IP"
  fi
  [ "$found" = "1" ]
}

# ============================== 主流程 ==============================
printf '\n=== Fail2ban SSH 防护部署脚本 v%s ===\n\n' "$VERSION"

install_fail2ban

UNIT="$(detect_ssh_unit)"
BACKEND="$(detect_backend "$UNIT")"
ACTION="$(detect_action)"

if [ -z "$PORT" ]; then
  PORT="$(detect_ssh_port)"
  info "自动探测 SSH 端口: $PORT"
else
  info "使用指定 SSH 端口: $PORT"
fi

# ---------- 交互式询问 (可用 -y/-n 跳过) ----------
if [ "$NO_INTERACTIVE" != "1" ] && [ -t 0 ]; then
  # 注意: 内容以 "--" 开头，必须走格式串，否则被 printf 当成选项
  printf '\n%s\n' '---- 参数确认 (直接回车 = 使用括号内默认值) ----' >&2

  # 1) SSH 端口
  maybe_change_sshd_port "$PORT"
  [ "$CHANGE_SSHD_PORT" = "1" ] && PORT="$NEW_SSHD_PORT"

  # 2) 最大失败次数
  MR="$(ask "  > 最大失败次数 [2-10] (默认 $MAXRETRY): " "$MAXRETRY")"
  case "$MR" in
    ''|*[!0-9]*) warn "maxretry '$MR' 非法，保持 $MAXRETRY";;
    *)
      if [ "$MR" -ge 2 ] 2>/dev/null && [ "$MR" -le 10 ] 2>/dev/null; then
        MAXRETRY="$MR"
      else
        warn "maxretry 需在 2-10 之间，保持 $MAXRETRY"
      fi;;
  esac

  # 3) 封禁时长(小时) —— 默认永久
  BT="$(ask "  > 封禁时长[小时] (默认 永久 ; 输入 p/-1/0 也是永久): " "p")"
  case "$BT" in
    p|P|-1|0) PERMANENT=1; info "封禁方式: 永久 (bantime = -1)，需手动解封";;
    ''|*[!0-9]*) warn "bantime '$BT' 非法，保持永久封禁"; PERMANENT=1;;
    *)
      if [ "$BT" -ge 1 ] 2>/dev/null && [ "$BT" -le 876000 ] 2>/dev/null; then
        BANTIME_HOURS="$BT"; PERMANENT=0
      else
        warn "bantime 需在 1-876000 小时之间，保持永久封禁"; PERMANENT=1
      fi;;
  esac

  # 4) 统计窗口(秒)
  FT="$(ask "  > 统计窗口[秒] (默认 ${FINDTIME}s ≈ $((FINDTIME/3600)) 小时): " "$FINDTIME")"
  case "$FT" in
    ''|*[!0-9]*) warn "findtime '$FT' 非法，保持 ${FINDTIME}s";;
    *)
      if [ "$FT" -ge 60 ] 2>/dev/null && [ "$FT" -le 604800 ] 2>/dev/null; then
        FINDTIME="$FT"
      else
        warn "findtime 需在 60-604800 秒之间，保持 ${FINDTIME}s"
      fi;;
  esac

  printf '%s\n' '--------------------------------------------------' '' >&2
fi

if [ "$PERMANENT" = "1" ]; then
  ok "最终参数: 端口=$PORT  失败${MAXRETRY}次/${FINDTIME}s  封禁=永久"
else
  ok "最终参数: 端口=$PORT  失败${MAXRETRY}次/${FINDTIME}s  封禁${BANTIME_HOURS}h"
fi

if [ "$BACKEND" = "systemd" ]; then
  ok "日志后端: systemd-journald (单元: $UNIT)"
else
  LP="$(detect_logpath)"
  ok "日志后端: 文件 ($LP)"
  [ -f "$LP" ] || warn "$LP 当前不存在！若系统只装 journald，请改用 --backend systemd"
fi

ok "封禁动作: $ACTION"

# firewalld 与 iptables 动作可能冲突
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  warn "检测到 firewalld 运行中；如封禁不生效，请用 --action nftables 或改用 firewallcmd 动作"
fi

CUR_IP="$(detect_own_ip)"   # 独立解析: 避免子 shell 内赋值丢失导致提示不打印
IGNORE="$(build_ignoreip)"
[ -n "$CUR_IP" ] && info "检测到当前登录来源 IP $CUR_IP，已加入白名单(防自锁)"
write_jail "$PORT" "$BACKEND" "$ACTION" "$UNIT" "$IGNORE"
start_service

if [ "$SKIP_TEST" = "1" ]; then
  warn "已跳过封禁链路自检 (--no-test)"
elif verify_ban "$ACTION"; then
  ok "封禁链路自检通过 (测试 IP 已封禁并解封)"
else
  warn "自检未能在防火墙链中找到测试 IP，请手动确认: fail2ban-client status sshd"
fi

if [ "$CHANGE_SSHD_PORT" = "1" ]; then
  # 注意: 此处 heredoc 不能加引号，否则 ${NEW_SSHD_PORT} 不会被展开
  cat <<PORTWARN

================= 重要提示 ================
  你修改了 SSH 端口，但 sshd 尚未重启，新端口还未生效。
  请务必:
    1) 先**新开终端**用端口 $NEW_SSHD_PORT 测试登录成功
    2) 确认后再断开当前连接
    3) 如需重启: systemctl restart ssh   (或 sshd)
  fail2ban 侧已按新端口 $NEW_SSHD_PORT 配置完毕。
==========================================
PORTWARN
fi

cat <<SUMMARY

================= 部署完成 ================
  jail 名称   : sshd
  SSH 端口    : $PORT
  日志后端    : $BACKEND $( [ "$BACKEND" = systemd ] && printf '(unit: %s)' "$UNIT" )
  封禁动作    : $ACTION
  触发条件    : ${FINDTIME}s 内失败 ${MAXRETRY} 次
  封禁时长    : $( [ "$PERMANENT" = "1" ] && echo "永久 (bantime=-1，重启后仍保留)" || echo "${BANTIME_HOURS} 小时" )
  白名单      : $IGNORE
  配置文件    : $JAIL_FILE
--------------------------------------------
  查看状态    : fail2ban-client status sshd
  查看被封IP  : fail2ban-client status sshd | grep 'Banned IP'
  手动解封    : fail2ban-client set sshd unbanip <IP>
  手动封禁    : fail2ban-client set sshd banip <IP>
  永久封禁说明: 条目不会被自动清理，fail2ban 重启后也会从数据库恢复；
                误封请务必用上面的 unbanip 手动解除。
============================================
SUMMARY
