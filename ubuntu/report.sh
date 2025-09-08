#!/bin/bash
# =====================================================================
#  report.sh - Ubuntu Server Security & System Report
# =====================================================================
#  Author: Ropean
#  Purpose:
#    Collect system and security info, check for suspicious activity,
#    clean malicious proxy entries, run rootkit scans, and package a report archive.
#
#  WARNING:
#    - Run as root
#    - Review before executing on production servers
#    - This script does not remove all malware; it gathers evidence
#      and performs basic cleanup of proxy injections.
#
# =====================================================================
#  CHECKLIST:
#    [x] System info (uptime, kernel, OS, hostname)
#    [x] Users, groups, sudoers
#    [x] Authentication logs (lastlog, auth.log)
#    [x] SSH configs & authorized_keys
#    [x] Processes & resource usage
#    [x] Cron jobs (root, system, users)
#    [x] Network info (IP, routes, listening ports)
#    [x] Firewall rules (iptables, nft)
#    [x] SUID files
#    [x] Recently modified files
#    [x] /tmp, /var/tmp, /dev/shm checks
#    [x] Nginx configs & suspicious scripts
#    [x] Suspicious process/file scan
#    [x] Rootkit scan (rkhunter, chkrootkit)
# =====================================================================
#  Usage:
#    curl -sSL "https://raw.githubusercontent.com/ropean/server/main/ubuntu/report.sh?$(uuidgen)" | sudo bash
#    Report archive will be in /var/log/ir_report_<datetime>.tar.gz
# =====================================================================

set -euo pipefail

# -----------------------------
# Step 0: Define output
# -----------------------------
OUTDIR="/var/log/ir_report_$(date +%F_%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/run.log"
echo "[*] Report directory: $OUTDIR"

log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
save(){ 
  local name="$1"; shift
  log ">> $name"
  { echo "# $name"; "$@" 2>&1; echo; } > "$OUTDIR/${name// /_}.txt" || true
}

# -----------------------------
# Step 1: Install required packages
# -----------------------------
log "[*] Installing required packages..."
sudo apt update || true
sudo apt install -y rkhunter chkrootkit tree net-tools iproute2 || true

# -----------------------------
# Step 2: Clean proxy variables
# -----------------------------
log "[*] Unsetting proxy environment variables..."
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY || true

log "[*] Cleaning /etc/environment proxy entries..."
sudo cp /etc/environment /etc/environment.bak.$(date +%F-%H%M%S)
cat <<'EOF' | sudo tee /etc/environment >/dev/null
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
EOF
source /etc/environment

# -----------------------------
# Step 3: System info
# -----------------------------
save "datetime" date
save "uptime" uptime
save "who" who
save "hostnamectl" sh -c 'command -v hostnamectl >/dev/null && hostnamectl || true'
save "os-release" cat /etc/os-release
save "kernel" uname -a

# -----------------------------
# Step 4: Users & auth
# -----------------------------
save "passwd" cat /etc/passwd
save "group" cat /etc/group
save "sudoers" sh -c 'ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null; [ -f /etc/sudoers ] && sed -n "1,200p" /etc/sudoers; for f in /etc/sudoers.d/*; do [ -f "$f" ] && echo "===== $f =====" && sed -n "1,200p" "$f"; done'
save "lastlog" lastlog
save "auth.log_recent" sh -c 'journalctl -u ssh --no-pager --since "7 days ago" 2>/dev/null || grep -aE "sshd|Failed password|Accepted" -n /var/log/auth.log* 2>/dev/null || true'

# -----------------------------
# Step 5: SSH keys
# -----------------------------
save "sshd_config" sh -c 'grep -vE "^\s*#|^\s*$" /etc/ssh/sshd_config 2>/dev/null || true'
save "authorized_keys" sh -c 'for d in /root /home/*; do f="$d/.ssh/authorized_keys"; [ -f "$f" ] && echo "===== $f =====" && nl -ba "$f"; done'

# -----------------------------
# Step 6: Processes & services
# -----------------------------
save "top_CPU_procs" sh -c 'ps aux --sort=-%cpu | head -n 40'
save "top_MEM_procs" sh -c 'ps aux --sort=-%mem | head -n 40'
save "tree_of_processes" sh -c 'ps axo pid,ppid,user,stat,cmd --forest | head -n 500'
save "systemctl_running" sh -c 'systemctl list-units --type=service --state=running --no-pager'
save "systemctl_enabled" sh -c 'systemctl list-unit-files --type=service --state=enabled --no-pager'
save "systemd_timers" sh -c 'systemctl list-timers --all --no-pager'
save "rc_local_and_preload" sh -c '[ -f /etc/rc.local ] && sed -n "1,200p" /etc/rc.local; [ -f /etc/ld.so.preload ] && sed -n "1,200p" /etc/ld.so.preload || true'

# -----------------------------
# Step 7: Cron jobs
# -----------------------------
save "crontab_root" sh -c 'crontab -l 2>/dev/null || true'
save "crontab_system" sh -c 'sed -n "1,200p" /etc/crontab 2>/dev/null || true'
save "cron_dirs" sh -c 'for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do echo "===== $d ====="; ls -la "$d" 2>/dev/null; done'
save "user_crontabs" sh -c 'ls -la /var/spool/cron /var/spool/cron/crontabs 2>/dev/null; for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && echo "===== $f =====" && sed -n "1,200p" "$f"; done'

# -----------------------------
# Step 8: Network info
# -----------------------------
save "ip_addr" sh -c 'ip a 2>/dev/null || ifconfig -a 2>/dev/null || true'
save "ip_route" sh -c 'ip r 2>/dev/null || route -n 2>/dev/null || true'
save "resolv_conf" cat /etc/resolv.conf
save "listening_sockets" sh -c 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || true'
save "iptables_nft" sh -c 'iptables -S 2>/dev/null; iptables -L -n -v 2>/dev/null; nft list ruleset 2>/dev/null || true'

# -----------------------------
# Step 9: File system checks
# -----------------------------
save "suid_files" sh -c 'find / -xdev -perm -4000 -type f -printf "%p %m %u %g\n" 2>/dev/null | sort'
save "recently_modified_7d" sh -c 'find / -xdev -mtime -7 -ls 2>/dev/null | head -n 2000'
save "tmp_var_tmp_shm_files" sh -c 'ls -la /tmp /var/tmp /dev/shm 2>/dev/null'
save "procs_from_tmp" sh -c 'ps axo pid,user,cmd | grep -E "/tmp|/var/tmp|/dev/shm" --color=never | grep -v grep || true'

# -----------------------------
# Step 10: Nginx checks
# -----------------------------
save "nginx_V" sh -c 'nginx -V 2>&1 || true'
save "nginx_confs" sh -c 'for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-*/**/*; do [ -f "$f" ] && echo "===== $f =====" && sed -n "1,300p" "$f"; done 2>/dev/null'
save "grep_suspicious_in_nginx" sh -c 'grep -RnaE "<script|eval\(|atob\(|fromCharCode|document\.write|http[s]?://" /etc/nginx 2>/dev/null || true'

# -----------------------------
# Step 11: Suspicious process/file scan
# -----------------------------
SUS="xmrig|xmr|minerd|mining|kinsing|kdevtmpfsi|NetworkManager|sysupdate|kworker|watchdogs|bashminer|crypto"
save "process_grep_miner" sh -c "ps aux | grep -Ei \"$SUS\" | grep -v grep || true"
save "disk_grep_miner" sh -c "grep -RIl -m1 -E \"$SUS\" /usr /bin /lib /etc /var /opt 2>/dev/null | head -n 200"

# -----------------------------
# Step 12: Rootkit scan
# -----------------------------
save "rkhunter_scan" sh -c 'rkhunter --update && rkhunter --propupd && rkhunter --check --sk'
save "chkrootkit_scan" sh -c 'chkrootkit || true'

# -----------------------------
# Step 13: Package report
# -----------------------------
ARCHIVE="${OUTDIR}.tar.gz"
tar -C "$(dirname "$OUTDIR")" -czf "$ARCHIVE" "$(basename "$OUTDIR")"
log "[*] Report generated: $ARCHIVE"

# -----------------------------
# Step 14: Summary
# -----------------------------
log "[*] Summary:"
log "  Report directory: $OUTDIR"
log "  Report archive: $ARCHIVE"
log "  Included: system info, users, auth, ssh, processes, cron, network, firewall, suid files, tmp files, nginx configs, suspicious processes/files, rootkit scan"
log "[*] Done. Review the report carefully. Consider manual investigation for any suspicious findings."
