# 服务器安全重新配置完整指南

## 阶段 1: 紧急清理和评估（立即执行）

### 1.1 系统状态评估和备份

```bash
# 1. 创建当前状态快照
mkdir -p /tmp/incident_backup/$(date +%Y%m%d_%H%M%S)
cd /tmp/incident_backup/$(date +%Y%m%d_%H%M%S)

# 备份关键配置和日志
tar -czf system_state.tar.gz \
    /etc/passwd /etc/shadow /etc/group \
    /etc/ssh/ /etc/nginx/ /etc/mysql/ \
    /var/log/auth.log* /var/log/syslog* \
    /var/log/nginx/ /root/.ssh/ \
    /var/spool/cron/ 2>/dev/null

# 记录当前进程和网络状态
ps auxf > processes_full.txt
netstat -tulpnw > network_connections.txt
ss -tulpnw > socket_stats.txt
lsof -i > open_files_network.txt
crontab -l > root_crontab.txt 2>/dev/null
```

### 1.2 立即清理恶意内容

```bash
# 1. 清理可疑SSH密钥
cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.incident_backup
# 检查每个密钥，删除不认识的
nano /root/.ssh/authorized_keys

# 2. 检查并清理可疑定时任务
echo "=== 检查可疑定时任务 ==="
for hash in 87086a38e2337318a94b88074a352982 \
           2937a1d2a949712162af23eda9b44be7 \
           c02139b0bb3a6f185c97abc5dcaa8cc2 \
           880f47db9dfc2aa146f05feff67a3ea2 \
           d5644f974fcaac0560720e1c37e76a25 \
           a50afd8f7d0e95dc2fd7bbbcfdcccd82; do
    if [ -f "/www/server/cron/$hash" ]; then
        echo "发现可疑文件: /www/server/cron/$hash"
        cat "/www/server/cron/$hash"
        echo "删除此文件? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            rm -f "/www/server/cron/$hash"
        fi
    fi
done

# 3. 清理所有用户的crontab
for user in $(cut -f1 -d: /etc/passwd); do
    if crontab -u $user -l >/dev/null 2>&1; then
        echo "用户 $user 的定时任务:"
        crontab -u $user -l
        echo "---"
    fi
done

# 4. 查找可疑文件
find / -type f -name "*mining*" -o -name "*xmrig*" -o -name "*kdevtmpfsi*" 2>/dev/null
find /tmp /var/tmp -type f -executable -mtime -7 2>/dev/null
find /dev/shm -type f 2>/dev/null
```

### 1.3 终止可疑进程

```bash
# 查找并终止可疑进程
ps aux | grep -E "(mining|xmrig|kdevtmpfsi|cryptonight|stratum)" | grep -v grep
ps aux | awk '$3 > 80.0' | grep -v 'root.*\[.*\]'  # 高CPU使用率进程

# 检查网络连接
netstat -tupln | grep -v '127.0.0.1\|::1' | sort

# 如果发现可疑进程，记录PID后终止
# kill -9 <可疑进程PID>
```

## 阶段 2: 系统基础安全加固

### 2.1 用户和权限管理

```bash
# 1. 更改所有密码
passwd root  # 使用强密码: 16位以上，包含大小写字母、数字、特殊字符

# 2. 检查用户账户
cat /etc/passwd | grep -E "bash|sh$"
# 删除不需要的用户账户
# userdel -r suspicious_user

# 3. 创建管理用户（替代直接使用root）
useradd -m -s /bin/bash admin
passwd admin
usermod -aG sudo admin

# 4. 设置sudo权限
echo "admin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/admin
chmod 440 /etc/sudoers.d/admin

# 5. 锁定系统用户
for user in bin daemon adm lp sync shutdown halt mail operator games ftp nobody; do
    usermod -L $user 2>/dev/null
done
```

### 2.2 SSH 服务强化配置

```bash
# 备份原配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# 创建新的SSH配置
cat > /etc/ssh/sshd_config << 'EOF'
# SSH强化配置
Port 22334                              # 使用非标准端口
Protocol 2
AddressFamily inet                      # 仅IPv4

# 认证设置
PermitRootLogin no                      # 禁止root直接登录
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no               # 禁用密码认证
ChallengeResponseAuthentication no
UsePAM yes

# 连接限制
MaxAuthTries 3
MaxStartups 3:30:10
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# 用户限制
AllowUsers admin                        # 只允许特定用户
DenyUsers root
DenyGroups root

# 安全选项
PermitEmptyPasswords no
PermitUserEnvironment no
Compression no
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no

# 加密设置
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512

# 日志
LogLevel VERBOSE
SyslogFacility AUTH

# Banner
Banner /etc/ssh/banner
EOF

# 创建SSH警告横幅
cat > /etc/ssh/banner << 'EOF'
*******************************************************************************
                              WARNING
*******************************************************************************
This system is for authorized users only. All activities are logged and
monitored. Unauthorized access is prohibited and will be prosecuted.
*******************************************************************************
EOF

# 生成新的SSH主机密钥
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# 测试配置
sshd -t
if [ $? -eq 0 ]; then
    systemctl restart sshd
    echo "SSH配置已更新，新端口: 22334"
else
    echo "SSH配置错误，请检查"
fi
```

### 2.3 防火墙配置（高级版本）

```bash
# 安装和配置UFW
apt update && apt install -y ufw

# 重置防火墙规则
ufw --force reset

# 默认策略
ufw default deny incoming
ufw default deny forward
ufw default allow outgoing

# 允许本地回环
ufw allow in on lo
ufw allow out on lo

# SSH访问（使用新端口）
ufw allow 22334/tcp comment 'SSH'

# Web服务
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 888/tcp comment 'Panel'  # 如果使用面板

# 限制连接数（防止暴力破解）
ufw limit 22334/tcp
ufw limit ssh

# 阻止常见攻击端口
ufw deny 23    # Telnet
ufw deny 135   # Windows RPC
ufw deny 139   # NetBIOS
ufw deny 445   # SMB
ufw deny 1433  # MSSQL
ufw deny 3389  # RDP
ufw deny 5432  # PostgreSQL
ufw deny 6379  # Redis

# 启用防火墙
ufw --force enable

# 配置更详细的iptables规则
cat > /etc/iptables/custom.rules << 'EOF'
# 自定义iptables规则
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# 允许本地回环
-A INPUT -i lo -j ACCEPT

# 允许已建立的连接
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH连接限制（每分钟最多3次连接尝试）
-A INPUT -p tcp --dport 22334 -m state --state NEW -m recent --set --name SSH
-A INPUT -p tcp --dport 22334 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
-A INPUT -p tcp --dport 22334 -m state --state NEW -j ACCEPT

# Web服务
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP限制
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# 记录被拒绝的连接
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

COMMIT
EOF
```

### 2.4 Fail2Ban 强化配置

```bash
# 安装Fail2Ban
apt install -y fail2ban

# 创建自定义配置
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# 全局设置
bantime = 7200              # 封禁2小时
findtime = 600              # 10分钟内
maxretry = 3                # 最大尝试次数
backend = systemd           # 使用systemd日志
destemail = admin@localhost
sendername = Fail2Ban
mta = sendmail
protocol = tcp
chain = INPUT
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s

# SSH保护
[sshd]
enabled = true
port = 22334
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600
findtime = 600

# Nginx HTTP认证
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

# Nginx攻击防护
[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2

# 递归封禁
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = %(banaction)s[name=%(__name__)s-%(protocol)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
           %(mta)s-whois-lines[name=%(__name__)s, dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]
protocol = tcp
port = 0:65535
bantime = 604800  # 7天
findtime = 86400  # 24小时
maxretry = 5
EOF

# 创建自定义过滤器
cat > /etc/fail2ban/filter.d/nginx-badbots.conf << 'EOF'
[Definition]
badbots = autoget|download|pycurl|wget|curl
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*".*(?:%(badbots)s)
ignoreregex =
EOF

# 启动服务
systemctl enable fail2ban
systemctl restart fail2ban

# 检查状态
fail2ban-client status
```

## 阶段 3: 系统监控和检测

### 3.1 入侵检测系统

```bash
# 安装rootkit检测工具
apt install -y rkhunter chkrootkit unhide

# 配置rkhunter
cat > /etc/rkhunter.conf.local << 'EOF'
UPDATE_MIRRORS=1
MIRRORS_MODE=0
WEB_CMD=""
DISABLE_TESTS="suspscan hidden_procs deleted_files packet_cap_apps apps"
SCRIPTWHITELIST="/usr/bin/egrep /usr/bin/fgrep /usr/bin/which /usr/bin/ldd"
ALLOWHIDDENDIR="/etc/.java"
ALLOWHIDDENDIR="/dev/.static"
ALLOWHIDDENDIR="/dev/.udev"
ALLOWPROCDELFILE="/sbin/dhclient"
PKGMGR=DPKG
EOF

# 更新rkhunter数据库
rkhunter --update

# 初始化文件数据库
rkhunter --propupd

# 安装AIDE（高级入侵检测环境）
apt install -y aide

# 初始化AIDE数据库
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 创建定期检查脚本
cat > /usr/local/bin/security_scan.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/security_scan.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] 开始安全扫描..." | tee -a $LOG_FILE

# RKHunter扫描
echo "[$DATE] 运行RKHunter扫描..." | tee -a $LOG_FILE
rkhunter --check --skip-keypress --report-warnings-only | tee -a $LOG_FILE

# ChkRootkit扫描
echo "[$DATE] 运行ChkRootkit扫描..." | tee -a $LOG_FILE
chkrootkit | grep -v "nothing found" | tee -a $LOG_FILE

# AIDE检查
echo "[$DATE] 运行AIDE完整性检查..." | tee -a $LOG_FILE
aide --check | tee -a $LOG_FILE

# 检查异常进程
echo "[$DATE] 检查异常进程..." | tee -a $LOG_FILE
ps aux --sort=-%cpu | head -20 | tee -a $LOG_FILE

# 检查网络连接
echo "[$DATE] 检查网络连接..." | tee -a $LOG_FILE
netstat -tupln | grep -v '127.0.0.1\|::1' | tee -a $LOG_FILE

echo "[$DATE] 安全扫描完成." | tee -a $LOG_FILE
echo "----------------------------------------" | tee -a $LOG_FILE
EOF

chmod +x /usr/local/bin/security_scan.sh
```

### 3.2 实时监控系统

```bash
# 安装实时监控工具
apt install -y htop iotop iftop auditd

# 配置audit系统
cat > /etc/audit/rules.d/custom.rules << 'EOF'
# 删除所有规则
-D

# 设置缓冲区大小
-b 320

# 监控系统调用失败
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# 监控网络环境变化
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale

# 监控用户/组信息修改
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# 监控登录记录
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# 监控进程和会话启动
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# 监控权限提升
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

# 监控文件访问
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

# 监控特权命令
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged-su
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged-sudo

# 监控SSH密钥
-w /root/.ssh -p wa -k rootkey

# 不可变规则（必须在最后）
-e 2
EOF

# 重启auditd
systemctl restart auditd

# 创建实时监控脚本
cat > /usr/local/bin/realtime_monitor.sh << 'EOF'
#!/bin/bash

ALERT_LOG="/var/log/security_alerts.log"
CPU_THRESHOLD=80
MEMORY_THRESHOLD=80

while true; do
    DATE=$(date '+%Y-%m-%d %H:%M:%S')

    # 检查CPU使用率
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2+$4}' | cut -d% -f1)
    CPU_USAGE=${CPU_USAGE%.*}  # 取整

    if [ "$CPU_USAGE" -gt "$CPU_THRESHOLD" ]; then
        echo "[$DATE] 警告: CPU使用率过高: ${CPU_USAGE}%" >> $ALERT_LOG
        ps aux --sort=-%cpu | head -10 >> $ALERT_LOG
    fi

    # 检查内存使用率
    MEM_USAGE=$(free | awk 'FNR==2{printf "%.0f", $3/($3+$4)*100}')
    if [ "$MEM_USAGE" -gt "$MEMORY_THRESHOLD" ]; then
        echo "[$DATE] 警告: 内存使用率过高: ${MEM_USAGE}%" >> $ALERT_LOG
        ps aux --sort=-%mem | head -10 >> $ALERT_LOG
    fi

    # 检查可疑网络连接
    SUSPICIOUS_CONN=$(netstat -tupln | grep -E ":80[0-9][0-9]|:443[0-9]|:999[0-9]" | grep -v grep)
    if [ ! -z "$SUSPICIOUS_CONN" ]; then
        echo "[$DATE] 警告: 发现可疑网络连接:" >> $ALERT_LOG
        echo "$SUSPICIOUS_CONN" >> $ALERT_LOG
    fi

    sleep 60  # 每分钟检查一次
done
EOF

chmod +x /usr/local/bin/realtime_monitor.sh

# 创建systemd服务
cat > /etc/systemd/system/realtime-monitor.service << 'EOF'
[Unit]
Description=Real-time Security Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/realtime_monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable realtime-monitor
systemctl start realtime-monitor
```

## 阶段 4: Web 服务安全配置

### 4.1 Nginx 安全配置

```bash
# 备份现有配置
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

# 创建安全的Nginx配置
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    charset utf-8;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    log_not_found off;
    types_hash_max_size 4096;
    client_max_body_size 16M;

    # MIME
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 安全头设置
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 限速配置
    limit_req_status 429;
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for" '
                   '$request_time $upstream_response_time';

    log_format security '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" '
                       '"$http_user_agent" "$request_time"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # SSL设置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # 隐藏Nginx版本
    server_tokens off;

    # 包含其他配置
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# 创建安全的默认站点配置
cat > /etc/nginx/sites-available/default << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # 应用限速
    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;

    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # 隐藏敏感文件
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # 阻止常见攻击
    location ~* \.(sql|bak|backup|old|orig|tmp)$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # 阻止PHP执行
    location ~* \.(php|php3|php4|php5|phtml)$ {
        deny all;
        access_log /var/log/nginx/security.log security;
    }

    # 根目录
    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }

    # 日志配置
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
}
EOF

# 测试配置
nginx -t && systemctl reload nginx
```

### 4.2 数据库安全配置（MySQL/MariaDB）

```bash
# 运行安全配置脚本
mysql_secure_installation

# 创建额外的安全配置
cat >> /etc/mysql/mysql.conf.d/security.cnf << 'EOF'
[mysqld]
# 安全设置
skip-symbolic-links = 1
local-infile = 0
skip-show-database
secure-file-priv = /var/lib/mysql-files/

# 网络安全
bind-address = 127.0.0.1
skip-networking = 0
max_connections = 100
max_user_connections = 50

# 日志设置
log-error = /var/log/mysql/error.log
general_log = 1
general_log_file = /var/log/mysql/general.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# 性能设置
query_cache_type = 1
query_cache_limit = 1M
query_cache_size = 16M
EOF

systemctl restart mysql
```

## 阶段 5: 自动化监控和响应

### 5.1 创建监控 Dashboard 脚本

```bash
cat > /usr/local/bin/security_dashboard.sh << 'EOF'
#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

clear
echo -e "${GREEN}==================== 服务器安全状态面板 ====================${NC}"
echo -e "更新时间: $(date)"
echo

# 系统基本信息
echo -e "${GREEN}[系统信息]${NC}"
echo "系统负载: $(uptime | cut -d',' -f1-3)"
echo "内存使用: $(free -h | awk '/^Mem/ {print $3"/"$2" ("$3/$2*100"%)"}')"
echo "磁盘使用: $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5")"}')"
echo

# 网络连接
echo -e "${GREEN}[网络连接]${NC}"
CONN_COUNT=$(netstat -ant | grep ESTABLISHED | wc -l)
echo "当前连接数: $CONN_COUNT"
echo "监听端口:"
netstat -tlnp | grep LISTEN | head -10
echo

# SSH登录状态
echo -e "${GREEN}[SSH状态]${NC}"
FAILED_SSH=$(grep "Failed password" /var/log/auth.log | tail -n 5 | wc -l)
if [ $FAILED_SSH -gt 0 ]; then
    echo -e "${RED}最近5次失败登录:${NC}"
    grep "Failed password" /var/log/auth.log | tail -n 5 | cut -d' ' -f1-3,9-11
else
    echo -e "${GREEN}无最近失败登录${NC}"
fi
echo

# Fail2Ban状态
echo -e "${GREEN}[Fail2Ban状态]${NC}"
if systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}Fail2Ban运行正常${NC}"
    fail2ban-client status | grep "Jail list"
    BANNED_IPS=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | cut -d: -f2 | wc -w)
    echo "当前封禁IP数量: $BANNED_IPS"
else
    echo -e "${RED}Fail2Ban未运行${NC}"
fi
echo

# 进程监控
echo -e "${GREEN}[高CPU进程]${NC}"
ps aux --sort=-%cpu | head -6 | tail -5
echo

echo -e "${GREEN}[高内存进程]${NC}"
ps aux --sort=-%mem | head -6 | tail -5
echo

# 安全检查
echo -e "${GREEN}[安全检查]${NC}"
# 检查可疑进程
SUSPICIOUS=$(ps aux | grep -E "(mining|xmrig|kdevtmpfsi)" | grep -v grep | wc -l)
if [ $SUSPICIOUS -gt 0 ]; then
    echo -e "${RED}发现可疑进程!${NC}"
else
    echo -e "${GREEN}未发现可疑进程${NC}"
fi

# 检查磁盘使用率
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
if [ $DISK_USAGE -gt 90 ]; then
    echo -e "${RED}磁盘使用率过高: ${DISK_USAGE}%${NC}"
elif [ $DISK_USAGE -gt 80 ]; then
    echo -e "${YELLOW}磁盘使用率警告: ${DISK_USAGE}%${NC}"
else
    echo -e "${GREEN}磁盘使用率正常: ${DISK_USAGE}%${NC}"
fi

echo
echo -e "${GREEN}============================================================${NC}"
EOF

chmod +x /usr/local/bin/security_dashboard.sh
```

### 5.2 创建自动化响应系统

```bash
cat > /usr/local/bin/auto_incident_response.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/incident_response.log"
EMAIL="admin@localhost"
QUARANTINE_DIR="/var/quarantine"

mkdir -p $QUARANTINE_DIR

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# 检查高CPU使用率进程
check_high_cpu() {
    HIGH_CPU_PROCS=$(ps aux --sort=-%cpu | awk '$3 > 90.0 && NR > 1 {print $2,$11}')
    if [ ! -z "$HIGH_CPU_PROCS" ]; then
        log_message "警告: 发现高CPU使用率进程"
        echo "$HIGH_CPU_PROCS" >> $LOG_FILE

        # 自动终止已知的挖矿进程
        ps aux | grep -E "(mining|xmrig|kdevtmpfsi|cryptonight)" | grep -v grep | awk '{print $2}' | while read pid; do
            log_message "自动终止可疑进程 PID: $pid"
            kill -9 $pid 2>/dev/null
        done
    fi
}

# 检查可疑文件
check_suspicious_files() {
    # 检查临时目录中的可执行文件
    find /tmp /var/tmp -type f -executable -newer /tmp -print0 2>/dev/null | while IFS= read -r -d '' file; do
        log_message "发现可疑可执行文件: $file"
        file_info=$(file "$file")
        log_message "文件信息: $file_info"

        # 隔离可疑文件
        mv "$file" "$QUARANTINE_DIR/$(basename $file).$(date +%s)" 2>/dev/null
        log_message "已隔离文件: $file"
    done
}

# 检查网络连接
check_network_connections() {
    # 检查到已知挖矿池的连接
    MINING_POOLS="stratum pool.minergate.com xmr-pool"
    for pool in $MINING_POOLS; do
        if netstat -tupln | grep -i $pool; then
            log_message "警告: 发现到挖矿池的连接: $pool"
            # 可以在这里添加自动断开连接的逻辑
        fi
    done

    # 检查异常端口连接
    SUSPICIOUS_PORTS=$(netstat -tupln | awk '$4 ~ /:8080$|:4444$|:7777$|:9999$/ {print $4,$7}')
    if [ ! -z "$SUSPICIOUS_PORTS" ]; then
        log_message "发现可疑端口连接:"
        echo "$SUSPICIOUS_PORTS" >> $LOG_FILE
    fi
}

# 检查SSH暴力破解
check_ssh_attacks() {
    RECENT_FAILURES=$(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    if [ $RECENT_FAILURES -gt 50 ]; then
        log_message "警告: 今日SSH失败登录次数过多: $RECENT_FAILURES"

        # 获取攻击IP并加入黑名单
        grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | \
        awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -5 | \
        while read count ip; do
            if [ $count -gt 10 ]; then
                log_message "自动封禁攻击IP: $ip (失败次数: $count)"
                fail2ban-client set sshd banip $ip 2>/dev/null || iptables -A INPUT -s $ip -j DROP
            fi
        done
    fi
}

# 检查系统完整性
check_system_integrity() {
    # 检查关键系统文件
    CRITICAL_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config"
    for file in $CRITICAL_FILES; do
        if [ -f "$file" ]; then
            current_hash=$(sha256sum "$file" | cut -d' ' -f1)
            stored_hash_file="/var/lib/security_hashes/$(echo $file | tr '/' '_').hash"

            if [ -f "$stored_hash_file" ]; then
                stored_hash=$(cat "$stored_hash_file")
                if [ "$current_hash" != "$stored_hash" ]; then
                    log_message "警告: 关键文件已被修改: $file"
                fi
            else
                # 首次运行，存储哈希值
                mkdir -p /var/lib/security_hashes
                echo "$current_hash" > "$stored_hash_file"
            fi
        fi
    done
}

# 主检查函数
main_check() {
    log_message "开始自动安全检查..."

    check_high_cpu
    check_suspicious_files
    check_network_connections
    check_ssh_attacks
    check_system_integrity

    log_message "自动安全检查完成"
}

# 执行检查
main_check

# 如果检测到问题，发送告警邮件（需要配置邮件系统）
if grep -q "警告" $LOG_FILE; then
    tail -20 $LOG_FILE | mail -s "服务器安全告警" $EMAIL 2>/dev/null || true
fi
EOF

chmod +x /usr/local/bin/auto_incident_response.sh
```

### 5.3 定时任务配置

```bash
# 清理现有的crontab（小心操作）
crontab -r 2>/dev/null || true

# 创建新的安全定时任务
cat > /tmp/security_crontab << 'EOF'
# 安全监控定时任务

# 每5分钟检查一次系统状态
*/5 * * * * /usr/local/bin/auto_incident_response.sh

# 每小时更新rkhunter数据库
0 * * * * /usr/bin/rkhunter --update --quiet

# 每日凌晨2点进行全面安全扫描
0 2 * * * /usr/local/bin/security_scan.sh

# 每日凌晨3点备份重要文件
0 3 * * * /usr/local/bin/backup_important_files.sh

# 每周日凌晨1点运行完整的rootkit检查
0 1 * * 0 /usr/bin/rkhunter --check --skip-keypress --report-warnings-only

# 每月1号更新系统
0 4 1 * * /usr/bin/apt update && /usr/bin/apt upgrade -y && /usr/bin/apt autoremove -y

# 每周清理日志文件（保留30天）
0 5 * * 1 find /var/log -name "*.log" -mtime +30 -delete

# 每日检查磁盘使用率
0 6 * * * df -h | awk '$5 > "90%" {print "磁盘使用率告警:", $0}' | mail -s "磁盘告警" admin@localhost 2>/dev/null || true
EOF

# 安装定时任务
crontab /tmp/security_crontab
rm /tmp/security_crontab

# 验证定时任务
echo "当前定时任务:"
crontab -l
```

## 阶段 6: 备份和恢复策略

### 6.1 完整备份脚本

```bash
cat > /usr/local/bin/backup_important_files.sh << 'EOF'
#!/bin/bash

BACKUP_BASE_DIR="/var/backups/security"
REMOTE_BACKUP_HOST=""  # 设置远程备份主机
REMOTE_BACKUP_USER=""  # 设置远程备份用户
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/backup.log"

# 创建备份目录
mkdir -p $BACKUP_BASE_DIR/{config,database,logs,website}

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# 备份系统配置
backup_configs() {
    log_message "开始备份系统配置..."

    tar -czf "$BACKUP_BASE_DIR/config/system_config_$DATE.tar.gz" \
        /etc/nginx \
        /etc/ssh \
        /etc/mysql \
        /etc/php \
        /etc/fail2ban \
        /etc/iptables \
        /etc/ufw \
        /etc/hosts \
        /etc/hostname \
        /etc/passwd \
        /etc/group \
        /var/spool/cron \
        /root/.ssh \
        2>/dev/null

    log_message "系统配置备份完成"
}

# 备份数据库
backup_databases() {
    log_message "开始备份数据库..."

    # MySQL备份
    if systemctl is-active --quiet mysql; then
        mysqldump --all-databases --single-transaction --routines --triggers > \
            "$BACKUP_BASE_DIR/database/mysql_all_$DATE.sql"
    fi

    log_message "数据库备份完成"
}

# 备份网站文件
backup_websites() {
    log_message "开始备份网站文件..."

    if [ -d "/var/www" ]; then
        tar -czf "$BACKUP_BASE_DIR/website/websites_$DATE.tar.gz" /var/www
    fi

    if [ -d "/www/wwwroot" ]; then
        tar -czf "$BACKUP_BASE_DIR/website/wwwroot_$DATE.tar.gz" /www/wwwroot
    fi

    log_message "网站文件备份完成"
}

# 备份日志文件
backup_logs() {
    log_message "开始备份重要日志..."

    tar -czf "$BACKUP_BASE_DIR/logs/logs_$DATE.tar.gz" \
        /var/log/auth.log* \
        /var/log/syslog* \
        /var/log/nginx/ \
        /var/log/mysql/ \
        /var/log/fail2ban.log* \
        /var/log/security_*.log \
        2>/dev/null

    log_message "日志备份完成"
}

# 清理旧备份
cleanup_old_backups() {
    log_message "清理超过7天的备份..."

    find $BACKUP_BASE_DIR -name "*.tar.gz" -o -name "*.sql" -mtime +7 -delete

    log_message "旧备份清理完成"
}

# 远程备份（可选）
remote_backup() {
    if [ ! -z "$REMOTE_BACKUP_HOST" ] && [ ! -z "$REMOTE_BACKUP_USER" ]; then
        log_message "开始远程备份..."

        rsync -avz --delete-after $BACKUP_BASE_DIR/ \
            $REMOTE_BACKUP_USER@$REMOTE_BACKUP_HOST:/backup/$(hostname)/ \
            2>/dev/null && log_message "远程备份完成" || log_message "远程备份失败"
    fi
}

# 执行备份
main() {
    log_message "开始执行完整备份..."

    backup_configs
    backup_databases
    backup_websites
    backup_logs
    cleanup_old_backups
    remote_backup

    log_message "完整备份执行完成"

    # 计算备份大小
    BACKUP_SIZE=$(du -sh $BACKUP_BASE_DIR | cut -f1)
    log_message "当前备份总大小: $BACKUP_SIZE"
}

main
EOF

chmod +x /usr/local/bin/backup_important_files.sh
```

### 6.2 快速恢复脚本

```bash
cat > /usr/local/bin/emergency_restore.sh << 'EOF'
#!/bin/bash

BACKUP_BASE_DIR="/var/backups/security"
LOG_FILE="/var/log/restore.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# 显示可用备份
show_available_backups() {
    echo "可用的配置备份:"
    ls -la $BACKUP_BASE_DIR/config/system_config_*.tar.gz 2>/dev/null | tail -5
    echo
    echo "可用的数据库备份:"
    ls -la $BACKUP_BASE_DIR/database/mysql_all_*.sql 2>/dev/null | tail -5
}

# 恢复系统配置
restore_config() {
    local backup_file="$1"
    if [ -f "$backup_file" ]; then
        log_message "恢复系统配置从: $backup_file"

        # 创建当前配置的备份
        mkdir -p /var/restore_backup/$(date +%Y%m%d_%H%M%S)

        # 恢复配置
        tar -xzf "$backup_file" -C / 2>/dev/null

        log_message "系统配置恢复完成，请重启相关服务"
    else
        log_message "错误: 备份文件不存在: $backup_file"
    fi
}

# 恢复数据库
restore_database() {
    local backup_file="$1"
    if [ -f "$backup_file" ]; then
        log_message "恢复数据库从: $backup_file"

        # 恢复MySQL数据库
        mysql < "$backup_file"

        log_message "数据库恢复完成"
    else
        log_message "错误: 数据库备份文件不存在: $backup_file"
    fi
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo "========== 紧急恢复工具 =========="
        echo "1. 显示可用备份"
        echo "2. 恢复最新的系统配置"
        echo "3. 恢复指定的系统配置"
        echo "4. 恢复最新的数据库"
        echo "5. 恢复指定的数据库"
        echo "0. 退出"
        echo "=================================="
        read -p "请选择操作: " choice

        case $choice in
            1)
                show_available_backups
                read -p "按Enter继续..."
                ;;
            2)
                latest_config=$(ls -t $BACKUP_BASE_DIR/config/system_config_*.tar.gz 2>/dev/null | head -1)
                restore_config "$latest_config"
                read -p "按Enter继续..."
                ;;
            3)
                show_available_backups
                read -p "请输入完整的配置备份文件路径: " config_file
                restore_config "$config_file"
                read -p "按Enter继续..."
                ;;
            4)
                latest_db=$(ls -t $BACKUP_BASE_DIR/database/mysql_all_*.sql 2>/dev/null | head -1)
                restore_database "$latest_db"
                read -p "按Enter继续..."
                ;;
            5)
                show_available_backups
                read -p "请输入完整的数据库备份文件路径: " db_file
                restore_database "$db_file"
                read -p "按Enter继续..."
                ;;
            0)
                break
                ;;
            *)
                echo "无效选择"
                read -p "按Enter继续..."
                ;;
        esac
    done
}

main_menu
EOF

chmod +x /usr/local/bin/emergency_restore.sh
```

## 阶段 7: 最终检查和文档

### 7.1 安全配置验证脚本

```bash
cat > /usr/local/bin/security_validation.sh << 'EOF'
#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========== 安全配置验证 ==========${NC}"

# 检查SSH配置
echo -e "\n${YELLOW}[SSH安全配置]${NC}"
if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
    echo -e "${GREEN}✓ Root登录已禁用${NC}"
else
    echo -e "${RED}✗ Root登录未禁用${NC}"
fi

if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
    echo -e "${GREEN}✓ 密码认证已禁用${NC}"
else
    echo -e "${RED}✗ 密码认证未禁用${NC}"
fi

SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$SSH_PORT" != "22" ]; then
    echo -e "${GREEN}✓ SSH端口已更改为: $SSH_PORT${NC}"
else
    echo -e "${YELLOW}! SSH仍在使用默认端口22${NC}"
fi

# 检查防火墙
echo -e "\n${YELLOW}[防火墙状态]${NC}"
if ufw status | grep -q "Status: active"; then
    echo -e "${GREEN}✓ UFW防火墙已启用${NC}"
else
    echo -e "${RED}✗ UFW防火墙未启用${NC}"
fi

# 检查Fail2Ban
echo -e "\n${YELLOW}[Fail2Ban状态]${NC}"
if systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}✓ Fail2Ban正在运行${NC}"
    fail2ban-client status | grep "Number of jail"
else
    echo -e "${RED}✗ Fail2Ban未运行${NC}"
fi

# 检查系统更新
echo -e "\n${YELLOW}[系统更新]${NC}"
if systemctl is-enabled --quiet unattended-upgrades; then
    echo -e "${GREEN}✓ 自动更新已启用${NC}"
else
    echo -e "${RED}✗ 自动更新未启用${NC}"
fi

# 检查监控服务
echo -e "\n${YELLOW}[监控服务]${NC}"
if systemctl is-active --quiet realtime-monitor; then
    echo -e "${GREEN}✓ 实时监控正在运行${NC}"
else
    echo -e "${RED}✗ 实时监控未运行${NC}"
fi

if systemctl is-active --quiet auditd; then
    echo -e "${GREEN}✓ 审计服务正在运行${NC}"
else
    echo -e "${RED}✗ 审计服务未运行${NC}"
fi

# 检查关键文件权限
echo -e "\n${YELLOW}[文件权限]${NC}"
if [ "$(stat -c %a /etc/passwd)" = "644" ]; then
    echo -e "${GREEN}✓ /etc/passwd权限正确${NC}"
else
    echo -e "${RED}✗ /etc/passwd权限异常${NC}"
fi

if [ "$(stat -c %a /etc/shadow)" = "640" ]; then
    echo -e "${GREEN}✓ /etc/shadow权限正确${NC}"
else
    echo -e "${RED}✗ /etc/shadow权限异常${NC}"
fi

# 检查定时任务
echo -e "\n${YELLOW}[定时任务]${NC}"
CRON_COUNT=$(crontab -l 2>/dev/null | grep -v "^#" | wc -l)
echo "当前定时任务数量: $CRON_COUNT"
if [ $CRON_COUNT -gt 0 ]; then
    echo "定时任务列表:"
    crontab -l | grep -v "^#"
fi

echo -e "\n${GREEN}========== 验证完成 ==========${NC}"
EOF

chmod +x /usr/local/bin/security_validation.sh
```

### 7.2 创建安全操作手册

```bash
cat > /root/SECURITY_MANUAL.md << 'EOF'
# 服务器安全操作手册

## 日常安全检查清单

### 每日检查
- [ ] 运行安全状态面板: `/usr/local/bin/security_dashboard.sh`
- [ ] 检查安全告警日志: `tail -f /var/log/security_alerts.log`
- [ ] 检查fail2ban状态: `fail2ban-client status`
- [ ] 检查系统负载: `htop`

### 每周检查
- [ ] 运行完整安全扫描: `/usr/local/bin/security_scan.sh`
- [ ] 检查系统更新: `apt list --upgradable`
- [ ] 验证备份完整性: `ls -la /var/backups/security/`
- [ ] 检查磁盘空间: `df -h`

### 每月检查
- [ ] 运行安全配置验证: `/usr/local/bin/security_validation.sh`
- [ ] 更新安全工具数据库: `rkhunter --update`
- [ ] 审查用户账户: `cat /etc/passwd`
- [ ] 检查SSL证书到期时间

## 应急响应程序

### 发现可疑活动时
1. 立即运行: `/usr/local/bin/auto_incident_response.sh`
2. 检查进程: `ps aux --sort=-%cpu | head -20`
3. 检查网络连接: `netstat -tupln`
4. 检查日志: `tail -100 /var/log/auth.log`

### 确认入侵时
1. 断开网络: `systemctl stop networking`
2. 保存证据: 运行 `/usr/local/bin/security_dashboard.sh > /tmp/incident_$(date +%s).log`
3. 恢复备份: `/usr/local/bin/emergency_restore.sh`
4. 重新加固: 重新执行本安全配置指南

## 重要文件路径

### 配置文件
- SSH配置: `/etc/ssh/sshd_config`
- Nginx配置: `/etc/nginx/nginx.conf`
- Fail2Ban配置: `/etc/fail2ban/jail.local`
- UFW配置: `/etc/ufw/`

### 日志文件
- 安全告警: `/var/log/security_alerts.log`
- 入侵响应: `/var/log/incident_response.log`
- 备份日志: `/var/log/backup.log`
- SSH认证: `/var/log/auth.log`

### 工具脚本
- 安全面板: `/usr/local/bin/security_dashboard.sh`
- 自动响应: `/usr/local/bin/auto_incident_response.sh`
- 备份工具: `/usr/local/bin/backup_important_files.sh`
- 紧急恢复: `/usr/local/bin/emergency_restore.sh`

## 联系信息
- 系统管理员: [填写联系方式]
- 安全团队: [填写联系方式]
- 应急电话: [填写电话号码]
EOF

chmod 600 /root/SECURITY_MANUAL.md
```

## 最终执行步骤

### 执行前准备

```bash
# 1. 确保有稳定的网络连接
# 2. 准备好新的SSH密钥对
# 3. 确保有其他管理访问方式（如控制台）

# 创建执行日志
INSTALL_LOG="/var/log/security_install_$(date +%Y%m%d_%H%M%S).log"
echo "安全配置开始时间: $(date)" > $INSTALL_LOG
```

### 分阶段执行建议

1. **阶段 1-2**: 清理和基础加固（可能会断开当前连接）
2. **阶段 3**: 监控系统部署
3. **阶段 4**: Web 服务配置
4. **阶段 5-6**: 自动化和备份
5. **阶段 7**: 验证和文档

### 执行后验证

```bash
# 运行最终验证
/usr/local/bin/security_validation.sh

# 查看安全状态
/usr/local/bin/security_dashboard.sh

# 测试新的SSH连接（使用新端口和密钥）
# ssh -p 22334 -i ~/.ssh/new_key admin@your_server_ip
```

---

**重要提醒:**

1. **备份数据**: 在开始之前，务必备份所有重要数据
2. **测试环境**: 建议先在测试环境验证这些配置
3. **分步执行**: 不要一次性执行所有命令，分阶段进行
4. **保持访问**: 确保始终有备用的访问方式
5. **监控日志**: 执行过程中持续监控日志输出
6. **文档更新**: 根据实际环境调整配置参数

这个配置方案提供了企业级的安全防护，但请根据你的具体环境和需求进行适当调整。
