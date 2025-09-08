# 服务器入侵分析报告和解决方案

## 1. 入侵痕迹分析总结

根据对系统日志和文件的分析，发现以下几个主要问题：

### 1.1 SSH暴力破解攻击
- **问题描述**: 发现大量来自 `198.55.98.*` 网段的SSH暴力破解攻击
- **攻击特征**: 
  - 尝试多种用户名（root, admin, git, mysql, ubuntu等）
  - 使用字典攻击方式
  - 攻击时间集中在9月1日下午
- **当前状态**: SSH端口已更改为8622，有一定缓解作用

### 1.2 可疑SSH密钥
- **问题描述**: 在 `/root/.ssh/authorized_keys` 中发现可疑SSH公钥
- **密钥信息**: `ssh-rsa AAAAB3NzaC1yc2EAAAA... i9196880@gmail.com`
- **风险级别**: 高危 - 可能是攻击者植入的后门

### 1.3 定时任务异常
- **问题描述**: 发现多个使用MD5哈希命名的可疑cron任务
- **可疑任务**:
  ```
  /www/server/cron/87086a38e2337318a94b88074a352982
  /www/server/cron/2937a1d2a949712162af23eda9b44be7
  /www/server/cron/c02139b0bb3a6f185c97abc5dcaa8cc2
  /www/server/cron/880f47db9dfc2aa146f05feff67a3ea2
  /www/server/cron/d5644f974fcaac0560720e1c37e76a25
  /www/server/cron/a50afd8f7d0e95dc2fd7bbbcfdcccd82
  ```

### 1.4 NGINX配置问题
- **当前状态**: NGINX配置文件为空，这是异常的
- **可能原因**: 攻击者可能已清理了恶意配置，或配置被意外删除

### 1.5 挖矿程序嫌疑
- **当前状态**: 未发现明显的挖矿进程
- **分析结果**: 可能已被清理或隐藏，但系统中存在OpenSSL相关文件较多

## 2. 紧急安全加固措施

### 2.1 立即执行的命令

#### 步骤1: 删除可疑SSH密钥
```bash
# 备份当前authorized_keys
cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.backup.$(date +%Y%m%d_%H%M%S)

# 删除可疑密钥（请仔细检查，确保不是您自己的密钥）
sed -i '/i9196880@gmail.com/d' /root/.ssh/authorized_keys

# 验证结果
cat /root/.ssh/authorized_keys
```

#### 步骤2: 检查和清理可疑定时任务
```bash
# 查看可疑的cron脚本内容
for file in /www/server/cron/87086a38e2337318a94b88074a352982 \
           /www/server/cron/2937a1d2a949712162af23eda9b44be7 \
           /www/server/cron/c02139b0bb3a6f185c97abc5dcaa8cc2 \
           /www/server/cron/880f47db9dfc2aa146f05feff67a3ea2 \
           /www/server/cron/d5644f974fcaac0560720e1c37e76a25 \
           /www/server/cron/a50afd8f7d0e95dc2fd7bbbcfdcccd82; do
    if [ -f "$file" ]; then
        echo "=== $file ==="
        cat "$file"
        echo
    fi
done

# 如果发现恶意内容，删除这些文件
# rm -f /www/server/cron/87086a38e2337318a94b88074a352982
# rm -f /www/server/cron/2937a1d2a949712162af23eda9b44be7
# ... 依此类推

# 清理root的crontab中的可疑条目
crontab -l > /tmp/crontab_backup.$(date +%Y%m%d_%H%M%S)
# 手动编辑crontab，删除可疑条目
crontab -e
```

#### 步骤3: 更改所有密码
```bash
# 更改root密码
passwd root

# 如果有其他用户，也要更改密码
# passwd username
```

#### 步骤4: 检查网络连接
```bash
# 检查可疑的网络连接
netstat -tulpn | grep -v '127.0.0.1\|::1'

# 检查是否有可疑进程
ps aux | grep -E 'mining|xmrig|kdevtmpfsi|curl|wget' | grep -v grep
```

### 2.2 系统安全加固

#### 步骤5: 配置SSH安全
```bash
# 编辑SSH配置
nano /etc/ssh/sshd_config

# 添加或修改以下设置：
# PermitRootLogin no                    # 禁止root直接登录
# PasswordAuthentication no             # 禁用密码认证，只允许密钥认证
# MaxAuthTries 3                        # 限制认证尝试次数
# ClientAliveInterval 300               # 设置连接超时
# ClientAliveCountMax 2                 # 设置最大空闲连接数
# AllowUsers your_username              # 只允许特定用户登录

# 重启SSH服务
systemctl restart sshd
```

#### 步骤6: 配置防火墙
```bash
# 安装并启用UFW防火墙
apt update
apt install -y ufw

# 默认拒绝所有入站连接
ufw default deny incoming
ufw default allow outgoing

# 允许SSH（使用当前端口8622）
ufw allow 8622/tcp

# 允许Web服务
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 888/tcp

# 允许MySQL（如果需要远程访问）
# ufw allow 3306/tcp

# 启用防火墙
ufw enable

# 检查状态
ufw status verbose
```

#### 步骤7: 安装和配置Fail2Ban
```bash
# Fail2Ban已安装，检查配置
systemctl status fail2ban

# 查看当前规则
fail2ban-client status

# 检查SSH保护状态
fail2ban-client status sshd

# 创建自定义配置
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 8622
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600
EOF

# 重启Fail2Ban
systemctl restart fail2ban
```

### 2.3 系统监控和检测

#### 步骤8: 安装系统监控工具
```bash
# 安装htop和iotop用于监控
apt install -y htop iotop

# 安装rkhunter和chkrootkit用于rootkit检测
apt install -y rkhunter chkrootkit

# 更新rkhunter数据库
rkhunter --update

# 运行全面扫描
rkhunter --check

# 运行chkrootkit扫描
chkrootkit
```

#### 步骤9: 设置日志监控
```bash
# 创建日志监控脚本
cat > /usr/local/bin/security_monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/security_monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 检查可疑进程
SUSPICIOUS_PROCS=$(ps aux | grep -E 'mining|xmrig|kdevtmpfsi|curl.*sh|wget.*sh' | grep -v grep)
if [ ! -z "$SUSPICIOUS_PROCS" ]; then
    echo "[$DATE] 发现可疑进程:" >> $LOG_FILE
    echo "$SUSPICIOUS_PROCS" >> $LOG_FILE
fi

# 检查高CPU使用率进程
HIGH_CPU=$(ps aux --sort=-%cpu | head -n 10 | awk '$3 > 80.0 {print}')
if [ ! -z "$HIGH_CPU" ]; then
    echo "[$DATE] 发现高CPU使用率进程:" >> $LOG_FILE
    echo "$HIGH_CPU" >> $LOG_FILE
fi

# 检查新的SSH登录
NEW_SSH=$(journalctl --since "1 hour ago" | grep "Accepted\|Failed" | grep ssh)
if [ ! -z "$NEW_SSH" ]; then
    echo "[$DATE] SSH登录活动:" >> $LOG_FILE
    echo "$NEW_SSH" >> $LOG_FILE
fi
EOF

chmod +x /usr/local/bin/security_monitor.sh

# 添加到crontab，每5分钟执行一次
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/security_monitor.sh") | crontab -
```

## 3. NGINX配置恢复

#### 步骤10: 检查和恢复NGINX配置
```bash
# 检查NGINX配置文件
nginx -t

# 如果配置有问题，恢复默认配置
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.$(date +%Y%m%d_%H%M%S)

# 创建基本的安全NGINX配置
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 安全头设置
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Gzip设置
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # 包含其他配置文件
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# 测试配置
nginx -t

# 如果测试通过，重启nginx
systemctl restart nginx
```

## 4. 长期安全措施

### 4.1 定期安全检查
```bash
# 创建每日安全检查脚本
cat > /usr/local/bin/daily_security_check.sh << 'EOF'
#!/bin/bash
REPORT_FILE="/var/log/daily_security_$(date +%Y%m%d).log"
echo "=== $(date) 每日安全检查报告 ===" > $REPORT_FILE

# 检查系统更新
echo "系统更新检查:" >> $REPORT_FILE
apt list --upgradable 2>/dev/null >> $REPORT_FILE

# 检查失败的登录尝试
echo -e "\n最近24小时失败的登录尝试:" >> $REPORT_FILE
journalctl --since "1 day ago" | grep "Failed password" | tail -20 >> $REPORT_FILE

# 检查新安装的软件包
echo -e "\n最近安装的软件包:" >> $REPORT_FILE
grep "install" /var/log/dpkg.log | tail -10 >> $REPORT_FILE

# 检查异常进程
echo -e "\n当前高CPU进程:" >> $REPORT_FILE
ps aux --sort=-%cpu | head -10 >> $REPORT_FILE

# 发送报告邮件（如果配置了邮件系统）
# mail -s "Daily Security Report" admin@yourdomain.com < $REPORT_FILE
EOF

chmod +x /usr/local/bin/daily_security_check.sh

# 添加到每日凌晨2点执行
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/daily_security_check.sh") | crontab -
```

### 4.2 系统更新和维护
```bash
# 设置自动安全更新
apt install -y unattended-upgrades

# 配置自动更新
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# 启用自动更新
systemctl enable unattended-upgrades
systemctl start unattended-upgrades
```

## 5. 备份和恢复策略

### 5.1 重要文件备份
```bash
# 创建备份脚本
cat > /usr/local/bin/backup_important_files.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/security"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# 备份重要配置文件
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz \
    /etc/nginx \
    /etc/ssh \
    /etc/mysql \
    /etc/php \
    /var/spool/cron/crontabs \
    /root/.ssh \
    2>/dev/null

# 备份网站数据（根据实际情况修改路径）
tar -czf $BACKUP_DIR/website_backup_$DATE.tar.gz /www/wwwroot 2>/dev/null

# 保留最近7天的备份
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "备份完成: $BACKUP_DIR"
EOF

chmod +x /usr/local/bin/backup_important_files.sh

# 添加到每日备份
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/backup_important_files.sh") | crontab -
```

## 6. 紧急响应清单

如果再次发现入侵：

1. **立即断网**: `systemctl stop networking`
2. **保存证据**: `ps aux > /tmp/processes.txt; netstat -tulpn > /tmp/connections.txt`
3. **终止可疑进程**: `kill -9 <PID>`
4. **更改所有密码**: `passwd root; passwd <other_users>`
5. **检查系统文件**: `rkhunter --check; chkrootkit`
6. **恢复备份**: 从干净的备份恢复系统

## 7. 联系和报告

- 定期检查 `/var/log/security_monitor.log`
- 监控 `/var/log/daily_security_*.log`
- 设置邮件告警系统
- 考虑使用专业的安全监控服务

---

**重要提醒**: 
1. 执行任何命令前请先备份重要数据
2. 建议在测试环境先验证这些步骤
3. 如果不确定某个文件是否为恶意文件，请先备份再删除
4. 定期更新这个安全方案以应对新的威胁

**执行优先级**:
- 🔴 **高优先级** (立即执行): 步骤1-4
- 🟡 **中优先级** (24小时内): 步骤5-7  
- 🟢 **低优先级** (一周内): 步骤8-10及长期措施
