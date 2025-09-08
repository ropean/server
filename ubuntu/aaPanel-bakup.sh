#!/bin/bash

# aaPanel 完整备份脚本
# 支持Ubuntu/Debian和CentOS/RHEL系统
# 使用方法: curl -sSL https://raw.githubusercontent.com/ropean/server/main/ubuntu/aaPanel-bakup.sh | sudo bash

# 备份文件结构
# /root/aapanel_backup/backup_YYYYMMDD_HHMMSS/
# ├── websites.tar.gz              # 网站文件
# ├── all_databases.sql            # 所有数据库
# ├── databases/                   # 单个数据库文件
# ├── panel.tar.gz                # 面板配置
# ├── nginx.tar.gz                # Nginx配置
# ├── php.tar.gz                  # PHP配置
# ├── mysql_config.tar.gz         # MySQL配置
# ├── pure-ftpd.tar.gz            # FTP配置
# ├── phpmyadmin.tar.gz           # phpMyAdmin
# ├── ssl/                        # SSL证书
# ├── restore.sh                  # 恢复脚本
# └── backup_info.txt             # 备份信息

# 主要功能
# 1. 完整备份内容

# 网站文件: /www/wwwroot/ 下的所有网站
# 数据库: 全部数据库的完整备份
# 面板配置: aaPanel核心配置文件
# Web服务器: Nginx/Apache配置
# PHP配置: 所有PHP版本的配置
# MySQL配置: 数据库服务配置
# FTP配置: Pure-FTPd配置和用户数据
# SSL证书: 包括Let's Encrypt证书
# 其他组件: phpMyAdmin、Node.js、NVM等

# 2. 智能特性

# 自动检测系统环境和已安装组件
# 自动获取MySQL密码（从面板数据库）
# 彩色日志输出，清晰显示备份进度
# 错误处理和警告提示
# 生成详细的备份信息文件

# 3. 便捷恢复

# 自动生成恢复脚本 restore.sh
# 一键恢复所有配置和数据
# 自动设置文件权限
# 服务启停管理

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 检查aaPanel是否安装
check_aapanel() {
    if [[ ! -d "/www/server/panel" ]]; then
        log_error "未检测到aaPanel安装，请确认aaPanel已正确安装"
        exit 1
    fi
    log_info "检测到aaPanel安装目录"
}

# 创建备份目录
create_backup_dir() {
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_BASE_DIR="/root/aapanel_backup"
    BACKUP_DIR="$BACKUP_BASE_DIR/backup_$TIMESTAMP"
    
    mkdir -p "$BACKUP_DIR"
    log_info "备份目录创建完成: $BACKUP_DIR"
}

# 获取MySQL root密码函数
# 功能：提示用户输入MySQL root密码，并验证连接有效性
# 返回：设置全局变量MYSQL_PASS为有效的MySQL密码
get_mysql_password() {
    local max_attempts=3  # 最大尝试次数
    local attempt=1       # 当前尝试次数
    MYSQL_PASS=""        # 全局变量存储密码
    
    log_info "开始获取MySQL root密码..."
    
    # 循环提示用户输入密码，最多尝试3次
    while [[ $attempt -le $max_attempts ]]; do
        echo -n "请输入MySQL root密码 (尝试 $attempt/$max_attempts): "
        # 确保在交互式 shell（本地登录或 ssh 终端）直接运行脚本
        read -s MYSQL_PASS < /dev/tty  # -s参数隐藏输入内容
        echo  # 换行
        
        # 验证密码是否正确
        log_info "验证MySQL密码..."
        if mysqladmin ping -u root --password="$MYSQL_PASS" >/dev/null 2>&1; then
            log_success "MySQL密码验证成功"
            return 0
        else
            log_error "MySQL密码验证失败"
            if [[ $attempt -lt $max_attempts ]]; then
                log_warn "密码错误，请重新输入"
            fi
        fi
        
        ((attempt++))
    done
    
    # 所有尝试都失败
    log_error "MySQL密码验证失败，已达到最大尝试次数($max_attempts)"
    log_error "请检查MySQL服务状态或密码是否正确"
    return 1
}

# 备份数据库
backup_databases() {
    log_step "1. 备份数据库..."
    
    if ! command -v mysqldump >/dev/null 2>&1; then
        log_warn "未找到mysqldump命令，跳过数据库备份"
        return
    fi
    
    get_mysql_password
    
    if [ $? -ne 0 ]; then
        log_error "获取MySQL密码失败，跳过数据库备份"
        return 1
    fi
    
    # 使用环境变量传递密码（避免特殊字符问题）
    export MYSQL_PWD="$MYSQL_PASS"
    
    # 测试MySQL连接
    if mysql -u root -e "SELECT 1;" >/dev/null 2>&1; then
        log_info "MySQL连接测试成功，开始备份数据库..."
        
        # 备份所有数据库
        mysqldump -u root --all-databases --single-transaction --routines --triggers > "$BACKUP_DIR/all_databases.sql" 2>/dev/null
        
        # 单独备份每个数据库
        mkdir -p "$BACKUP_DIR/databases"
        databases=$(mysql -u root -e "SHOW DATABASES;" | grep -Ev '^(Database|information_schema|performance_schema|mysql|sys)$')
        
        for db in $databases; do
            if [[ -n "$db" ]]; then
                mysqldump -u root --single-transaction --routines --triggers "$db" > "$BACKUP_DIR/databases/${db}.sql" 2>/dev/null
                if [ $? -eq 0 ]; then
                    log_info "数据库 $db 备份完成"
                else
                    log_error "数据库 $db 备份失败"
                fi
            fi
        done
        
        log_success "数据库备份完成"
    else
        log_error "无法连接到MySQL数据库，跳过数据库备份"
        # 取消环境变量设置
        unset MYSQL_PWD
        return 1
    fi
    
    # 清理环境变量
    unset MYSQL_PWD
}

# 备份网站文件
backup_websites() {
    log_step "2. 备份网站文件..."
    if [[ -d "/www/wwwroot" ]]; then
        cd /www
        tar --exclude='*.log' --exclude='*.tmp' -czf "$BACKUP_DIR/websites.tar.gz" wwwroot/ 2>/dev/null || {
            log_warn "网站文件备份过程中出现警告，但继续执行"
        }
        log_info "网站文件备份完成"
    else
        log_warn "未找到网站目录 /www/wwwroot"
    fi
}

# 备份aaPanel面板配置
backup_panel_config() {
    log_step "3. 备份aaPanel面板配置..."
    
    if [[ -d "/www/server/panel" ]]; then
        cd /www/server
        tar -czf "$BACKUP_DIR/panel.tar.gz" panel/ 2>/dev/null || {
            log_warn "面板配置备份过程中出现警告，但继续执行"
        }
        log_info "面板配置备份完成"
    fi
}

# 备份Web服务器配置
backup_webserver_config() {
    log_step "4. 备份Web服务器配置..."
    
    cd /www/server
    
    # 备份Nginx配置
    if [[ -d "nginx" ]]; then
        tar -czf "$BACKUP_DIR/nginx.tar.gz" nginx/ 2>/dev/null
        log_info "Nginx配置备份完成"
    fi
    
    # 备份Apache配置（如果存在）
    if [[ -d "apache" ]]; then
        tar -czf "$BACKUP_DIR/apache.tar.gz" apache/ 2>/dev/null
        log_info "Apache配置备份完成"
    fi
}

# 备份PHP配置
backup_php_config() {
    log_step "5. 备份PHP配置..."
    
    if [[ -d "/www/server/php" ]]; then
        cd /www/server
        tar -czf "$BACKUP_DIR/php.tar.gz" php/ 2>/dev/null
        log_info "PHP配置备份完成"
    fi
}

# 备份MySQL配置
backup_mysql_config() {
    log_step "6. 备份MySQL配置..."
    
    cd /www/server
    if [[ -d "mysql" ]]; then
        tar -czf "$BACKUP_DIR/mysql_config.tar.gz" mysql/ 2>/dev/null
        log_info "MySQL配置备份完成"
    fi
    
    # 备份系统MySQL配置文件
    if [[ -f "/etc/mysql/my.cnf" ]]; then
        cp "/etc/mysql/my.cnf" "$BACKUP_DIR/system_my.cnf"
    elif [[ -f "/etc/my.cnf" ]]; then
        cp "/etc/my.cnf" "$BACKUP_DIR/system_my.cnf"
    fi
}

# 备份FTP配置
backup_ftp_config() {
    log_step "7. 备份FTP配置..."
    
    if [[ -d "/www/server/pure-ftpd" ]]; then
        cd /www/server
        tar -czf "$BACKUP_DIR/pure-ftpd.tar.gz" pure-ftpd/ 2>/dev/null
        log_info "Pure-FTPd配置备份完成"
    fi
    
    # 备份FTP用户数据
    if [[ -f "/etc/pure-ftpd/pureftpd.passwd" ]]; then
        cp "/etc/pure-ftpd/pureftpd.passwd" "$BACKUP_DIR/ftp_users.passwd" 2>/dev/null
    fi
    
    if [[ -f "/www/server/panel/data/ftps.json" ]]; then
        cp "/www/server/panel/data/ftps.json" "$BACKUP_DIR/ftp_panel_config.json" 2>/dev/null
    fi
}

# 备份其他组件
backup_other_components() {
    log_step "8. 备份其他组件..."
    
    cd /www/server
    
    # 备份phpMyAdmin
    if [[ -d "phpmyadmin" ]]; then
        tar -czf "$BACKUP_DIR/phpmyadmin.tar.gz" phpmyadmin/ 2>/dev/null
        log_info "phpMyAdmin备份完成"
    fi
    
    # 备份Node.js
    if [[ -d "nodejs" ]]; then
        tar -czf "$BACKUP_DIR/nodejs.tar.gz" nodejs/ 2>/dev/null
        log_info "Node.js备份完成"
    fi
    
    # 备份NVM
    if [[ -d "nvm" ]]; then
        tar -czf "$BACKUP_DIR/nvm.tar.gz" nvm/ 2>/dev/null
        log_info "NVM备份完成"
    fi
    
    # 备份定时任务
    if [[ -d "cron" ]]; then
        tar -czf "$BACKUP_DIR/cron.tar.gz" cron/ 2>/dev/null
        log_info "定时任务备份完成"
    fi
    
    # 备份数据目录
    if [[ -d "data" ]]; then
        tar -czf "$BACKUP_DIR/server_data.tar.gz" data/ 2>/dev/null
        log_info "服务器数据备份完成"
    fi
}

# 备份SSL证书
backup_ssl_certificates() {
    log_step "9. 备份SSL证书..."
    
    # aaPanel SSL证书目录
    if [[ -d "/www/server/panel/vhost/cert" ]]; then
        mkdir -p "$BACKUP_DIR/ssl"
        cp -r "/www/server/panel/vhost/cert"/* "$BACKUP_DIR/ssl/" 2>/dev/null || true
        log_info "aaPanel SSL证书备份完成"
    fi
    
    # Let's Encrypt证书
    if [[ -d "/etc/letsencrypt" ]]; then
        tar -czf "$BACKUP_DIR/letsencrypt.tar.gz" -C /etc letsencrypt/ 2>/dev/null
        log_info "Let's Encrypt证书备份完成"
    fi
}

# 备份系统定时任务
backup_system_cron() {
    log_step "10. 备份系统定时任务..."
    
    # 备份root用户的crontab
    crontab -l > "$BACKUP_DIR/root_crontab.txt" 2>/dev/null || log_warn "无root用户定时任务"
    
    # 备份系统定时任务
    if [[ -d "/etc/cron.d" ]]; then
        tar -czf "$BACKUP_DIR/system_cron.tar.gz" -C /etc cron.d/ cron.daily/ cron.hourly/ cron.monthly/ cron.weekly/ 2>/dev/null
        log_info "系统定时任务备份完成"
    fi
}

# 生成恢复脚本
generate_restore_script() {
    log_step "11. 生成恢复脚本..."
    
    cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash

# aaPanel 恢复脚本
# 请在重新安装aaPanel后运行此脚本

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info "开始恢复aaPanel数据..."
log_info "备份目录: $BACKUP_DIR"

# 检查aaPanel是否已安装
if [[ ! -d "/www/server/panel" ]]; then
    log_error "请先安装aaPanel后再运行恢复脚本"
    exit 1
fi

read -p "确认要恢复数据吗？这将覆盖现有配置 (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "取消恢复操作"
    exit 0
fi

# 停止服务
log_step "停止相关服务..."
systemctl stop nginx 2>/dev/null || true
systemctl stop apache2 2>/dev/null || true
systemctl stop mysql 2>/dev/null || true
systemctl stop pure-ftpd 2>/dev/null || true
systemctl stop bt 2>/dev/null || true

# 恢复网站文件
log_step "恢复网站文件..."
if [[ -f "$BACKUP_DIR/websites.tar.gz" ]]; then
    cd /www
    tar -xzf "$BACKUP_DIR/websites.tar.gz"
    chown -R www:www wwwroot/ 2>/dev/null || chown -R www-data:www-data wwwroot/
    log_info "网站文件恢复完成"
fi

# 恢复面板配置
log_step "恢复面板配置..."
if [[ -f "$BACKUP_DIR/panel.tar.gz" ]]; then
    cd /www/server
    tar -xzf "$BACKUP_DIR/panel.tar.gz"
    log_info "面板配置恢复完成"
fi

# 恢复服务配置
log_step "恢复服务配置..."
cd /www/server

for service in nginx apache php mysql_config pure-ftpd phpmyadmin nodejs nvm cron server_data; do
    if [[ -f "$BACKUP_DIR/${service}.tar.gz" ]]; then
        tar -xzf "$BACKUP_DIR/${service}.tar.gz"
        log_info "${service}配置恢复完成"
    fi
done

# 恢复数据库
log_step "恢复数据库..."
if [[ -f "$BACKUP_DIR/all_databases.sql" ]]; then
    log_warn "请输入MySQL root密码来恢复数据库:"
    mysql -u root -p < "$BACKUP_DIR/all_databases.sql"
    log_info "数据库恢复完成"
fi

# 恢复SSL证书
log_step "恢复SSL证书..."
if [[ -d "$BACKUP_DIR/ssl" ]]; then
    mkdir -p /www/server/panel/vhost/cert
    cp -r "$BACKUP_DIR/ssl"/* /www/server/panel/vhost/cert/
    log_info "SSL证书恢复完成"
fi

# 恢复Let's Encrypt证书
if [[ -f "$BACKUP_DIR/letsencrypt.tar.gz" ]]; then
    cd /etc
    tar -xzf "$BACKUP_DIR/letsencrypt.tar.gz"
    log_info "Let's Encrypt证书恢复完成"
fi

# 恢复定时任务
log_step "恢复定时任务..."
if [[ -f "$BACKUP_DIR/root_crontab.txt" ]]; then
    crontab "$BACKUP_DIR/root_crontab.txt"
    log_info "定时任务恢复完成"
fi

# 设置权限
log_step "设置文件权限..."
chown -R www:www /www/wwwroot/ 2>/dev/null || chown -R www-data:www-data /www/wwwroot/
chmod -R 755 /www/wwwroot/
chmod -R 600 /www/server/panel/vhost/cert/ 2>/dev/null || true

# 重启服务
log_step "重启服务..."
systemctl start mysql 2>/dev/null || true
systemctl start nginx 2>/dev/null || true
systemctl start pure-ftpd 2>/dev/null || true
systemctl start bt 2>/dev/null || true

log_info "恢复完成！"
log_info "请检查各项服务是否正常运行"
EOF

    chmod +x "$BACKUP_DIR/restore.sh"
    log_info "恢复脚本生成完成: $BACKUP_DIR/restore.sh"
}

# 生成备份信息文件
generate_backup_info() {
    log_step "12. 生成备份信息..."
    
    cat > "$BACKUP_DIR/backup_info.txt" << EOF
aaPanel 备份信息
================

备份时间: $(date '+%Y-%m-%d %H:%M:%S')
服务器信息: $(uname -a)
备份路径: $BACKUP_DIR

备份内容清单:
EOF

    # 列出所有备份文件
    echo "文件列表:" >> "$BACKUP_DIR/backup_info.txt"
    ls -lh "$BACKUP_DIR" >> "$BACKUP_DIR/backup_info.txt"
    
    # 计算总大小
    TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
    echo -e "\n总大小: $TOTAL_SIZE" >> "$BACKUP_DIR/backup_info.txt"
    
    log_info "备份信息文件生成完成"
}

# 主函数
main() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "         aaPanel 完整备份脚本            "
    echo "========================================"
    echo -e "${NC}"
    
    check_root
    check_aapanel
    create_backup_dir
    
    backup_websites
    backup_databases
    backup_panel_config
    backup_webserver_config
    backup_php_config
    backup_mysql_config
    backup_ftp_config
    backup_other_components
    backup_ssl_certificates
    backup_system_cron
    generate_restore_script
    generate_backup_info
    
    echo -e "${GREEN}"
    echo "========================================"
    echo "           备份完成！"
    echo "========================================"
    echo -e "${NC}"
    
    log_info "备份目录: $BACKUP_DIR"
    log_info "备份大小: $(du -sh "$BACKUP_DIR" | cut -f1)"
    log_info "使用以下命令打包备份文件:"
    echo -e "${YELLOW}cd $BACKUP_BASE_DIR && tar -czf backup_$TIMESTAMP.tar.gz backup_$TIMESTAMP/${NC}"
    
    echo
    log_info "恢复说明:"
    echo "1. 重新安装aaPanel"
    echo "2. 解压备份文件"
    echo "3. 运行 restore.sh 脚本"
    
    echo
    log_warn "重要提醒:"
    echo "• 请将备份文件下载到安全位置"
    echo "• 建议定期测试恢复流程"
    echo "• 记录重要的数据库密码和面板登录信息"
}

# 执行主函数
main "$@"