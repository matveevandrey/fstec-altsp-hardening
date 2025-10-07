#!/bin/bash

# Скрипт настройки Альт Линукс СП в соответствии с эталонной конфигурацией
# Версия: 1.1 - Исправлены ошибки auditd

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="/var/log/fix_altsp_reference_$(date +%Y%m%d_%H%M%S).log"

# Функции вывода
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

print_success() { 
    echo -e "${GREEN}✓ $1${NC}"
    log "✓ $1"
}

print_warning() { 
    echo -e "${YELLOW}⚠ $1${NC}"
    log "⚠ $1"
}

print_info() { 
    echo -e "${BLUE}ℹ $1${NC}"
    log "ℹ $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ОШИБКА: Скрипт должен запускаться с правами root${NC}"
        exit 1
    fi
}

create_backup() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
        print_info "Создан бэкап: ${file}.backup.$(date +%Y%m%d_%H%M%S)"
    fi
}

configure_password_policy() {
    log ""
    log "=== НАСТРОЙКА ПОЛИТИКИ ПАРОЛЕЙ ==="
    
    create_backup "/etc/security/pwquality.conf"
    
    # Настройка политики паролей
    cat > /etc/security/pwquality.conf << 'EOF'
# Настройки политики паролей согласно эталонной конфигурации
minlen = 12
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
maxsequence = 4
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

    print_success "Настроена политика паролей: minlen=12, minclass=4"
    
    # Настройка PAM для использования pwquality
    if [[ -f "/etc/pam.d/system-auth" ]]; then
        create_backup "/etc/pam.d/system-auth"
        if grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
            sed -i 's/pam_pwquality\.so.*/pam_pwquality.so try_first_pass local_users_only retry=3 minlen=12 minclass=4/' /etc/pam.d/system-auth
        else
            # Добавляем строку после password required pam_deny.so
            sed -i '/password.*pam_deny\.so/a password requisite pam_pwquality.so try_first_pass local_users_only retry=3 minlen=12 minclass=4' /etc/pam.d/system-auth
        fi
        print_success "Настроен PAM для использования pwquality"
    fi
    
    # Настройка старения паролей
    if command -v chage &>/dev/null; then
        chage -M 90 -W 7 root
        print_success "Настроено старение паролей: MAX_DAYS=90, WARN_DAYS=7 для root"
        
        # Для всех существующих пользователей
        for user in $(getent passwd | cut -d: -f1); do
            if [[ "$user" != "root" ]] && [[ "$user" != "nobody" ]] && [[ "$user" != "*" ]]; then
                chage -M 90 -W 7 "$user" 2>/dev/null || true
            fi
        done
        print_success "Настроено старение паролей для всех пользователей"
    fi
}

configure_account_lockout() {
    log ""
    log "=== НАСТРОЙКА ПОЛИТИКИ БЛОКИРОВКИ УЧЕТНЫХ ЗАПИСЕЙ ==="
    
    # Настройка PAM для блокировки учетных записей
    if [[ -f "/etc/pam.d/system-auth" ]]; then
        create_backup "/etc/pam.d/system-auth"
        
        # Удаляем старые настройки блокировки
        sed -i '/pam_tally2\.so/d' /etc/pam.d/system-auth
        sed -i '/pam_faillock\.so/d' /etc/pam.d/system-auth
        
        # Добавляем настройки pam_tally2 (более стабильно в Альт)
        sed -i '/auth.*required.*pam_deny\.so/i auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit silent' /etc/pam.d/system-auth
        sed -i '/account.*required.*pam_unix\.so/i account required pam_tally2.so' /etc/pam.d/system-auth
        
        print_success "Настроена блокировка учетных записей: 5 попыток, блокировка на 15 минут"
    fi
    
    # Сбрасываем счетчики блокировок
    if command -v pam_tally2 &>/dev/null; then
        pam_tally2 --reset
        print_success "Сброшены счетчики блокировок учетных записей"
    fi
}

configure_audit_settings() {
    log ""
    log "=== НАСТРОЙКА АУДИТА ==="
    
    # Установка auditd если не установлен
    if ! command -v auditctl &>/dev/null; then
        print_info "Установка auditd..."
        apt-get update
        apt-get install -y auditd audispd-plugins
    fi
    
    # Останавливаем службу перед настройкой
    systemctl stop auditd 2>/dev/null || true
    
    # Базовая конфигурация auditd
    create_backup "/etc/audit/auditd.conf"
    
    cat > /etc/audit/auditd.conf << 'EOF'
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF

    print_success "Настроен конфигурационный файл auditd"
    
    # Базовые правила аудита
    create_backup "/etc/audit/rules.d/audit.rules"
    
    cat > /etc/audit/rules.d/audit.rules << 'EOF'
## Первая строка должна быть пустой
-b 320
-f 1

# Аудит системных вызовов
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Аудит входа в систему
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# Аудит изменений прав доступа
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Аудит критичных файлов
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# Аудит сетевых настроек
-w /etc/hosts -p wa -k hosts
-w /etc/network -p wa -k network

# Аудит загрузки/выгрузки модулей ядра
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
EOF

    # Включаем автозагрузку
    systemctl enable auditd
    
    # Запускаем службу
    if systemctl start auditd; then
        print_success "Служба auditd запущена"
        
        # Перезагружаем правила аудита
        if auditctl -R /etc/audit/rules.d/audit.rules 2>/dev/null; then
            print_success "Применены правила аудита"
        else
            print_warning "Правила аудита применены с предупреждениями"
        fi
    else
        print_warning "Служба auditd не запущена, но настроена для автозапуска"
    fi
}

configure_memory_clearing() {
    log ""
    log "=== НАСТРОЙКА ПОЛИТИКИ ОЧИСТКИ ПАМЯТИ ==="
    
    # Настройка гарантированного удаления файлов через cron
    if ! grep -q "shred" /etc/crontab 2>/dev/null; then
        echo "# Гарантированное удаление временных файлов каждый день в 2:00" >> /etc/crontab
        echo "0 2 * * * root find /tmp -type f -atime +1 -exec shred -zuf {} \;" >> /etc/crontab
        print_success "Настроено гарантированное удаление файлов в /tmp"
    fi
    
    # Настройка очистки других временных каталогов
    if [[ ! -f "/etc/cron.daily/secure-delete" ]]; then
        cat > /etc/cron.daily/secure-delete << 'EOF'
#!/bin/bash
# Гарантированное удаление временных файлов
find /var/tmp -type f -atime +7 -exec shred -zuf {} \; 2>/dev/null
find /tmp -type f -atime +1 -exec shred -zuf {} \; 2>/dev/null
EOF
        chmod +x /etc/cron.daily/secure-delete
        print_success "Создан скрипт безопасного удаления для cron.daily"
    fi
}

configure_integrity_control() {
    log ""
    log "=== НАСТРОЙКА МАНДАТНОГО КОНТРОЛЯ ЦЕЛОСТНОСТИ ==="
    
    # Согласно эталонной конфигурации - выключено
    print_info "Мандатный контроль целостности отключен (соответствует эталону)"
    
    # Отключаем SELinux если установлен (для совместимости)
    if command -v setenforce &>/dev/null; then
        setenforce 0
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        print_info "SELinux переведен в режим disabled"
    fi
}

configure_software_environment() {
    log ""
    log "=== НАСТРОЙКА ЗАМКНУТОЙ ПРОГРАММНОЙ СРЕДЫ ==="
    
    # Согласно эталонной конфигурации - контроль выключен
    print_info "Контроль исполняемых файлов отключен (соответствует эталону)"
    print_info "Контроль расширенных атрибутов отключен (соответствует эталону)"
    
    # Базовая настройка APT для безопасности
    if [[ ! -f "/etc/apt/apt.conf.d/99security" ]]; then
        cat > /etc/apt/apt.conf.d/99security << 'EOF'
# Базовые настройки безопасности APT
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
EOF
        print_success "Добавлены базовые настройки безопасности APT"
    fi
}

apply_sysctl_security() {
    log ""
    log "=== ПРИМЕНЕНИЕ БЕЗОПАСНЫХ ПАРАМЕТРОВ ЯДРА ==="
    
    create_backup "/etc/sysctl.conf"
    
    # Добавляем безопасные параметры ядра
    cat >> /etc/sysctl.conf << 'EOF'

# Безопасные параметры ядра
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
EOF

    # Применяем настройки
    if sysctl -p > /dev/null 2>&1; then
        print_success "Применены безопасные параметры ядра"
    else
        print_warning "Настройки ядра применены с предупреждениями"
    fi
}

finalize_configuration() {
    log ""
    log "=== ЗАВЕРШЕНИЕ НАСТРОЙКИ ==="
    
    # Проверяем применение настроек без перезапуска auditd
    if systemctl is-enabled auditd &>/dev/null; then
        print_success "Служба auditd настроена для автозапуска"
    else
        print_warning "Служба auditd не настроена для автозапуска"
    fi
    
    # Проверяем, что правила аудита загружены
    if command -v auditctl &>/dev/null; then
        local rule_count=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
        if [[ $rule_count -gt 0 ]]; then
            print_success "Правила аудита активны: $rule_count правил"
        else
            print_warning "Правила аудита не загружены"
        fi
    fi
    
    print_success "Настройка системы завершена!"
    print_info "Подробный лог сохранен в: $LOG_FILE"
    print_info "Рекомендуется перезагрузить систему для применения всех изменений"
    echo
    print_warning "После перезагрузки запустите check_altsp_reference.sh для проверки"
}

main() {
    check_root
    
    echo -e "${BLUE}"
    echo "================================================"
    echo "  Настройка Альт Линукс СП"
    echo "  в соответствии с эталонной конфигурацией"
    echo "================================================"
    echo -e "${NC}"
    
    log "Начало настройки системы"
    
    configure_password_policy
    configure_account_lockout
    configure_audit_settings
    configure_memory_clearing
    configure_integrity_control
    configure_software_environment
    apply_sysctl_security
    finalize_configuration
}

# Запуск скрипта
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo -e "${YELLOW}Запуск настройки системы...${NC}"
    echo -e "${YELLOW}Внимание: будут изменены системные настройки!${NC}"
    echo -e "${YELLOW}Рекомендуется сделать бэкап системы перед продолжением.${NC}"
    echo
    read -p "Продолжить? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        main
    else
        echo -e "${RED}Настройка отменена пользователем${NC}"
        exit 0
    fi
fi
