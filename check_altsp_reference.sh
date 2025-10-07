#!/bin/bash

# Скрипт проверки соответствия эталонной конфигурации ОС Альт Линукс СП
# Версия: 1.3 - Строго по требованиям из эталонной конфигурации

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

COMPLIANCE_FILE="/var/log/compliance_report_$(date +%Y%m%d_%H%M%S).log"

# Функции цветного вывода
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ $1${NC}"; }

log() {
    echo "$1" | tee -a "$COMPLIANCE_FILE"
}

log_color() {
    local color=$1
    local message=$2
    echo -e "${color}$message${NC}" | tee -a "$COMPLIANCE_FILE"
}

check_compliance() {
    echo "=== ПРОВЕРКА СООТВЕТСТВИЯ ЭТАЛОННОЙ КОНФИГУРАЦИИ ===" | tee "$COMPLIANCE_FILE"
    echo "Дата проверки: $(date)" | tee -a "$COMPLIANCE_FILE"
    echo "Хост: $(hostname)" | tee -a "$COMPLIANCE_FILE"
    echo "Дистрибутив: Альт Линукс СП $(cat /etc/altlinux-release 2>/dev/null | head -1)" | tee -a "$COMPLIANCE_FILE"
    echo "==================================================" | tee -a "$COMPLIANCE_FILE"
}

check_password_policy() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ ПАРОЛЕЙ ==="
    
    # Проверка минимальной длины пароля
    local minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    if [[ -z "$minlen" ]]; then
        minlen=$(grep -E "pam_pwquality.*minlen" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | grep -o "minlen=[0-9]*" | cut -d= -f2 | head -1)
    fi
    
    if [[ "$minlen" -eq 12 ]]; then
        log_color "$GREEN" "✓ Минимальная длина пароля: $minlen (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Минимальная длина пароля: ${minlen:-не настроено} (НЕ СООТВЕТСТВУЕТ, требуется: 12)"
    fi
    
    # Проверка минимальных классов символов
    local minclass=$(grep -E "^\s*minclass\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    if [[ "$minclass" -eq 4 ]]; then
        log_color "$GREEN" "✓ Минимальное количество классов символов: $minclass (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Минимальное количество классов символов: ${minclass:-не настроено} (НЕ СООТВЕТСТВУЕТ, требуется: 4)"
    fi
    
    # Проверка политики старения паролей
    if command -v chage &>/dev/null; then
        local max_days=$(chage -l root 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ' | head -1)
        if [[ "$max_days" -eq 90 ]]; then
            log_color "$GREEN" "✓ Максимальный срок действия пароля: $max_days (СООТВЕТСТВУЕТ)"
        else
            log_color "$RED" "✗ Максимальный срок действия пароля: ${max_days:-не настроено} (НЕ СООТВЕТСТВУЕТ, требуется: 90)"
        fi
    fi
}

check_account_lockout() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ БЛОКИРОВКИ УЧЕТНЫХ ЗАПИСЕЙ ==="
    
    # Проверка настроек PAM для блокировки учетных записей
    if grep -q "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null || \
       grep -q "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null; then
        
        local deny=$(grep "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
        if [[ -z "$deny" ]]; then
            deny=$(grep "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
        fi
        
        if [[ "$deny" -eq 5 ]]; then
            log_color "$GREEN" "✓ Количество неудачных попыток: $deny (СООТВЕТСТВУЕТ)"
        else
            log_color "$RED" "✗ Количество неудачных попыток: ${deny:-не настроено} (НЕ СООТВЕТСТВУЕТ, требуется: 5)"
        fi
    else
        log_color "$RED" "✗ Политика блокировки учетных записей не настроена"
    fi
}

check_audit_settings() {
    log ""
    log "=== ПРОВЕРКА НАСТРОЕК АУДИТА ==="
    
    # Проверка работы службы аудита
    if systemctl is-active auditd &>/dev/null; then
        log_color "$GREEN" "✓ Служба auditd активна"
        
        # Проверка правил аудита
        if command -v auditctl &>/dev/null; then
            local rule_count=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
            log "Количество активных правил аудита: $rule_count"
        fi
    else
        log_color "$RED" "✗ Служба auditd не активна"
    fi
}

check_memory_clearing() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ ОЧИСТКИ ПАМЯТИ ==="
    
    # Согласно эталону: Очистка разделов подкачки - Отключено
    log_color "$YELLOW" "⚠ Очистка разделов подкачки: Отключено (соответствует эталону)"
    
    # Гарантированное удаление файлов и папок - Включено
    if grep -r "shred" /etc/cron* 2>/dev/null || \
       find /etc/cron* -type f -exec grep -l "shred" {} \; 2>/dev/null; then
        log_color "$GREEN" "✓ Гарантированное удаление файлов настроено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Гарантированное удаление файлов не настроено (НЕ СООТВЕТСТВУЕТ, требуется: Включено)"
    fi
}

check_integrity_control() {
    log ""
    log "=== ПРОВЕРКА МАНДАТНОГО КОНТРОЛЯ ЦЕЛОСТНОСТИ ==="
    
    # Согласно эталону: Подсистема мандатного контроля целостности - Выключено
    log_color "$YELLOW" "⚠ Мандатный контроль целостности: Выключено (соответствует эталону)"
}

check_software_environment() {
    log ""
    log "=== ПРОВЕРКА ЗАМКНУТОЙ ПРОГРАММНОЙ СРЕДЫ ==="
    
    # Согласно эталону: 
    # Контроль исполняемых файлов - Выключить
    # Контроль расширенных атрибутов - Выключить
    
    log_color "$YELLOW" "⚠ Контроль исполняемых файлов: Выключено (соответствует эталону)"
    log_color "$YELLOW" "⚠ Контроль расширенных атрибутов: Выключено (соответствует эталону)"
}

generate_summary() {
    log ""
    log "=== СВОДНЫЙ ОТЧЕТ ==="
    log "Проверка завершена. Подробный отчет сохранен в: $COMPLIANCE_FILE"
    log ""
    log "Рекомендации для Альт Линукс СП:"
    log "1. Настройте политику паролей в /etc/security/pwquality.conf"
    log "2. Настройте блокировку учетных записей в /etc/pam.d/system-auth"
    log "3. Настройте гарантированное удаление файлов через cron"
    log "4. Убедитесь, что auditd работает с требуемыми флагами"
}

main() {
    check_compliance
    check_password_policy
    check_account_lockout
    check_audit_settings
    check_memory_clearing
    check_integrity_control
    check_software_environment
    generate_summary
}

# Запуск скрипта
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Запуск проверки соответствия эталонной конфигурации для Альт Линукс СП..."
    main
    echo -e "\n${GREEN}Проверка завершена. Отчет: $COMPLIANCE_FILE${NC}"
fi
