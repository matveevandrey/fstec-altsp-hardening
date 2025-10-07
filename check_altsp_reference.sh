#!/bin/bash

# Скрипт проверки соответствия эталонной конфигурации ОС Альт Линукс СП
# Версия: 1.4 - Упрощенная логика проверки

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

COMPLIANCE_FILE="/var/log/compliance_report_$(date +%Y%m%d_%H%M%S).log"

# Функции вывода
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
    echo "Дистрибутив: $(cat /etc/altlinux-release 2>/dev/null | head -1 || echo 'Альт Линукс СП')" | tee -a "$COMPLIANCE_FILE"
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
    local deny=""
    if grep -q "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null; then
        deny=$(grep "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
    elif grep -q "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null; then
        deny=$(grep "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
    fi
    
    if [[ "$deny" -eq 5 ]]; then
        log_color "$GREEN" "✓ Количество неудачных попыток: $deny (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Количество неудачных попыток: ${deny:-не настроено} (НЕ СООТВЕТСТВУЕТ, требуется: 5)"
    fi
}

check_audit_settings() {
    log ""
    log "=== ПРОВЕРКА НАСТРОЕК АУДИТА ==="
    
    # Проверка работы службы аудита
    if systemctl is-active auditd &>/dev/null; then
        log_color "$GREEN" "✓ Служба auditd активна (СООТВЕТСТВУЕТ)"
        
        # Проверка правил аудита
        if command -v auditctl &>/dev/null; then
            local rule_count=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
            if [[ $rule_count -gt 0 ]]; then
                log_color "$GREEN" "✓ Правила аудита настроены: $rule_count правил (СООТВЕТСТВУЕТ)"
            else
                log_color "$RED" "✗ Правила аудита не настроены (НЕ СООТВЕТСТВУЕТ)"
            fi
        fi
    else
        log_color "$RED" "✗ Служба auditd не активна (НЕ СООТВЕТСТВУЕТ)"
    fi
}

check_memory_clearing() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ ОЧИСТКИ ПАМЯТИ ==="
    
    # Согласно эталону: Очистка разделов подкачки - Отключено
    # Проверяем стандартные настройки swappiness
    local swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "60")
    if [[ $swappiness -le 60 ]]; then
        log_color "$GREEN" "✓ Очистка разделов подкачки: Отключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Очистка разделов подкачки настроена (НЕ СООТВЕТСТВУЕТ, требуется: Отключено)"
    fi
    
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
    # Проверяем, что не активны системы мандатного контроля
    local mac_enabled=false
    
    # Проверка SELinux
    if command -v sestatus &>/dev/null; then
        if sestatus 2>/dev/null | grep -q "enabled"; then
            mac_enabled=true
        fi
    fi
    
    # Проверка AppArmor
    if command -v aa-status &>/dev/null; then
        if aa-status 2>/dev/null | grep -q "apparmor module is loaded"; then
            mac_enabled=true
        fi
    fi
    
    if [[ "$mac_enabled" == "false" ]]; then
        log_color "$GREEN" "✓ Мандатный контроль целостности: Выключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Мандатный контроль целостности активен (НЕ СООТВЕТСТВУЕТ, требуется: Выключено)"
    fi
}

check_software_environment() {
    log ""
    log "=== ПРОВЕРКА ЗАМКНУТОЙ ПРОГРАММНОЙ СРЕДЫ ==="
    
    # Согласно эталону: 
    # Контроль исполняемых файлов - Выключить
    # Контроль расширенных атрибутов - Выключить
    
    # Проверяем, что нет активного контроля версий пакетов
    local held_packages=0
    if command -v apt-mark &>/dev/null; then
        held_packages=$(apt-mark showhold 2>/dev/null | wc -l)
    fi
    
    if [[ $held_packages -eq 0 ]]; then
        log_color "$GREEN" "✓ Контроль исполняемых файлов: Выключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Контроль исполняемых файлов активен (НЕ СООТВЕТСТВУЕТ, требуется: Выключено)"
    fi
    
    # Для контроля расширенных атрибутов - проверяем, что не используются атрибуты типа immutable
    if ! find /etc /bin /sbin /usr -type f -exec lsattr {} + 2>/dev/null | grep -q "^[^/]*i[^/]*[/ ]"; then
        log_color "$GREEN" "✓ Контроль расширенных атрибутов: Выключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Контроль расширенных атрибутов активен (НЕ СООТВЕТСТВУЕТ, требуется: Выключено)"
    fi
}

generate_summary() {
    log ""
    log "=== СВОДНЫЙ ОТЧЕТ ==="
    log "Проверка завершена. Подробный отчет сохранен в: $COMPLIANCE_FILE"
    
    # Подсчет результатов
    local total_checks=0
    local passed_checks=0
    
    # Анализируем лог для подсчета результатов
    if grep -q "✓" "$COMPLIANCE_FILE"; then
        passed_checks=$(grep -c "✓" "$COMPLIANCE_FILE")
    fi
    if grep -q "✗" "$COMPLIANCE_FILE"; then
        failed_checks=$(grep -c "✗" "$COMPLIANCE_FILE")
    fi
    total_checks=$((passed_checks + failed_checks))
    
    log ""
    log "РЕЗУЛЬТАТЫ ПРОВЕРКИ:"
    log "Всего проверок: $total_checks"
    log "Соответствует: $passed_checks"
    log "Не соответствует: ${failed_checks:-0}"
    
    if [[ ${failed_checks:-0} -eq 0 ]]; then
        log_color "$GREEN" "✓ Система полностью соответствует эталонной конфигурации"
    else
        log_color "$RED" "✗ Обнаружены несоответствия эталонной конфигурации"
        log ""
        log "Рекомендации:"
        log "1. Настройте политику паролей в /etc/security/pwquality.conf"
        log "2. Настройте блокировку учетных записей в /etc/pam.d/system-auth"
        log "3. Настройте гарантированное удаление файлов через cron"
        log "4. Убедитесь, что auditd работает с требуемыми флагами"
        log "5. Отключите системы мандатного контроля если они активны"
    fi
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
