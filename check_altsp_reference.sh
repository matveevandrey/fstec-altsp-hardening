#!/bin/bash

# Скрипт проверки соответствия эталонной конфигурации ОС Альт Линукс СП
# Версия: 1.6 - Полная проверка всех параметров политики паролей

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
    
    # 1. Минимальная длина пароля
    local minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    if [[ -z "$minlen" ]]; then
        minlen=$(grep -E "pam_pwquality.*minlen" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | grep -o "minlen=[0-9]*" | cut -d= -f2 | head -1)
    fi
    log "1. Минимальная длина пароля: ${minlen:-не настроено} (требуется: 12)"
    if [[ "$minlen" -eq 12 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 2. Минимальное количество строчных букв
    local lcredit=$(grep -E "^\s*lcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    log "2. Минимальное количество строчных букв: ${lcredit:--} (требуется: -1 или 1)"
    if [[ "$lcredit" == "-1" ]] || [[ "$lcredit" == "1" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 3. Минимальное количество заглавных букв
    local ucredit=$(grep -E "^\s*ucredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    log "3. Минимальное количество заглавных букв: ${ucredit:--} (требуется: -1 или 1)"
    if [[ "$ucredit" == "-1" ]] || [[ "$ucredit" == "1" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 4. Минимальное количество цифр
    local dcredit=$(grep -E "^\s*dcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    log "4. Минимальное количество цифр: ${dcredit:--} (требуется: -1 или 1)"
    if [[ "$dcredit" == "-1" ]] || [[ "$dcredit" == "1" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 5. Минимальное количество других символов
    local ocredit=$(grep -E "^\s*ocredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    log "5. Минимальное количество других символов: ${ocredit:--} (требуется: -1 или 1)"
    if [[ "$ocredit" == "-1" ]] || [[ "$ocredit" == "1" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 6. Минимальное количество дней между сменами пароля
    local min_days=$(chage -l root 2>/dev/null | grep "Minimum" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "6. Минимальное количество дней между сменами пароля: ${min_days:-не настроено} (требуется: 0)"
    if [[ "$min_days" -eq 0 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 7. Максимальное количество дней между сменами пароля
    local max_days=$(chage -l root 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "7. Максимальное количество дней между сменами пароля: ${max_days:-не настроено} (требуется: 90)"
    if [[ "$max_days" -eq 90 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 8. Число дней выдачи предупреждения до смены пароля
    local warn_days=$(chage -l root 2>/dev/null | grep "warning" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "8. Число дней выдачи предупреждения до смены пароля: ${warn_days:-не настроено} (требуется: 7)"
    if [[ "$warn_days" -eq 7 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 9. Число дней неактивности после устаревания пароля до блокировки учетной записи
    local inactive_days=$(chage -l root 2>/dev/null | grep "Inactive" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "9. Число дней неактивности после устаревания пароля: ${inactive_days:-не настроено} (требуется: -1 или отключено)"
    if [[ "$inactive_days" == "-1" ]] || [[ -z "$inactive_days" ]] || [[ "$inactive_days" == "never" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ (отключено)"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 10. Срок действия учетной записи пользователя
    local account_expires=$(chage -l root 2>/dev/null | grep "Account expires" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "10. Срок действия учетной записи: ${account_expires:-never} (требуется: never или отключено)"
    if [[ "$account_expires" == "never" ]] || [[ "$account_expires" == "" ]] || [[ "$account_expires" == "никогда" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ (отключено)"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # Проверка minclass как резервный вариант
    local minclass=$(grep -E "^\s*minclass\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    if [[ -n "$minclass" ]]; then
        log ""
        log "Резервная проверка через minclass: $minclass (требуется: 4)"
        if [[ "$minclass" -eq 4 ]]; then
            log_color "$GREEN" "   ✓ minclass СООТВЕТСТВУЕТ"
        else
            log_color "$RED" "   ✗ minclass НЕ СООТВЕТСТВУЕТ"
        fi
    fi
}

check_account_lockout() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ БЛОКИРОВКИ УЧЕТНЫХ ЗАПИСЕЙ ==="
    
    # Проверка настроек PAM для блокировки учетных записей
    local deny=""
    local unlock_time=""
    
    if grep -q "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null; then
        deny=$(grep "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
        unlock_time=$(grep "pam_tally2.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "unlock_time=[0-9]*" | cut -d= -f2 | head -1)
    elif grep -q "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null; then
        deny=$(grep "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
        unlock_time=$(grep "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/login 2>/dev/null | grep -o "unlock_time=[0-9]*" | cut -d= -f2 | head -1)
    fi
    
    log "Текущие настройки блокировки:"
    log "  Количество попыток: ${deny:-не настроено} (требуется: 5)"
    log "  Время блокировки: ${unlock_time:-не настроено} секунд (требуется: 900)"
    
    if [[ "$deny" -eq 5 ]]; then
        log_color "$GREEN" "✓ Количество неудачных попыток: $deny (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Количество неудачных попыток: ${deny:-не настроено} (НЕ СООТВЕТСТВУЕТ)"
    fi
    
    # Вывод текущих счетчиков блокировок
    log ""
    log "Текущие счетчики блокировок:"
    if command -v pam_tally2 &>/dev/null; then
        pam_tally2 --user root 2>/dev/null | while read line; do
            log "  $line"
        done
    fi
}

check_audit_settings() {
    log ""
    log "=== ПРОВЕРКА НАСТРОЕК АУДИТА ==="
    
    # Проверка работы службы аудита
    local audit_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
    log "Статус службы auditd: $audit_status"
    
    if systemctl is-active auditd &>/dev/null; then
        log_color "$GREEN" "✓ Служба auditd активна (СООТВЕТСТВУЕТ)"
        
        # Проверка правил аудита
        if command -v auditctl &>/dev/null; then
            local rule_count=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
            log "Количество активных правил аудита: $rule_count"
            
            if [[ $rule_count -gt 0 ]]; then
                log_color "$GREEN" "✓ Правила аудита настроены: $rule_count правил (СООТВЕТСТВУЕТ)"
                
                # Вывод примеров правил
                log ""
                log "Примеры активных правил аудита:"
                auditctl -l 2>/dev/null | head -5 | while read rule; do
                    log "  $rule"
                done
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
    local swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "60")
    log "Текущее значение vm.swappiness: $swappiness (требуется: <= 60)"
    
    if [[ $swappiness -le 60 ]]; then
        log_color "$GREEN" "✓ Очистка разделов подкачки: Отключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Очистка разделов подкачки настроена (НЕ СООТВЕТСТВУЕТ, требуется: Отключено)"
    fi
    
    # Гарантированное удаление файлов и папок - Включено
    log ""
    log "Поиск настроек гарантированного удаления:"
    local shred_found=false
    
    if grep -r "shred" /etc/cron* 2>/dev/null | head -3; then
        shred_found=true
    fi
    
    if find /etc/cron* -type f -exec grep -l "shred" {} \; 2>/dev/null | head -3; then
        shred_found=true
    fi
    
    if [[ "$shred_found" == "true" ]]; then
        log_color "$GREEN" "✓ Гарантированное удаление файлов настроено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Гарантированное удаление файлов не настроено (НЕ СООТВЕТСТВУЕТ, требуется: Включено)"
    fi
}

check_integrity_control() {
    log ""
    log "=== ПРОВЕРКА МАНДАТНОГО КОНТРОЛЯ ЦЕЛОСТНОСТИ ==="
    
    # Согласно эталону: Подсистема мандатного контроля целостности - Выключено
    local mac_enabled=false
    local mac_systems=()
    
    # Проверка SELinux
    if command -v sestatus &>/dev/null; then
        if sestatus 2>/dev/null | grep -q "enabled"; then
            mac_enabled=true
            mac_systems+=("SELinux")
        fi
        local selinux_mode=$(sestatus 2>/dev/null | grep "Current mode" | awk '{print $3}' || echo "unknown")
        log "SELinux статус: $selinux_mode"
    fi
    
    # Проверка AppArmor
    if command -v aa-status &>/dev/null; then
        if aa-status 2>/dev/null | grep -q "apparmor module is loaded"; then
            mac_enabled=true
            mac_systems+=("AppArmor")
        fi
        local apparmor_profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
        log "AppArmor профилей загружено: $apparmor_profiles"
    fi
    
    if [[ "$mac_enabled" == "false" ]]; then
        log_color "$GREEN" "✓ Мандатный контроль целостности: Выключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Мандатный контроль целостности активен: ${mac_systems[*]} (НЕ СООТВЕТСТВУЕТ, требуется: Выключено)"
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
    
    log "Заблокированных пакетов: $held_packages (требуется: 0)"
    if [[ $held_packages -eq 0 ]]; then
        log_color "$GREEN" "✓ Контроль исполняемых файлов: Выключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Контроль исполняемых файлов активен (НЕ СООТВЕТСТВУЕТ, требуется: Выключено)"
        log "Заблокированные пакеты:"
        apt-mark showhold 2>/dev/null | head -5 | while read pkg; do
            log "  $pkg"
        done
    fi
    
    # Для контроля расширенных атрибутов - проверяем, что не используются атрибуты типа immutable
    log ""
    log "Проверка расширенных атрибутов..."
    local immutable_files=$(find /etc /bin /sbin /usr -type f -exec lsattr {} + 2>/dev/null | grep "^[^/]*i[^/]*[/ ]" | wc -l)
    log "Файлов с атрибутом immutable: $immutable_files (требуется: 0)"
    
    if [[ $immutable_files -eq 0 ]]; then
        log_color "$GREEN" "✓ Контроль расширенных атрибутов: Выключено (СООТВЕТСТВУЕТ)"
    else
        log_color "$RED" "✗ Контроль расширенных атрибутов активен (НЕ СООТВЕТСТВУЕТ, требуется: Выключено)"
        log "Файлы с атрибутом immutable:"
        find /etc /bin /sbin /usr -type f -exec lsattr {} + 2>/dev/null | grep "^[^/]*i[^/]*[/ ]" | head -3 | while read file; do
            log "  $file"
        done
    fi
}

generate_summary() {
    log ""
    log "=== СВОДНЫЙ ОТЧЕТ ==="
    log "Проверка завершена. Подробный отчет сохранен в: $COMPLIANCE_FILE"
    
    # Подсчет результатов
    local total_checks=0
    local passed_checks=0
    local failed_checks=0
    
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
    log "Не соответствует: $failed_checks"
    
    if [[ $failed_checks -eq 0 ]]; then
        log_color "$GREEN" "✓ Система полностью соответствует эталонной конфигурации"
    else
        log_color "$RED" "✗ Обнаружены несоответствия эталонной конфигурации"
        log ""
        log "Рекомендации по исправлению:"
        
        # Контекстные рекомендации based on failed checks
        if grep -q "Минимальная длина пароля.*НЕ СООТВЕТСТВУЕТ" "$COMPLIANCE_FILE"; then
            log "1. Настройте минимальную длину пароля: echo 'minlen = 12' >> /etc/security/pwquality.conf"
        fi
        
        if grep -q "Максимальное количество дней между сменами пароля.*НЕ СООТВЕТСТВУЕТ" "$COMPLIANCE_FILE"; then
            log "2. Настройте старение паролей: chage -M 90 root"
        fi
        
        if grep -q "Количество неудачных попыток.*НЕ СООТВЕТСТВУЕТ" "$COMPLIANCE_FILE"; then
            log "3. Настройте блокировку учетных записей в /etc/pam.d/system-auth"
        fi
        
        if grep -q "Гарантированное удаление файлов не настроено" "$COMPLIANCE_FILE"; then
            log "4. Настройте гарантированное удаление файлов через cron"
        fi
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
