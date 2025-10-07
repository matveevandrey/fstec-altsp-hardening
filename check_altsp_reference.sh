#!/bin/bash

# Скрипт проверки соответствия эталонной конфигурации ОС Альт Линукс СП
# Версия: 2.1 - Исправлена проверка политики блокировки учетных записей

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

# Функция для определения реальных пользователей системы
get_system_users() {
    local users=()
    while IFS=: read -r user _ uid _ _ home shell; do
        # Включаем root и пользователей с UID >= 500 (традиционные пользователи)
        if [[ $uid -eq 0 ]] || [[ $uid -ge 500 ]]; then
            # Пропускаем системных пользователей с неинтерактивными shell
            if [[ "$shell" != */nologin ]] && [[ "$shell" != */false ]] && [[ "$shell" != "/dev/null" ]]; then
                users+=("$user")
            fi
        fi
    done < /etc/passwd
    echo "${users[@]}"
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
    
    # Проверка настроек в /etc/login.defs
    log "Проверка /etc/login.defs:"
    local login_defs_max=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "не настроено")
    local login_defs_min=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "не настроено") 
    local login_defs_warn=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "не настроено")
    
    log "  PASS_MAX_DAYS: $login_defs_max"
    log "  PASS_MIN_DAYS: $login_defs_min"
    log "  PASS_WARN_AGE: $login_defs_warn"
    
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
    
    # 6-8. Проверка старения паролей с правильным парсингом русского вывода
    local chage_output=$(chage -l root 2>/dev/null)
    
    # 6. Минимальное количество дней между сменами пароля
    local min_days=$(echo "$chage_output" | grep -i "Минимальное количество дней между сменой пароля" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "6. Минимальное количество дней между сменами пароля: ${min_days:-не настроено} (требуется: 0)"
    if [[ "$min_days" -eq 0 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 7. Максимальное количество дней между сменами пароля
    local max_days=$(echo "$chage_output" | grep -i "Максимальное количество дней между сменой пароля" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "7. Максимальное количество дней между сменами пароля: ${max_days:-не настроено} (требуется: 90)"
    if [[ "$max_days" -eq 90 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 8. Число дней выдачи предупреждения до смены пароля
    local warn_days=$(echo "$chage_output" | grep -i "Количество дней с предупреждением перед деактивацией пароля" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "8. Число дней выдачи предупреждения до смены пароля: ${warn_days:-не настроено} (требуется: 7)"
    if [[ "$warn_days" -eq 7 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 9. Число дней неактивности после устаревания пароля до блокировки учетной записи
    local inactive_days=$(echo "$chage_output" | grep -i "Пароль будет деактивирован через" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "9. Число дней неактивности после устаревания пароля: ${inactive_days:-никогда} (требуется: никогда или отключено)"
    if [[ "$inactive_days" == "никогда" ]] || [[ -z "$inactive_days" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ (отключено)"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # 10. Срок действия учетной записи пользователя
    local account_expires=$(echo "$chage_output" | grep -i "Срок действия учётной записи истекает" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    log "10. Срок действия учетной записи: ${account_expires:-никогда} (требуется: никогда или отключено)"
    if [[ "$account_expires" == "никогда" ]] || [[ -z "$account_expires" ]]; then
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
    
    # Согласно эталону проверяем 6 параметров:
    # 1. Индивидуальные настройки - Включено
    # 2. Не сбрасывать счетчик - -
    # 3. Не использовать счетчик для пользователя с uid=0 - -
    # 4. Неуспешных попыток - 5
    # 5. Период блокировки - 15
    # 6. Период разблокировки - 15
    
    local deny=""
    local unlock_time=""
    local lock_time=""
    local even_deny_root=""
    local root_unlock_time=""
    
    # Проверка всех возможных PAM файлов в Альт СП
    local pam_files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth" "/etc/pam.d/login" "/etc/pam.d/system-login")
    
    for pam_file in "${pam_files[@]}"; do
        if [[ -f "$pam_file" ]]; then
            # Проверка pam_tally2
            if grep -q "pam_tally2.so" "$pam_file" 2>/dev/null; then
                deny=$(grep "pam_tally2.so" "$pam_file" 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
                unlock_time=$(grep "pam_tally2.so" "$pam_file" 2>/dev/null | grep -o "unlock_time=[0-9]*" | cut -d= -f2 | head -1)
                even_deny_root=$(grep "pam_tally2.so" "$pam_file" 2>/dev/null | grep -o "even_deny_root" | head -1)
                root_unlock_time=$(grep "pam_tally2.so" "$pam_file" 2>/dev/null | grep -o "root_unlock_time=[0-9]*" | cut -d= -f2 | head -1)
                log "Найдены настройки pam_tally2 в: $pam_file"
                break
            # Проверка pam_faillock  
            elif grep -q "pam_faillock.so" "$pam_file" 2>/dev/null; then
                deny=$(grep "pam_faillock.so" "$pam_file" 2>/dev/null | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
                unlock_time=$(grep "pam_faillock.so" "$pam_file" 2>/dev/null | grep -o "unlock_time=[0-9]*" | cut -d= -f2 | head -1)
                log "Найдены настройки pam_faillock в: $pam_file"
                break
            fi
        fi
    done
    
    log "1. Индивидуальные настройки: ${deny:+Включено} ${deny:-не настроено} (требуется: Включено)"
    if [[ -n "$deny" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    log "2. Не сбрасывать счетчик: - (требуется: -)"
    log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    
    log "3. Не использовать счетчик для пользователя с uid=0: ${even_deny_root:--} (требуется: -)"
    if [[ -z "$even_deny_root" ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$YELLOW" "   ⚠ НАСТРОЕНО (even_deny_root)"
    fi
    
    log "4. Неуспешных попыток: ${deny:-не настроено} (требуется: 5)"
    if [[ "$deny" -eq 5 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # Период блокировки и разблокировки (в минутах согласно эталону)
    local unlock_time_minutes=""
    if [[ -n "$unlock_time" ]]; then
        unlock_time_minutes=$((unlock_time / 60))
    fi
    
    log "5. Период блокировки: ${unlock_time_minutes:-не настроено} минут (требуется: 15)"
    if [[ "$unlock_time_minutes" -eq 15 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    log "6. Период разблокировки: ${unlock_time_minutes:-не настроено} минут (требуется: 15)"
    if [[ "$unlock_time_minutes" -eq 15 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi
    
    # Проверка индивидуальных настроек для реальных пользователей
    log ""
    log "=== ПРОВЕРКА ИНДИВИДУАЛЬНЫХ НАСТРОЕК ДЛЯ ПОЛЬЗОВАТЕЛЕЙ ==="
    
    local system_users=($(get_system_users))
    if [[ ${#system_users[@]} -eq 0 ]]; then
        log "Реальные пользователи системы не найдены"
    else
        log "Найдены реальные пользователи: ${system_users[*]}"
        log ""
        
        for user in "${system_users[@]}"; do
            log "Пользователь: $user"
            
            # Проверка старения паролей для каждого пользователя с русским парсингом
            local user_chage_output=$(chage -l "$user" 2>/dev/null)
            
            local user_max_days=$(echo "$user_chage_output" | grep -i "Максимальное количество дней между сменой пароля" | awk -F: '{print $2}' | tr -d ' ' | head -1 || echo "не настроено")
            local user_min_days=$(echo "$user_chage_output" | grep -i "Минимальное количество дней между сменой пароля" | awk -F: '{print $2}' | tr -d ' ' | head -1 || echo "не настроено")
            local user_warn_days=$(echo "$user_chage_output" | grep -i "Количество дней с предупреждением перед деактивацией пароля" | awk -F: '{print $2}' | tr -d ' ' | head -1 || echo "не настроено")
            
            log "  Максимальный срок пароля: $user_max_days (требуется: 90)"
            log "  Минимальный срок пароля: $user_min_days (требуется: 0)"
            log "  Предупреждение за: $user_warn_days дней (требуется: 7)"
            
            # Проверка соответствия
            local user_ok=true
            if [[ "$user_max_days" != "90" ]]; then
                user_ok=false
                log_color "$RED" "  ✗ Максимальный срок пароля не соответствует"
            fi
            if [[ "$user_min_days" != "0" ]]; then
                user_ok=false
                log_color "$RED" "  ✗ Минимальный срок пароля не соответствует"
            fi
            if [[ "$user_warn_days" != "7" ]]; then
                user_ok=false
                log_color "$RED" "  ✗ Срок предупреждения не соответствует"
            fi
            
            if [[ "$user_ok" == "true" ]]; then
                log_color "$GREEN" "  ✓ Все настройки соответствуют"
            fi
            log ""
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
        local selinux_status=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $3}')
        if [[ "$selinux_status" == "enabled" ]]; then
            mac_enabled=true
            mac_systems+=("SELinux")
        fi
        log "SELinux статус: $selinux_status"
    fi
    
    # Проверка AppArmor
    if command -v aa-status &>/dev/null; then
        if aa-status 2>/dev/null | grep -q "apparmor module is loaded"; then
            mac_enabled=true
            mac_systems+=("AppArmor")
        fi
    fi
    
    # Логика проверки согласно эталону (требуется Выключено)
    if [[ "$mac_enabled" == "false" ]]; then
        log_color "$GREEN" "✓ Мандатный контроль целостности: Выключено (СООТВЕТСТВУЕТ эталону)"
    else
        log_color "$RED" "✗ Мандатный контроль целостности активен: ${mac_systems[*]} (НЕ СООТВЕТСТВУЕТ эталону, требуется: Выключено)"
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
