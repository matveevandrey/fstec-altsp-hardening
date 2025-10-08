#!/bin/bash
# Скрипт проверки соответствия эталонной конфигурации ОС Альт Линукс СП
# Версия: 2.3-full — С интеграцией требований КСЗ по мандатному контролю целостности и замкнутой среде
# Автор: [твой отдел / дата]

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

COMPLIANCE_FILE="/var/log/compliance_report_$(date +%Y%m%d_%H%M%S).log"

log() { echo "$1" | tee -a "$COMPLIANCE_FILE"; }
log_color() { echo -e "${1}${2}${NC}" | tee -a "$COMPLIANCE_FILE"; }

get_system_users() {
    local users=()
    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ $uid -eq 0 ]] || [[ $uid -ge 500 ]]; then
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
    echo "===================================================" | tee -a "$COMPLIANCE_FILE"
}

# === ПРОВЕРКА ПОЛИТИКИ ПАРОЛЕЙ ===
check_password_policy() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ ПАРОЛЕЙ ==="
    local minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
    log "1. Минимальная длина пароля: ${minlen:-не настроено} (требуется: 12)"
    if [[ "$minlen" -eq 12 ]]; then
        log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
    else
        log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    fi

    for c in lcredit ucredit dcredit ocredit; do
        val=$(grep -E "^\s*$c\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
        case $c in
            lcredit) txt="строчных";;
            ucredit) txt="заглавных";;
            dcredit) txt="цифр";;
            ocredit) txt="других символов";;
        esac
        log "Минимальное количество $txt: ${val:--} (требуется: -1 или 1)"
        if [[ "$val" == "-1" || "$val" == "1" ]]; then
            log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ"
        else
            log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
        fi
    done

    local chage_output=$(chage -l root 2>/dev/null)
    local min_days=$(echo "$chage_output" | grep -i "Минимальное количество дней" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    local max_days=$(echo "$chage_output" | grep -i "Максимальное количество дней" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    local warn_days=$(echo "$chage_output" | grep -i "предупреждением" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    local inactive_days=$(echo "$chage_output" | grep -i "Пароль будет деактивирован" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    local expire_days=$(echo "$chage_output" | grep -i "Срок действия учётной записи истекает" | awk -F: '{print $2}' | tr -d ' ' | head -1)

    log "6. Минимальное количество дней между сменами пароля: ${min_days:-не настроено} (требуется: 0)"
    [[ "$min_days" -eq 0 ]] && log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ" || log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    log "7. Максимальное количество дней между сменами пароля: ${max_days:-не настроено} (требуется: 90)"
    [[ "$max_days" -eq 90 ]] && log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ" || log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    log "8. Число дней предупреждения: ${warn_days:-не настроено} (требуется: 7)"
    [[ "$warn_days" -eq 7 ]] && log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ" || log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    log "9. Неактивность после устаревания: ${inactive_days:-никогда} (требуется: отключено)"
    [[ -z "$inactive_days" || "$inactive_days" == "никогда" ]] && log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ" || log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
    log "10. Срок действия учетной записи: ${expire_days:-никогда} (требуется: отключено)"
    [[ -z "$expire_days" || "$expire_days" == "никогда" ]] && log_color "$GREEN" "   ✓ СООТВЕТСТВУЕТ" || log_color "$RED" "   ✗ НЕ СООТВЕТСТВУЕТ"
}

# === ПРОВЕРКА ПОЛИТИКИ БЛОКИРОВКИ ===
check_account_lockout() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ БЛОКИРОВКИ УЧЕТНЫХ ЗАПИСЕЙ ==="
    local deny unlock_time
    if [[ -f /etc/security/faillock.conf ]]; then
        deny=$(grep -E "^deny" /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ')
        unlock_time=$(grep -E "^unlock_time" /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ')
    fi
    log "Неуспешных попыток: ${deny:-не настроено} (требуется: 5)"
    [[ "$deny" -eq 5 ]] && log_color "$GREEN" "✓ Соответствует" || log_color "$RED" "✗ НЕ соответствует"
    local unlock_min=$((unlock_time/60))
    log "Период блокировки/разблокировки: ${unlock_min:-не настроено} мин (требуется: 15)"
    [[ "$unlock_min" -eq 15 ]] && log_color "$GREEN" "✓ Соответствует" || log_color "$RED" "✗ НЕ соответствует"

    log ""
    log "=== ПРОВЕРКА ИНДИВИДУАЛЬНЫХ НАСТРОЕК ДЛЯ ПОЛЬЗОВАТЕЛЕЙ ==="
    log "# Проверка индивидуальных настроек пользователей согласно эталонной модели (Таблица 1)"
    local system_users=($(get_system_users))
    for user in "${system_users[@]}"; do
        local out=$(chage -l "$user" 2>/dev/null)
        local max_days=$(echo "$out" | grep -i "Максимальное количество дней" | awk -F: '{print $2}' | tr -d ' ' | head -1)
        local min_days=$(echo "$out" | grep -i "Минимальное количество дней" | awk -F: '{print $2}' | tr -d ' ' | head -1)
        local warn_days=$(echo "$out" | grep -i "предупреждением" | awk -F: '{print $2}' | tr -d ' ' | head -1)
        log "Пользователь: $user"
        log "  max_days=$max_days (90), min_days=$min_days (0), warn_days=$warn_days (7)"
        [[ "$max_days" == "90" && "$min_days" == "0" && "$warn_days" == "7" ]] \
            && log_color "$GREEN" "   ✓ Все настройки соответствуют" \
            || log_color "$RED" "   ✗ Обнаружено несоответствие"
    done
}

# === ПРОВЕРКА НАСТРОЕК АУДИТА ===
check_audit_settings() {
    log ""
    log "=== ПРОВЕРКА НАСТРОЕК АУДИТА ==="
    local audit_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
    log "Статус службы auditd: $audit_status"
    if systemctl is-active auditd &>/dev/null; then
        log_color "$GREEN" "✓ Служба auditd активна"
        local rules=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l)
        log "Количество активных правил: $rules"
        [[ $rules -gt 0 ]] && log_color "$GREEN" "✓ Правила аудита настроены" || log_color "$RED" "✗ Правила отсутствуют"
        grep -q "ocxudntligarmphew" /etc/audit/audit.rules 2>/dev/null \
            && log_color "$GREEN" "✓ Маска аудита отказов соответствует (ocxudntligarmphew)" \
            || log_color "$RED" "✗ Нет маски аудита отказов"
        grep -q "cxuth" /etc/audit/audit.rules 2>/dev/null \
            && log_color "$GREEN" "✓ Маска аудита успехов соответствует (cxuth)" \
            || log_color "$RED" "✗ Нет маски аудита успехов"
    else
        log_color "$RED" "✗ Служба auditd не активна"
    fi
}

# === ПРОВЕРКА ПОЛИТИКИ ОЧИСТКИ ПАМЯТИ ===
check_memory_clearing() {
    log ""
    log "=== ПРОВЕРКА ПОЛИТИКИ ОЧИСТКИ ПАМЯТИ ==="
    local swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "60")
    log "vm.swappiness=$swappiness (требуется <=60)"
    [[ $swappiness -le 60 ]] && log_color "$GREEN" "✓ Очистка swap отключена" || log_color "$RED" "✗ Очистка активна"
    rpm -q secure_delete &>/dev/null || command -v srm &>/dev/null \
        && log_color "$GREEN" "✓ Утилиты гарантированного удаления присутствуют" \
        || log_color "$RED" "✗ secure_delete отсутствует"
}

# === ПРОВЕРКА МАНДАТНОГО КОНТРОЛЯ ЦЕЛОСТНОСТИ ===
check_integrity_control() {
    log ""
    log "=== ПРОВЕРКА МАНДАТНОГО КОНТРОЛЯ ЦЕЛОСТНОСТИ ==="
    local ima_status integ_status
    systemctl is-active ima-evm &>/dev/null && ima_status="active" || ima_status="inactive"
    systemctl is-active integalert &>/dev/null && integ_status="active" || integ_status="inactive"
    log "ima-evm: $ima_status, integalert: $integ_status"
    [[ "$ima_status" == "inactive" && "$integ_status" == "inactive" ]] \
        && log_color "$GREEN" "✓ Подсистема контроля целостности выключена (соответствует эталону)" \
        || log_color "$RED" "✗ Подсистема контроля целостности активна"
    grep -q "ima_policy=" /proc/cmdline 2>/dev/null \
        && log_color "$RED" "✗ ima_policy найден (должен отсутствовать)" \
        || log_color "$GREEN" "✓ Параметр ima_policy отсутствует"
}

# === ПРОВЕРКА ЗАМКНУТОЙ ПРОГРАММНОЙ СРЕДЫ ===
check_software_environment() {
    log ""
    log "=== ПРОВЕРКА ЗАМКНУТОЙ ПРОГРАММНОЙ СРЕДЫ ==="
    systemctl is-active control++ &>/dev/null \
        && log_color "$RED" "✗ control++ активен (должен быть выключен)" \
        || log_color "$GREEN" "✓ control++ выключен (соответствует эталону)"
    local rule_count=$(find /etc/control++/rules.d/ -type f 2>/dev/null | wc -l)
    [[ $rule_count -eq 0 ]] && log_color "$GREEN" "✓ Политики control++ отсутствуют" || log_color "$YELLOW" "⚠ Найдено $rule_count политик control++"
    local imm=$(find /etc /bin /usr -maxdepth 2 -type f -exec lsattr {} + 2>/dev/null | grep " i " | wc -l)
    [[ $imm -eq 0 ]] && log_color "$GREEN" "✓ Атрибут immutable не используется" || log_color "$RED" "✗ Обнаружено $imm файлов с immutable"
}

generate_summary() {
    log ""
    log "=== СВОДНЫЙ ОТЧЁТ ==="
    local pass fail
    pass=$(grep -c "✓" "$COMPLIANCE_FILE")
    fail=$(grep -c "✗" "$COMPLIANCE_FILE")
    log "Всего проверок: $((pass+fail))"
    log "Соответствует: $pass"
    log "Не соответствует: $fail"
    [[ $fail -eq 0 ]] && log_color "$GREEN" "✓ Система полностью соответствует эталонной конфигурации" || log_color "$RED" "✗ Обнаружены несоответствия эталонной конфигурации"
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Запуск проверки соответствия эталонной конфигурации для Альт Линукс СП..."
    main
    echo -e "\n${GREEN}Проверка завершена. Отчет: $COMPLIANCE_FILE${NC}"
fi
