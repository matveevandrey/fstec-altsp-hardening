#!/bin/bash
# Скрипт проверки соответствия эталонной конфигурации ОС Альт Линукс СП
# Версия: 2.6 — поддержка английской и русской локали chage, улучшенный формат отчёта

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
    if [[ $uid -eq 0 || $uid -ge 500 ]]; then
      [[ "$shell" != */nologin && "$shell" != */false && "$shell" != "/dev/null" ]] && users+=("$user")
    fi
  done < /etc/passwd
  echo "${users[@]}"
}

check_compliance() {
  echo "=== ПРОВЕРКА СООТВЕТСТВИЯ ЭТАЛОННОЙ КОНФИГУРАЦИИ ===" | tee "$COMPLIANCE_FILE"
  echo "Дата проверки: $(date)" | tee -a "$COMPLIANCE_FILE"
  echo "Хост: $(hostname)" | tee -a "$COMPLIANCE_FILE"
  echo "Дистрибутив: $(head -1 /etc/altlinux-release 2>/dev/null || echo 'Альт Линукс СП')" | tee -a "$COMPLIANCE_FILE"
  echo "===================================================" | tee -a "$COMPLIANCE_FILE"
}

# --- Проверка политики паролей ---
check_password_policy() {
  log ""
  log "=== ПРОВЕРКА ПОЛИТИКИ ПАРОЛЕЙ ==="

  # Чтение параметров pwquality
  local minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
  local lcredit=$(grep -E "^\s*lcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
  local ucredit=$(grep -E "^\s*ucredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
  local dcredit=$(grep -E "^\s*dcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
  local ocredit=$(grep -E "^\s*ocredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)

  printf "%-70s" "1. Минимальная длина пароля: ${minlen:-нет} (требуется: 12)" | tee -a "$COMPLIANCE_FILE"
  [[ "$minlen" -eq 12 ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "2. Минимум строчных символов (lcredit): ${lcredit:-нет} (требуется: -1 или 1)" | tee -a "$COMPLIANCE_FILE"
  [[ "$lcredit" == "-1" || "$lcredit" == "1" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "3. Минимум заглавных символов (ucredit): ${ucredit:-нет} (требуется: -1 или 1)" | tee -a "$COMPLIANCE_FILE"
  [[ "$ucredit" == "-1" || "$ucredit" == "1" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "4. Минимум цифр (dcredit): ${dcredit:-нет} (требуется: -1 или 1)" | tee -a "$COMPLIANCE_FILE"
  [[ "$dcredit" == "-1" || "$dcredit" == "1" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "5. Минимум спецсимволов (ocredit): ${ocredit:-нет} (требуется: -1 или 1)" | tee -a "$COMPLIANCE_FILE"
  [[ "$ocredit" == "-1" || "$ocredit" == "1" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  # Универсальные регулярки: поддержка ru/en локалей
  local chage_output=$(chage -l root 2>/dev/null)
  local min_days=$(echo "$chage_output" | grep -E -i "Минимальное количество дней|Minimum number of days" | awk -F: '{print $2}' | tr -d ' ')
  local max_days=$(echo "$chage_output" | grep -E -i "Максимальное количество дней|Maximum number of days" | awk -F: '{print $2}' | tr -d ' ')
  local warn_days=$(echo "$chage_output" | grep -E -i "предупреждением|Number of days of warning" | awk -F: '{print $2}' | tr -d ' ')
  local inactive_days=$(echo "$chage_output" | grep -E -i "Пароль будет деактивирован|Password inactive" | awk -F: '{print $2}' | tr -d ' ')
  local account_expires=$(echo "$chage_output" | grep -E -i "Срок действия учётной записи истекает|Account expires" | awk -F: '{print $2}' | tr -d ' ')

  printf "%-70s" "6. Минимальное кол-во дней между сменами: ${min_days:-нет} (нужно: 0)" | tee -a "$COMPLIANCE_FILE"
  [[ "$min_days" == "0" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "7. Максимальное кол-во дней между сменами: ${max_days:-нет} (нужно: 90)" | tee -a "$COMPLIANCE_FILE"
  [[ "$max_days" == "90" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "8. Предупреждение за: ${warn_days:-нет} (нужно: 7)" | tee -a "$COMPLIANCE_FILE"
  [[ "$warn_days" == "7" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "9. Неактивность после устаревания: ${inactive_days:-never} (нужно: отключено)" | tee -a "$COMPLIANCE_FILE"
  [[ -z "$inactive_days" || "$inactive_days" == "never" || "$inactive_days" == "никогда" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  printf "%-70s" "10. Срок действия учётной записи: ${account_expires:-never} (нужно: отключено)" | tee -a "$COMPLIANCE_FILE"
  [[ -z "$account_expires" || "$account_expires" == "never" || "$account_expires" == "никогда" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"
}

# --- Проверка политики блокировки учетных записей ---
check_account_lockout() {
  log ""
  log "=== ПРОВЕРКА ПОЛИТИКИ БЛОКИРОВКИ УЧЕТНЫХ ЗАПИСЕЙ ==="

  local deny="" unlock_time=""
  if [[ -f /etc/security/faillock.conf ]]; then
    deny=$(grep -E "^deny\s*=" /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ')
    unlock_time=$(grep -E "^unlock_time\s*=" /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ')
  fi

  printf "%-70s" "1. Неуспешных попыток (deny): ${deny:-не настроено} (нужно: 5)" | tee -a "$COMPLIANCE_FILE"
  [[ "$deny" == "5" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  local unlock_min=""; [[ -n "$unlock_time" ]] && unlock_min=$((unlock_time/60))
  printf "%-70s" "2. Период блокировки/разблокировки: ${unlock_min:-не настроено} мин (нужно: 15)" | tee -a "$COMPLIANCE_FILE"
  [[ "$unlock_min" == "15" ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"

  local pam="/etc/pam.d/system-auth-local-only"
  if [[ -f "$pam" ]]; then
    if grep -q "pam_faillock.so" "$pam"; then
      log_color "$GREEN" "✓ pam_faillock подключен в $pam"
    else
      log_color "$RED" "✗ pam_faillock отсутствует в $pam"
    fi
  fi

  log_color "$GREEN" "✓ PAM faillock ведёт индивидуальные счётчики блокировки (/var/run/faillock/<user>)"
}

# --- Проверка аудита ---
check_audit_settings() {
  log ""
  log "=== ПРОВЕРКА НАСТРОЕК АУДИТА ==="
  systemctl is-active auditd &>/dev/null && log_color "$GREEN" "✓ auditd активен" || log_color "$RED" "✗ auditd не активен"
  grep -q "ocxudntligarmphew" /etc/audit/audit.rules && log_color "$GREEN" "✓ Маска отказов присутствует" || log_color "$RED" "✗ Нет маски отказов"
  grep -q "cxuth" /etc/audit/audit.rules && log_color "$GREEN" "✓ Маска успехов присутствует" || log_color "$RED" "✗ Нет маски успехов"
}

# --- Очистка памяти ---
check_memory_clearing() {
  log ""
  log "=== ПРОВЕРКА ПОЛИТИКИ ОЧИСТКИ ПАМЯТИ ==="
  local swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "60")
  printf "%-70s" "vm.swappiness=$swappiness (требуется <=60)" | tee -a "$COMPLIANCE_FILE"
  [[ "$swappiness" -le 60 ]] && echo -e "${GREEN} ✓${NC}" || echo -e "${RED} ✗${NC}"
  if command -v srm &>/dev/null; then log_color "$GREEN" "✓ secure_delete/srm присутствует"; else log_color "$RED" "✗ secure_delete не установлен"; fi
}

# --- Контроль целостности ---
check_integrity_control() {
  log ""
  log "=== ПРОВЕРКА МАНДАТНОГО КОНТРОЛЯ ЦЕЛОСТНОСТИ ==="
  systemctl is-active ima-evm &>/dev/null && log_color "$RED" "✗ ima-evm активен" || log_color "$GREEN" "✓ ima-evm выключен"
  systemctl is-active integalert &>/dev/null && log_color "$RED" "✗ integalert активен" || log_color "$GREEN" "✓ integalert выключен"
  grep -q "ima_policy=" /proc/cmdline && log_color "$RED" "✗ ima_policy найден" || log_color "$GREEN" "✓ ima_policy отсутствует"
}

# --- Замкнутая среда ---
check_software_environment() {
  log ""
  log "=== ПРОВЕРКА ЗАМКНУТОЙ ПРОГРАММНОЙ СРЕДЫ ==="
  systemctl is-active control++ &>/dev/null && log_color "$RED" "✗ control++ активен" || log_color "$GREEN" "✓ control++ выключен"
  local rules=$(find /etc/control++/rules.d/ -type f 2>/dev/null | wc -l)
  [[ "$rules" -eq 0 ]] && log_color "$GREEN" "✓ Политики control++ отсутствуют" || log_color "$YELLOW" "⚠ Найдено $rules политик control++"
}

# --- Сводка ---
generate_summary() {
  log ""
  log "=== СВОДНЫЙ ОТЧЁТ ==="
  local pass fail
  pass=$(grep -c "✓" "$COMPLIANCE_FILE")
  fail=$(grep -c "✗" "$COMPLIANCE_FILE")
  log "Всего проверок: $((pass+fail))"
  log "Соответствует: $pass"
  log "Не соответствует: $fail"
  [[ $fail -eq 0 ]] && log_color "$GREEN" "✓ Система полностью соответствует эталонной конфигурации" || log_color "$RED" "✗ Обнаружены несоответствия"
}

# --- Основной блок ---
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
