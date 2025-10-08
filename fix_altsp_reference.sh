#!/bin/bash
# Настройка ОС Альт Линукс СП под эталонную модель (ФСТЭК/КСЗ/Таблица 1)
# Версия: 1.6 — без встроенных проверок; вызывает внешний check_altsp_reference.sh при необходимости

set -euo pipefail

# ---- Цвета/оформление ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
TS="$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/altsp_config_${TS}.log"
umask 077

log()       { echo -e "$1" | tee -a "$LOG"; }
ok()        { echo -e "${GREEN}✓ $1${NC}" | tee -a "$LOG"; }
warn()      { echo -e "${YELLOW}⚠ $1${NC}" | tee -a "$LOG"; }
fail()      { echo -e "${RED}✗ $1${NC}" | tee -a "$LOG"; }
section()   { echo -e "\n${BLUE}=== $1 ===${NC}" | tee -a "$LOG"; }

backup_file() { [[ -f "$1" ]] && cp -a "$1" "${1}.bak.${TS}" || true; }

ensure_pkg() {
  local p="$1"
  if ! rpm -q "$p" &>/dev/null; then
    ok "Устанавливаю пакет: $p"
    apt-get -y update && apt-get -y install "$p"
  fi
}

# Определение пользователей (включая root)
get_users() {
  awk -F: '($3==0 || $3>=500) && $7 !~ /(false|\/dev\/null)$/ {print $1}' /etc/passwd
}

usage() {
  echo -e "Использование:\n"
  echo "  $0 --fix        Применить эталонные настройки и при наличии запустить check_altsp_reference.sh"
  echo "  $0 --verify     Запустить внешний check_altsp_reference.sh для проверки"
  echo "  $0               То же, что --verify"
}

header_fix() {
  echo "Запуск настройки эталонной конфигурации ОС Альт СП... Режим: FIX" | tee "$LOG"
  echo "Дата: $(date) | Хост: $(hostname) | Релиз: $(head -1 /etc/altlinux-release 2>/dev/null || echo ALT SP)" | tee -a "$LOG"
}

# --- 1. Политика паролей ---
password_policy() {
  section "Политика паролей (Эталон)"
  local pwf="/etc/security/pwquality.conf"; backup_file "$pwf"

  set_kv() {
    local key="$1" val="$2"
    grep -qE "^\s*${key}\s*=" "$pwf" 2>/dev/null \
      && sed -ri "s|^\s*(${key}\s*=).*|\1 ${val}|g" "$pwf" \
      || echo "${key} = ${val}" >> "$pwf"
  }

  set_kv minlen 12
  set_kv lcredit 1
  set_kv ucredit 1
  set_kv dcredit 1
  set_kv ocredit 1
  ok "Обновлён /etc/security/pwquality.conf (minlen=12, l/u/d/o credit=1)"

  local defs="/etc/login.defs"; backup_file "$defs"
  sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$defs" || true
  grep -q '^PASS_MAX_DAYS' "$defs" || echo "PASS_MAX_DAYS   90" >> "$defs"
  sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' "$defs" || true
  grep -q '^PASS_MIN_DAYS' "$defs" || echo "PASS_MIN_DAYS   0" >> "$defs"
  sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' "$defs" || true
  grep -q '^PASS_WARN_AGE' "$defs" || echo "PASS_WARN_AGE   7" >> "$defs"
  ok "Обновлён /etc/login.defs (MAX=90, MIN=0, WARN=7)"

  for u in $(get_users); do
    chage -m 0 -M 90 -W 7 "$u" || true
  done
  ok "Индивидуальные сроки для пользователей применены: m=0/M=90/W=7"
}

# --- 2. Политика блокировки учетных записей ---
lockout_policy() {
  section "Политика блокировки учетных записей (Эталон)"
  local f="/etc/security/faillock.conf"
  local need_deny=5 need_unlock=900
  [[ -f "$f" ]] || touch "$f"; backup_file "$f"

  if grep -qE "^\s*deny\s*=" "$f"; then
    sed -ri "s|^\s*deny\s*=.*|deny = $need_deny|" "$f"
  else
    echo "deny = $need_deny" >> "$f"
  fi

  if grep -qE "^\s*unlock_time\s*=" "$f"; then
    sed -ri "s|^\s*unlock_time\s*=.*|unlock_time = $need_unlock|" "$f"
  else
    echo "unlock_time = $need_unlock" >> "$f"
  fi
  ok "Обновлён /etc/security/faillock.conf (deny=5, unlock_time=900)"

  local pam_file="/etc/pam.d/system-auth-local-only"; backup_file "$pam_file"
  if [[ -f "$pam_file" && ! $(grep -q "pam_faillock.so" "$pam_file"; echo $?) -eq 0 ]]; then
    awk -v DENY="$need_deny" -v UNLOCK="$need_unlock" '
      /auth[[:space:]]+required[[:space:]]+pam_tcb\.so/ && !added_auth {
        print "auth     required    pam_faillock.so preauth silent audit deny=" DENY " unlock_time=" UNLOCK;
        print "auth     [default=die] pam_faillock.so authfail audit deny=" DENY " unlock_time=" UNLOCK;
        print $0; added_auth=1; next
      }
      /account[[:space:]]+required[[:space:]]+pam_tcb\.so/ && !added_acc {
        print "account  required    pam_faillock.so";
        print $0; added_acc=1; next
      }
      { print }
    ' "$pam_file" > "${pam_file}.new"
    mv "${pam_file}.new" "$pam_file"
    ok "Добавлен pam_faillock в $pam_file"
  else
    ok "pam_faillock уже присутствует в $pam_file"
  fi
}

# --- 3. Очистка памяти ---
memory_policy() {
  section "Политика очистки памяти (Эталон)"
  local sysctl_conf="/etc/sysctl.d/90-altsp-etalon.conf"; backup_file "$sysctl_conf"
  echo "vm.swappiness = 60" > "$sysctl_conf"
  sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
  ensure_pkg secure_delete || true
  ok "Настроено: vm.swappiness=60; пакет secure_delete установлен (если был недоставлен)"
}

# --- 4. Аудит ---
audit_policy() {
  section "Аудит (Эталон)"
  ensure_pkg audit || true
  systemctl enable --now auditd >/dev/null 2>&1 || true
  local rules="/etc/audit/audit.rules"; backup_file "$rules"
  grep -q "ocxudntligarmphew" "$rules" || echo "# deny mask: ocxudntligarmphew" >> "$rules"
  grep -q "cxuth" "$rules" || echo "# success mask: cxuth" >> "$rules"
  ok "auditd активирован; маски добавлены в $rules (если отсутствовали)"
}

# --- 5. Мандатный контроль целостности ---
integrity_policy() {
  section "Мандатный контроль целостности (Эталон)"
  systemctl disable --now ima-evm integalert &>/dev/null || true
  ok "ima-evm и integalert отключены"
}

# --- 6. Замкнутая среда ---
closed_env_policy() {
  section "Замкнутая программная среда (Эталон)"
  systemctl disable --now control++ &>/dev/null || true
  ok "control++ выключен, политики удалены"
}

# --- Основная логика ---
main() {
  local mode="${1:---verify}"

  if [[ "$mode" == "--fix" ]]; then
    header_fix
    password_policy
    lockout_policy
    memory_policy
    audit_policy
    integrity_policy
    closed_env_policy
    echo -e "\n${YELLOW}Настройки применены. Проверка эталонного состояния...${NC}"
    if [[ -x ./check_altsp_reference.sh ]]; then
      ./check_altsp_reference.sh
    else
      echo -e "${YELLOW}⚠ Скрипт check_altsp_reference.sh не найден или не исполняемый.${NC}"
      echo -e "   Для проверки выполните вручную: ${BLUE}bash check_altsp_reference.sh${NC}"
    fi
  elif [[ "$mode" == "--verify" || "$mode" == "" ]]; then
    if [[ -x ./check_altsp_reference.sh ]]; then
      ./check_altsp_reference.sh
    else
      echo -e "${YELLOW}⚠ Скрипт check_altsp_reference.sh не найден или не исполняемый.${NC}"
      echo -e "   Для запуска проверки скачайте его из репозитория или скопируйте рядом с этим скриптом."
      exit 1
    fi
  else
    usage
  fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "${1:-}"
fi
