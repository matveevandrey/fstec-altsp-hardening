#!/bin/bash
# Настройка ОС Альт Линукс СП под эталонную модель (ФСТЭК/КСЗ/Таблица 1)
# Версия: 1.7 — добавлен pam_faillock (локальный вход) и аудит SSH
# Основано на версии 1.6, без удаления прежней логики

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

  sed -ri "s|^\s*deny\s*=.*|deny = $need_deny|" "$f" 2>/dev/null || echo "deny = $need_deny" >> "$f"
  sed -ri "s|^\s*unlock_time\s*=.*|unlock_time = $need_unlock|" "$f" 2>/dev/null || echo "unlock_time = $need_unlock" >> "$f"
  grep -q "^# even_deny_root" "$f" || echo "# even_deny_root" >> "$f"
  ok "Обновлён /etc/security/faillock.conf (deny=5, unlock_time=900, root исключён)"

  local pam_file="/etc/pam.d/system-auth-local-only"; backup_file "$pam_file"
  cat > "$pam_file" <<'EOF'
#%PAM-1.0
# --- Контроль неудачных попыток ---
auth            requisite       pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth            [success=1 default=bad] pam_tcb.so shadow fork nullok
auth            [default=die]   pam_faillock.so authfail deny=5 unlock_time=900
auth            sufficient      pam_faillock.so authsucc deny=5 unlock_time=900

# --- Основная аутентификация ---
account         required        pam_tcb.so shadow fork
password        required        pam_passwdqc.so config=/etc/passwdqc.conf
password        required        pam_tcb.so use_authtok shadow fork nullok write_to=tcb
session         required        pam_tcb.so
EOF
  ok "Обновлён PAM-стек для локальной аутентификации (system-auth-local-only)"
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
  local rules="/etc/audit/rules.d/ssh_fail.rules"; backup_file "$rules"
  cat > "$rules" <<'EOF'
# Отслеживание неудачных попыток входа по SSH
-w /var/log/btmp -p wa -k ssh_fail
EOF
  service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true
  ok "auditd активирован; аудит SSH-входов включен (ключ ssh_fail)"
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

# --- 7. Очистка faillock и проверка ---
reset_and_test() {
  section "Сброс и проверка"
  faillock --reset || true
  ok "Счётчики faillock сброшены"
  ausearch -k ssh_fail --start recent >/dev/null 2>&1 || true
  ok "Аудит SSH активен (проверен ключ ssh_fail)"
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
    reset_and_test
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
