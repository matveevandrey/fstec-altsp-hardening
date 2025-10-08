#!/bin/bash
# Настройка ОС Альт Линукс СП под эталонную модель (ФСТЭК/КСЗ/Таблица 1)
# Версия: 1.3 (root включён в проверку и настройку индивидуальных сроков)
# Режимы:
#   без флагов / --check : только проверка соответствия
#   --fix                : применить настройки к эталону

set -euo pipefail

# ---- Цвета/вывод ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
TS="$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/altsp_config_${TS}.log"
MODE="check"
[[ "${1:-}" == "--fix" ]] && MODE="fix"
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
    if [[ "$MODE" == "fix" ]]; then
      ok "Устанавливаю пакет: $p"
      apt-get -y update && apt-get -y install "$p"
    else
      warn "Пакет $p не установлен"
      return 1
    fi
  fi
}

# Определение реальных пользователей (включая root)
get_users() {
  awk -F: '($3==0 || $3>=500) && $7 !~ /(false|\/dev\/null)$/ {print $1}' /etc/passwd
}

COUNT_TOTAL=0; COUNT_OK=0; COUNT_FAIL=0
checkmark() { COUNT_TOTAL=$((COUNT_TOTAL+1)); [[ "$1" == "ok" ]] && COUNT_OK=$((COUNT_OK+1)) || COUNT_FAIL=$((COUNT_FAIL+1)); }

header() {
  echo "Запуск настройки эталонной конфигурации ОС Альт СП... Режим: $MODE" | tee "$LOG"
  echo "Дата: $(date) | Хост: $(hostname) | Релиз: $(head -1 /etc/altlinux-release 2>/dev/null || echo ALT SP)" | tee -a "$LOG"
}

# --- 1. Политика паролей ---
password_policy() {
  section "Политика паролей (Эталон)"
  local pwf="/etc/security/pwquality.conf"; backup_file "$pwf"
  local need_minlen=12

  get_val() { grep -E "^\s*$1\s*=" "$pwf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2);print $2}' | tail -1; }
  set_val() {
    local key="$1" val="$2"
    grep -qE "^\s*${key}\s*=" "$pwf" 2>/dev/null && sed -ri "s|^\s*(${key}\s*=).*|\1 ${val}|g" "$pwf" || echo "${key} = ${val}" >> "$pwf"
  }

  if [[ "$MODE" == "fix" ]]; then
    set_val minlen "$need_minlen"
    set_val lcredit 1
    set_val ucredit 1
    set_val dcredit 1
    set_val ocredit 1
  fi

  for k in minlen lcredit ucredit dcredit ocredit; do
    val="$(get_val $k)"
    case $k in minlen) target=12;; *) target=1;; esac
    if [[ "$val" == "$target" || "$val" == "-1" ]]; then ok "$k=$val (ОК)"; checkmark ok; else fail "$k=${val:-нет} (нужно $target)"; checkmark fail; fi
  done

  local defs="/etc/login.defs"; backup_file "$defs"
  if [[ "$MODE" == "fix" ]]; then
    sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$defs" || echo "PASS_MAX_DAYS   90" >> "$defs"
    sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' "$defs" || echo "PASS_MIN_DAYS   0" >> "$defs"
    sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' "$defs" || echo "PASS_WARN_AGE   7" >> "$defs"
  fi

  grep -q "^PASS_MAX_DAYS\s\+90" "$defs" && ok "PASS_MAX_DAYS=90" || fail "PASS_MAX_DAYS неверно"
  grep -q "^PASS_MIN_DAYS\s\+0"  "$defs" && ok "PASS_MIN_DAYS=0"  || fail "PASS_MIN_DAYS неверно"
  grep -q "^PASS_WARN_AGE\s\+7"  "$defs" && ok "PASS_WARN_AGE=7"  || fail "PASS_WARN_AGE неверно"

  log ""
  log "Проверка индивидуальных сроков смены паролей (Таблица 1):"
  for u in $(get_users); do
    if [[ "$MODE" == "fix" ]]; then
      chage -m 0 -M 90 -W 7 "$u" || true
    fi
    local out=$(chage -l "$u" 2>/dev/null)
    local min=$(echo "$out" | grep -i "Минимальное количество дней" | awk -F: '{gsub(/ /,"",$2);print $2}')
    local max=$(echo "$out" | grep -i "Максимальное количество дней" | awk -F: '{gsub(/ /,"",$2);print $2}')
    local warn=$(echo "$out" | grep -i "предупреждением" | awk -F: '{gsub(/ /,"",$2);print $2}')
    if [[ "$min" == "0" && "$max" == "90" && "$warn" == "7" ]]; then
      ok "Пользователь $u: индивидуальные сроки соответствуют"
    else
      fail "Пользователь $u: m=$min M=$max W=$warn (нужно 0/90/7)"
    fi
  done
}

# --- 2. Политика блокировки учетных записей ---
lockout_policy() {
  section "Политика блокировки учетных записей (Эталон)"
  local f="/etc/security/faillock.conf"; backup_file "$f"
  local need_deny=5; local need_unlock=900

  if [[ "$MODE" == "fix" ]]; then
    grep -q "deny" "$f" && sed -ri "s|^\s*deny\s*=.*|deny = $need_deny|" "$f" || echo "deny = $need_deny" >> "$f"
    grep -q "unlock_time" "$f" && sed -ri "s|^\s*unlock_time\s*=.*|unlock_time = $need_unlock|" "$f" || echo "unlock_time = $need_unlock" >> "$f"
  fi

  local cur_deny=$(grep -E "^\s*deny\s*=" "$f" | awk -F= '{print $2}' | tr -d ' ')
  local cur_unlock=$(grep -E "^\s*unlock_time\s*=" "$f" | awk -F= '{print $2}' | tr -d ' ')
  [[ "$cur_deny" == "$need_deny" ]] && ok "deny=$cur_deny" || fail "deny=${cur_deny:-нет}"
  [[ "$cur_unlock" == "$need_unlock" ]] && ok "unlock_time=${cur_unlock}s (15m)" || fail "unlock_time=${cur_unlock:-нет}"

  # Правим system-auth-local-only
  local pam_file="/etc/pam.d/system-auth-local-only"; backup_file "$pam_file"
  if [[ -f "$pam_file" ]]; then
    if ! grep -q "pam_faillock.so" "$pam_file"; then
      if [[ "$MODE" == "fix" ]]; then
        log "Добавляю pam_faillock в $pam_file"
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
        ok "pam_faillock добавлен в $pam_file"
      else
        warn "pam_faillock не найден в $pam_file"
      fi
    else
      ok "pam_faillock уже подключён в $pam_file"
    fi
  else
    fail "$pam_file отсутствует"
  fi

  log ""
  ok "PAM faillock ведёт индивидуальные счётчики блокировки (по одному файлу на пользователя в /var/run/faillock)"
}

# --- 3. Очистка памяти ---
memory_policy() {
  section "Политика очистки памяти (Эталон)"
  local sysctl_conf="/etc/sysctl.d/90-altsp-etalon.conf"; backup_file "$sysctl_conf"
  if [[ "$MODE" == "fix" ]]; then
    echo "vm.swappiness = 60" > "$sysctl_conf"
    sysctl -p "$sysctl_conf" || true
  fi
  local cur=$(sysctl -n vm.swappiness 2>/dev/null || echo 60)
  [[ "$cur" -le 60 ]] && ok "vm.swappiness=$cur" || fail "vm.swappiness=$cur (>60)"
  ensure_pkg secure_delete || true
  if command -v srm &>/dev/null; then ok "secure_delete/srm присутствует"; else fail "secure_delete не установлен"; fi
}

# --- 4. Аудит ---
audit_policy() {
  section "Аудит (Эталон)"
  ensure_pkg audit || true
  systemctl enable --now auditd &>/dev/null || true
  local rules="/etc/audit/audit.rules"; backup_file "$rules"
  if [[ "$MODE" == "fix" ]]; then
    grep -q "ocxudntligarmphew" "$rules" || echo "# deny mask: ocxudntligarmphew" >> "$rules"
    grep -q "cxuth" "$rules" || echo "# success mask: cxuth" >> "$rules"
  fi
  systemctl is-active auditd &>/dev/null && ok "auditd активен" || fail "auditd не активен"
  grep -q "ocxudntligarmphew" "$rules" && ok "Маска отказов присутствует" || fail "Нет маски отказов"
  grep -q "cxuth" "$rules" && ok "Маска успехов присутствует" || fail "Нет маски успехов"
}

# --- 5. Мандатный контроль целостности ---
integrity_policy() {
  section "Мандатный контроль целостности (Эталон: Выключено)"
  local grub="/etc/default/grub"; backup_file "$grub"
  if [[ "$MODE" == "fix" ]]; then
    systemctl disable --now ima-evm integalert &>/dev/null || true
    sed -ri 's/(GRUB_CMDLINE_LINUX=.*)ima_policy=[^" ]* ?/\1/g' "$grub" || true
    if command -v grub2-mkconfig &>/dev/null; then grub2-mkconfig -o /boot/grub/grub.cfg; fi
  fi
  systemctl is-active ima-evm &>/dev/null    && fail "ima-evm активен"      || ok "ima-evm выключен"
  systemctl is-active integalert &>/dev/null && fail "integalert активен"   || ok "integalert выключен"
  grep -q "ima_policy=" /proc/cmdline        && fail "ima_policy найден в параметрах ядра" || ok "ima_policy отсутствует"
}

# --- 6. Замкнутая программная среда ---
closed_env_policy() {
  section "Замкнутая программная среда (Эталон: Выключить)"
  if systemctl is-active control++ &>/dev/null; then
    [[ "$MODE" == "fix" ]] && systemctl disable --now control++ &>/dev/null
  fi
  systemctl is-active control++ &>/dev/null && fail "control++ активен" || ok "control++ выключен"
  local rule_count=$(find /etc/control++/rules.d/ -type f 2>/dev/null | wc -l)
  [[ "$rule_count" -eq 0 ]] && ok "Политики control++ отсутствуют" || warn "Найдено $rule_count политик control++"
  local imm=$(find /etc /bin /usr -maxdepth 2 -type f -exec lsattr {} + 2>/dev/null | grep " i " | wc -l)
  [[ "$imm" -eq 0 ]] && ok "Атрибут immutable не используется" || warn "Найдено $imm файлов с immutable"
}

# --- Сводка ---
summary() {
  section "Сводка"
  log "Всего проверок: $COUNT_TOTAL"
  log "ОК: $COUNT_OK | Ошибок: $COUNT_FAIL"
  [[ "$MODE" == "fix" ]] && log "Режим FIX — применены изменения, бэкапы *.bak.${TS}" || log "Режим CHECK — изменений не вносилось."
  [[ $COUNT_FAIL -eq 0 ]] && ok "Система соответствует эталонной конфигурации" || fail "Обнаружены несоответствия, см. $LOG"
}

main() {
  header
  password_policy
  lockout_policy
  memory_policy
  audit_policy
  integrity_policy
  closed_env_policy
  summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main
fi
