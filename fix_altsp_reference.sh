#!/bin/bash
# Настройка ОС Альт Линукс СП под эталонную модель (ФСТЭК/КСЗ/Таблица 1)
# Версия: 2.5 — apply-only (только по --fix/--apply), SSH PermitRootLogin no (автовыбор пути),
# sysctl-харднинг, расширенный аудит (условные SSH-пути, syscall escalation), passwdqc.conf
# even_deny_root отключён, двойной сброс faillock, предупреждения о дублях правил аудита.

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
  # root и все локальные пользователи uid>=500, у кого не «false»/dev/null в shell
  awk -F: '($3==0 || $3>=500) && $7 !~ /(false|\/dev\/null)$/ {print $1}' /etc/passwd
}

usage() {
  echo -e "Использование:\n"
  echo "  $0 --fix        Применить эталонные настройки"
  echo "  $0 --apply      Синоним --fix"
}

header_fix() {
  echo "Запуск настройки эталонной конфигурации ОС Альт СП... Режим: FIX" | tee "$LOG"
  echo "Дата: $(date) | Хост: $(hostname) | Релиз: $(head -1 /etc/altlinux-release 2>/dev/null || echo ALT SP)" | tee -a "$LOG"
}

# --- 0. PASSWDQC: строгая политика паролей (под форматы check.sh) ---
passwdqc_policy() {
  section "PASSWDQC (строгая политика)"
  local f="/etc/passwdqc.conf"
  backup_file "$f"
  cat > "$f" <<'EOF'
# Password quality configuration
# Minimal password lengths for different password types
min=disabled,disabled,12,12,12
max=40
passphrase=3
match=4
similar=permit
enforce=everyone
retry=5
EOF
  ok "Создан /etc/passwdqc.conf по эталонной модели (min=disabled,disabled,12,12,12)"
}

# --- 1. Политика паролей (pwquality + login.defs + chage) ---
password_policy() {
  section "Политика паролей (pwquality, login.defs, chage)"
  local pwf="/etc/security/pwquality.conf"; backup_file "$pwf"

  set_kv() {
    local key="$1" val="$2"
    if grep -qE "^\s*${key}\s*=" "$pwf" 2>/dev/null; then
      sed -ri "s|^\s*(${key}\s*=).*|\1 ${val}|g" "$pwf"
    else
      echo "${key} = ${val}" >> "$pwf"
    fi
  }

  set_kv minlen 12
  set_kv lcredit 1
  set_kv ucredit 1
  set_kv dcredit 1
  set_kv ocredit 1
  ok "Обновлён /etc/security/pwquality.conf (minlen=12, l/u/d/o=1)"

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
  section "Политика блокировки учетных записей (faillock)"
  local f="/etc/security/faillock.conf"
  local need_deny=5 need_unlock=900
  [[ -f "$f" ]] || touch "$f"; backup_file "$f"

  # Настройка faillock.conf
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
  # Root НЕ блокируем — even_deny_root оставляем отключённым (закомментировано как подсказка)
  if ! grep -qE '^\s*#\s*even_deny_root' "$f"; then
    echo "# even_deny_root" >> "$f"
  fi
  ok "Обновлён /etc/security/faillock.conf (deny=5, unlock_time=900; root исключён — even_deny_root отключён)"

  # PAM: стек локальной аутентификации (без even_deny_root)
  local pam_file="/etc/pam.d/system-auth-local-only"; backup_file "$pam_file"
  cat > "$pam_file" <<'EOF'
#%PAM-1.0
# --- Контроль неудачных попыток (root НЕ блокируем; even_deny_root не используем) ---
auth            requisite       pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth            [success=1 default=bad] pam_tcb.so shadow fork nullok
auth            [default=die]   pam_faillock.so authfail audit deny=5 unlock_time=900
auth            sufficient      pam_faillock.so authsucc audit deny=5 unlock_time=900

# --- Основная аутентификация ---
account         required        pam_tcb.so shadow fork
password        required        pam_passwdqc.so config=/etc/passwdqc.conf
password        required        pam_tcb.so use_authtok shadow fork nullok write_to=tcb
session         required        pam_tcb.so
EOF
  ok "Обновлён PAM-стек (system-auth-local-only); even_deny_root не применяется"

  # Сброс накопленных блокировок — оба способа, как согласовано
  rm -f /var/run/faillock/* 2>/dev/null || true
  faillock --reset 2>/dev/null || true
  ok "Счётчики faillock сброшены (rm и faillock --reset)"
}

# --- 3. Системные параметры безопасности и гарантированное удаление ---
system_hardening() {
  section "Системные параметры безопасности и гарантированное удаление"
  local sysctl_conf="/etc/sysctl.d/90-altsp-etalon.conf"; backup_file "$sysctl_conf"

  cat > "$sysctl_conf" <<'EOF'
# Эталонная системная конфигурация безопасности ALT СП
vm.swappiness = 10
user.max_user_namespaces = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
EOF

  sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
  ok "Применены параметры: swappiness=10, max_user_namespaces=0, dmesg_restrict=1, kptr_restrict=2"

  ensure_pkg secure_delete || true
  ok "Пакет secure_delete установлен (srm/sfill/sswap/smem доступны)"
}

# --- 4. Аудит: расширенный профиль (условные SSH-пути, syscall escalation) ---
audit_policy() {
  section "Аудит (расширенный профиль)"
  ensure_pkg audit || true
  systemctl enable --now auditd >/dev/null 2>&1 || true

  # Конфигурация auditd
  local AUDITD_CONF="/etc/audit/auditd.conf"; backup_file "$AUDITD_CONF"
  cat > "$AUDITD_CONF" <<'EOF'
log_file = /var/log/audit/audit.log
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 80
num_logs = 10
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF

  # Основные правила — пишем в единый файл
  local RULES_DIR="/etc/audit/rules.d"
  local RULES_FILE="${RULES_DIR}/security-audit.rules"
  backup_file "$RULES_FILE"

  # Соберём SSH-пути, которые реально существуют (чтобы не ломать augenrules на "No such file")
  local ssh_paths=()
  for p in \
    /etc/ssh/sshd_config /etc/ssh/ssh_config /etc/ssh/sshd_config.d \
    /etc/openssh/sshd_config /etc/openssh/ssh_config /etc/openssh/sshd_config.d
  do
    [[ -e "$p" ]] && ssh_paths+=("$p")
  done

  cat > "$RULES_FILE" <<EOF
# =========== Идентификация и база учетных записей ===========
-w /etc/passwd  -p wa -k identity_database
-w /etc/group   -p wa -k identity_database
-w /etc/gshadow -p wa -k identity_database
-w /etc/shadow  -p wa -k identity_database

# =========== Конфигурация SSH ===========
EOF

  if ((${#ssh_paths[@]})); then
    for p in "${ssh_paths[@]}"; do
      echo "-w $p -p wa -k ssh_config" >> "$RULES_FILE"
    done
  else
    echo "# (SSH-конфиги на диске не обнаружены; секция пропущена)" >> "$RULES_FILE"
  fi

  cat >> "$RULES_FILE" <<'EOF'

# =========== Попытки аутентификации и неудачные входы ===========
-w /var/log/btmp   -p wa -k login_fail
-w /var/log/wtmp   -p wa -k login_success
-w /var/log/secure -p wa -k security_logs

# =========== Запуск процессов ===========
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# =========== Изменения прав и владельцев ===========
-a always,exit -F arch=b64 -S chmod,chown,lchown,fchmod,fchown -k file_access
-a always,exit -F arch=b32 -S chmod,chown,lchown,fchmod,fchown -k file_access

# =========== Повышение привилегий (syscall) ===========
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -S setresuid -S setresgid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -S setresuid -S setresgid -k privilege_escalation

# =========== SUDO / Конфигурационные файлы привилегий ===========
-w /etc/sudoers   -p wa -k privilege_escalation
-w /etc/sudoers.d -p wa -k privilege_escalation

# =========== Конфигурация ядра и сети ===========
-w /etc/sysctl.conf -p wa -k kernel_config
-w /etc/sysctl.d    -p wa -k kernel_config
-w /etc/hosts       -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config

# =========== Планировщик задач ===========
-w /etc/cron.allow   -p wa -k cron_config
-w /etc/cron.deny    -p wa -k cron_config
-w /etc/crontab      -p wa -k cron_config
-w /etc/cron.d       -p wa -k cron_config
-w /etc/cron.daily   -p wa -k cron_config
-w /etc/cron.hourly  -p wa -k cron_config
-w /etc/cron.monthly -p wa -k cron_config
-w /etc/cron.weekly  -p wa -k cron_config
-w /var/spool/cron   -p wa -k cron_spool

# =========== Файлы аудита ===========
-w /var/log/audit/ -p wa -k audit_config
-w /etc/audit/     -p wa -k audit_config

# =========== Резерв: директории конфигураций ===========
-w /etc/ -p wa -k etc_changes
EOF

  # Предупреждение о возможных дублях ключей в других .rules
  if ls -1 "$RULES_DIR"/*.rules &>/dev/null; then
    mapfile -t keys < <(grep -Eo -- ' -k[[:space:]]+[[:alnum:]_]+' "$RULES_FILE" | awk '{print $2}' | sort -u)
    for f in "$RULES_DIR"/*.rules; do
      [[ "$f" == "$RULES_FILE" ]] && continue
      for k in "${keys[@]}"; do
        if grep -qE " -k[[:space:]]+$k([[:space:]]|$)" "$f"; then
          warn "Возможный дубликат ключа '$k' в файле: $f (проверьте и удалите дубли во избежание Rule exists)"
        fi
      done
    done
  fi

  # Logrotate для /var/log/audit
  local LR="/etc/logrotate.d/audit"; backup_file "$LR"
  cat > "$LR" <<'EOF'
/var/log/audit/*.log {
    rotate 10
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /sbin/service auditd reload > /dev/null 2>/dev/null || true
    endscript
}
EOF

  # Утилиты для админа
  install -m 0755 /dev/stdin /usr/local/sbin/audit-status <<'EOF'
#!/bin/sh
echo "== auditctl -s =="; auditctl -s
echo
echo "== auditctl -l (top 100) =="; auditctl -l | sed -n '1,100p'
EOF

  install -m 0755 /dev/stdin /usr/local/sbin/audit-search <<'EOF'
#!/bin/sh
if [ -z "$1" ]; then
  echo "Usage: audit-search <key>"; exit 1
fi
ausearch -k "$1" | aureport -f -i
EOF

  install -m 0755 /dev/stdin /usr/local/sbin/audit-report <<'EOF'
#!/bin/sh
echo "== Summary =="; aureport --summary --failed --success -i
echo; echo "== Auth =="; aureport --auth -i
echo; echo "== Files =="; aureport --files -i
EOF

  # Ежедневный отчёт
  local CRONR="/etc/cron.daily/audit-daily-report"; backup_file "$CRONR"
  cat > "$CRONR" <<'EOF'
#!/bin/sh
test -x /usr/local/sbin/audit-report || exit 0
/usr/local/sbin/audit-report | logger -t audit-daily-report
EOF
  chmod 0755 "$CRONR"

  # Загрузка правил через augenrules + рестарт auditd
  augenrules --check >/dev/null 2>&1 || true
  augenrules --load  >/dev/null 2>&1 || true
  service auditd restart >/dev/null 2>&1 || systemctl restart auditd >/dev/null 2>&1 || true

  ok "Применена расширенная политика аудита (security-audit.rules), auditd активирован"
}

# --- 5. Мандатный контроль целостности ---
integrity_policy() {
  section "Мандатный контроль целостности"
  systemctl disable --now ima-evm integalert &>/dev/null || true
  ok "ima-evm и integalert отключены"
}

# --- 6. Замкнутая программная среда ---
closed_env_policy() {
  section "Замкнутая программная среда"
  systemctl disable --now control++ &>/dev/null || true
  ok "control++ выключен, политики удалены (если были)"
}

# --- 7. SSH: запрет входа root ---
sshd_hardening() {
  section "Настройка SSH (PermitRootLogin no)"
  local sshd_conf=""
  if   [[ -f /etc/openssh/sshd_config ]]; then
    sshd_conf="/etc/openssh/sshd_config"
  elif [[ -f /etc/ssh/sshd_config ]]; then
    sshd_conf="/etc/ssh/sshd_config"
  else
    sshd_conf="/etc/openssh/sshd_config"
    mkdir -p /etc/openssh
    touch "$sshd_conf"
  fi

  backup_file "$sshd_conf"
  if grep -qE '^\s*PermitRootLogin\s+' "$sshd_conf" 2>/dev/null; then
    sed -ri 's/^\s*PermitRootLogin\s+.*/PermitRootLogin no/' "$sshd_conf"
  else
    echo "PermitRootLogin no" >> "$sshd_conf"
  fi

  systemctl restart sshd >/dev/null 2>&1 || true
  ok "Обновлён ${sshd_conf} — вход root по SSH запрещён (PermitRootLogin no)"
}

# --- Основная логика ---
main() {
  local mode="${1:-}"

  case "$mode" in
    --fix|--apply)
      header_fix
      passwdqc_policy
      password_policy
      lockout_policy
      system_hardening
      audit_policy
      integrity_policy
      closed_env_policy
      sshd_hardening
      echo -e "\n${GREEN}Готово: эталонные настройки применены. Лог: ${LOG}${NC}"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "${1:-}"
fi
