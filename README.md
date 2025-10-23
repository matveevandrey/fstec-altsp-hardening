# Эталонная настройка ОС Альт Линукс СП (ФСТЭК) — README

Репозиторий содержит:
- `fix_altsp_reference.sh` — применяет настройки, приводящие систему к эталонному состоянию.
- `check_altsp_reference.sh` — проверяет соответствие эталону (здесь описывается только то, что настраивается).

> ⚠️ Изменения применяются **только** при запуске с ключом `--fix` или `--apply`.  
> Без указания этих ключей скрипт ничего не изменяет.

---

## 🧩 Таблица проверяемых параметров и способов приведения к эталону

### 1. Политика паролей

| Параметр | Файл / место проверки | Эталонное значение | Как настраивается скриптом | Проверка | Раздел скрипта |
|---|---|---|---|---|---|
| Качество паролей (passwdqc) | `/etc/passwdqc.conf` | `min=disabled,disabled,12,12,12`, `max=40`, `passphrase=3`, `match=4`, `similar=permit`, `enforce=everyone`, `retry=5` | Формируется стандартный файл с этими параметрами | `cat /etc/passwdqc.conf` | `passwdqc_policy()` |
| Сложность (pwquality) | `/etc/security/pwquality.conf` | `minlen=12`, `lcredit=1`, `ucredit=1`, `dcredit=1`, `ocredit=1` | Обновление/добавление строк в pwquality.conf | `grep -E "minlen|credit" /etc/security/pwquality.conf` | `password_policy()` |
| Срок действия пароля (глобально) | `/etc/login.defs` | `PASS_MAX_DAYS=90`, `PASS_MIN_DAYS=0`, `PASS_WARN_AGE=7` | Правка или добавление строк | `grep PASS /etc/login.defs` | `password_policy()` |
| Срок действия пароля (по пользователям) | chage | `m=0/M=90/W=7` | Для root и всех локальных пользователей выполняется `chage -m 0 -M 90 -W 7` | `chage -l root` | `password_policy()` |

---

### 2. Политика блокировки учётных записей (pam_faillock)

| Параметр | Файл / место проверки | Эталон | Как настраивается | Проверка | Раздел |
|---|---|---|---|---|---|
| Количество неудачных попыток | `/etc/security/faillock.conf` | `deny = 5` | Добавление или изменение значения | `grep deny /etc/security/faillock.conf` | `lockout_policy()` |
| Время блокировки | `/etc/security/faillock.conf` | `unlock_time = 900` | Аналогично | `grep unlock_time /etc/security/faillock.conf` | `lockout_policy()` |
| Блокировка root | `/etc/security/faillock.conf` | Отключена (`# even_deny_root`) | Добавляется закомментированная подсказка | `grep even_deny_root /etc/security/faillock.conf` | `lockout_policy()` |
| PAM-стек | `/etc/pam.d/system-auth-local-only` | Настроен с модулями `pam_faillock` и `pam_tcb` | Формируется новый стек аутентификации | `cat /etc/pam.d/system-auth-local-only` | `lockout_policy()` |
| Очистка блокировок | `/var/run/faillock/` | Все записи сброшены | `rm -f /var/run/faillock/*` и `faillock --reset` | `faillock` | `lockout_policy()` |

---

### 3. Системные параметры и гарантированное удаление

| Параметр | Файл / место | Эталон | Действие | Проверка | Раздел |
|---|---|---|---|---|---|
| Ограничение пространств имён | `/etc/sysctl.d/90-altsp-etalon.conf` | `user.max_user_namespaces = 0` | Добавление в sysctl.d | `sysctl user.max_user_namespaces` | `system_hardening()` |
| Сокрытие указателей ядра | `/etc/sysctl.d/90-altsp-etalon.conf` | `kernel.kptr_restrict = 2` | Аналогично | `sysctl kernel.kptr_restrict` | `system_hardening()` |
| Ограничение dmesg | `/etc/sysctl.d/90-altsp-etalon.conf` | `kernel.dmesg_restrict = 1` | Аналогично | `sysctl kernel.dmesg_restrict` | `system_hardening()` |
| Поведение подкачки | `/etc/sysctl.d/90-altsp-etalon.conf` | `vm.swappiness = 10` | Установка значения | `sysctl vm.swappiness` | `system_hardening()` |
| Средства гарантированного удаления | Пакет `secure_delete` | Установлен | Устанавливается при необходимости | `which srm` | `system_hardening()` |

> Примечание: пункт *«Очистка разделов подкачки — Отключено»* означает, что затирание свопа при завершении работы не требуется. Скрипт только ограничивает активное использование свопа (`vm.swappiness=10`).

---

### 4. Аудит (auditd и правила)

#### Конфигурация службы auditd

| Параметр | Место | Эталон | Проверка | Раздел |
|---|---|---|---|---|
| Служба auditd | systemd | Включена | `systemctl status auditd` | `audit_policy()` |
| Конфигурация auditd | `/etc/audit/auditd.conf` | Формат RAW, ротация, пороги заполнения | `cat /etc/audit/auditd.conf` | `audit_policy()` |
| Ротация логов | `/etc/logrotate.d/audit` | Еженедельная, 10 файлов, compress, reload | `cat /etc/logrotate.d/audit` | `audit_policy()` |
| Ежедневный отчёт | `/etc/cron.daily/audit-daily-report` | Присутствует | `ls -l /etc/cron.daily/audit-daily-report` | `audit_policy()` |
| Вспомогательные утилиты | `/usr/local/sbin/` | `audit-status`, `audit-search`, `audit-report` | `ls /usr/local/sbin/audit-*` | `audit_policy()` |

#### Правила `/etc/audit/rules.d/security-audit.rules`

| Группа | Что контролируется | Ключ (key) | Пример строки |
|---|---|---|---|
| Учётные базы | Изменения `/etc/passwd`, `/etc/shadow`, ... | `identity_database` | `-w /etc/passwd -p wa -k identity_database` |
| Конфигурация SSH | `/etc/ssh/*` и `/etc/openssh/*` | `ssh_config` | `-w /etc/openssh/sshd_config -p wa -k ssh_config` |
| Логи аутентификации | `/var/log/btmp`, `/var/log/wtmp`, `/var/log/secure` | `login_fail`, `login_success`, `security_logs` | `-w /var/log/btmp -p wa -k login_fail` |
| Запуск процессов | `execve` (x86_64 и i386) | `process_execution` | `-a always,exit -F arch=b64 -S execve -k process_execution` |
| Изменения прав и владельцев | chmod, chown, lchown, fchmod, fchown | `file_access` | `-a always,exit -F arch=b64 -S chmod,chown,lchown,fchmod,fchown -k file_access` |
| Повышение привилегий (syscalls) | setuid/setgid и аналоги | `privilege_escalation` | `-a always,exit -F arch=b64 -S setuid,setgid,... -k privilege_escalation` |
| Файлы sudo | `/etc/sudoers*` | `privilege_escalation` | `-w /etc/sudoers -p wa -k privilege_escalation` |
| Конфигурация ядра и сети | sysctl, hosts, resolv.conf | `kernel_config`, `network_config` | `-w /etc/sysctl.conf -p wa -k kernel_config` |
| Планировщик заданий | cron и пользовательские задания | `cron_config`, `cron_spool` | `-w /etc/crontab -p wa -k cron_config` |
| Конфигурация аудита | `/etc/audit/*`, `/var/log/audit/*` | `audit_config` | `-w /etc/audit/ -p wa -k audit_config` |
| Прочие изменения в /etc | Любые изменения конфигов | `etc_changes` | `-w /etc/ -p wa -k etc_changes` |

---

### 5. Контроль целостности и замкнутая среда

| Параметр | Место | Эталон | Действие | Проверка | Раздел |
|---|---|---|---|---|---|
| ima-evm / integalert | службы | Отключены | `systemctl disable --now ima-evm integalert` | `systemctl is-active ima-evm` | `integrity_policy()` |
| control++ | служба | Отключена | `systemctl disable --now control++` | `systemctl is-active control++` | `closed_env_policy()` |

---

### 6. SSH

| Параметр | Файл | Эталон | Действие | Проверка | Раздел |
|---|---|---|---|---|---|
| PermitRootLogin | `/etc/openssh/sshd_config` или `/etc/ssh/sshd_config` | `PermitRootLogin no` | Правка файла и рестарт службы | `sshd -T | grep permitrootlogin` | `sshd_hardening()` |

---

### 7. Применение и резервные копии

**Применение:**
```
./fix_altsp_reference.sh --fix
```

**Резервные копии:**
Все изменённые файлы сохраняются с суффиксом `.bak.<дата_время>` рядом с оригиналом.
