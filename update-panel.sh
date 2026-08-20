#!/usr/bin/env bash
# =========================================================================
# update-panel.sh — обновляет ТОЛЬКО код веб-панели (app.py, templates,
# scripts, init_db.py, requirements.txt, client.ovpn.tpl), НЕ трогая:
#   - сертификаты и PKI (/etc/openvpn/easy-rsa)
#   - конфиги OpenVPN (/etc/openvpn/server)
#   - данные панели: БД, настройки, журнал, админов (/opt/ovpn-panel/instance)
#
# Два способа запускать:
#   1) Из git-клона проекта (рекомендуется): скрипт сам сделает
#      `git pull --ff-only` перед обновлением, если каталог — git-репозиторий.
#         cd ~/ovpn-radius-panel && sudo ./update-panel.sh
#   2) Из распакованного архива (как раньше): скачали свежий zip,
#      распаковали в отдельную папку, запустили оттуда.
#
# Флаг --no-git-pull — обновиться от уже имеющегося локально кода, не делая
# git pull (например, если сами настроили нужный коммит/ветку вручную).
# =========================================================================
set -euo pipefail

NO_GIT_PULL=0
for arg in "$@"; do
  case "$arg" in
    --no-git-pull) NO_GIT_PULL=1 ;;
    *) echo "Неизвестный флаг: $arg" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DIR=/opt/ovpn-panel
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/opt/ovpn-panel-backups/${TS}"

if [[ $EUID -ne 0 ]]; then
  echo "Запускайте от root (sudo ./update-panel.sh)" >&2
  exit 1
fi

if [[ ! -d "$PANEL_DIR" ]]; then
  echo "Панель не установлена: нет каталога ${PANEL_DIR}." >&2
  echo "Для первичной установки используйте install.sh, а не этот скрипт." >&2
  exit 1
fi

if [[ "$NO_GIT_PULL" -ne 1 && -d "${SCRIPT_DIR}/.git" ]]; then
  echo "==> Обнаружен git-репозиторий в ${SCRIPT_DIR}, подтягиваю обновления"
  if ! git -C "$SCRIPT_DIR" pull --ff-only; then
    echo "" >&2
    echo "!!! git pull --ff-only не удался (см. вывод выше)." >&2
    echo "Возможно, в рабочей копии есть локальные правки или история" >&2
    echo "разошлась с origin. Разберитесь вручную (git status / git log)," >&2
    echo "либо запустите с флагом --no-git-pull, чтобы обновиться от уже" >&2
    echo "имеющегося локально кода." >&2
    exit 1
  fi
  echo "    текущий коммит: $(git -C "$SCRIPT_DIR" log -1 --format='%h %s')"
  echo ""
fi

if [[ ! -f "${SCRIPT_DIR}/panel/app.py" ]]; then
  echo "Не найден ${SCRIPT_DIR}/panel/app.py — запускайте скрипт из корня" >&2
  echo "распакованного НОВОГО архива проекта (там, где лежит папка panel/)." >&2
  exit 1
fi

echo "==> Обновление кода панели"
echo "    источник: ${SCRIPT_DIR}/panel"
echo "    цель:     ${PANEL_DIR}"
echo "    данные (instance/, venv/) НЕ трогаются."
echo ""

# -------------------------------------------------------------------------
# 1. Бэкап текущего кода (без venv — он большой и легко пересоздаётся,
#    и без instance — данные и так остаются на месте, но на всякий случай
#    их тоже копируем в бэкап отдельно).
# -------------------------------------------------------------------------
echo "==> Бэкап текущей версии в ${BACKUP_DIR}"
mkdir -p "$BACKUP_DIR"
# копируем код (всё кроме venv), instance попадёт сюда же как страховка
rsync -a --exclude venv "${PANEL_DIR}/" "${BACKUP_DIR}/" 2>/dev/null || {
  # если rsync не установлен — fallback на cp
  cp -a "${PANEL_DIR}/." "${BACKUP_DIR}/" 2>/dev/null || true
  rm -rf "${BACKUP_DIR}/venv" 2>/dev/null || true
}
echo "    готово."

# -------------------------------------------------------------------------
# 2. Обновляем код. Список того, что реально обновляется — фиксированный,
#    чтобы случайно не затащить в /opt/ovpn-panel что-то лишнее и, главное,
#    чтобы никогда не тронуть instance/.
# -------------------------------------------------------------------------
echo "==> Копирую новый код"

# app.py, init_db.py, requirements.txt, client.ovpn.tpl — файлы в корне panel/
for f in app.py init_db.py requirements.txt client.ovpn.tpl; do
  if [[ -f "${SCRIPT_DIR}/panel/${f}" ]]; then
    cp -f "${SCRIPT_DIR}/panel/${f}" "${PANEL_DIR}/${f}"
    echo "    обновлён ${f}"
  fi
done

# templates/ — полностью заменяем (это только HTML-шаблоны, не данные)
if [[ -d "${SCRIPT_DIR}/panel/templates" ]]; then
  rm -rf "${PANEL_DIR}/templates"
  cp -a "${SCRIPT_DIR}/panel/templates" "${PANEL_DIR}/templates"
  echo "    обновлён templates/"
fi

# static/ — если есть
if [[ -d "${SCRIPT_DIR}/panel/static" ]]; then
  rm -rf "${PANEL_DIR}/static"
  cp -a "${SCRIPT_DIR}/panel/static" "${PANEL_DIR}/static"
  echo "    обновлён static/"
fi

# scripts/ — привилегированные хелперы (issue/revoke/apply-*). Обновляем.
if [[ -d "${SCRIPT_DIR}/scripts" ]]; then
  mkdir -p "${PANEL_DIR}/scripts"
  cp -f "${SCRIPT_DIR}/scripts/"*.sh "${PANEL_DIR}/scripts/"
  chmod +x "${PANEL_DIR}/scripts/"*.sh
  echo "    обновлён scripts/"
fi

# -------------------------------------------------------------------------
# 3. Обновляем зависимости в venv (на случай если requirements.txt менялся).
#    venv не пересоздаём — просто до-устанавливаем/обновляем пакеты.
# -------------------------------------------------------------------------
if [[ -f "${PANEL_DIR}/venv/bin/pip" && -f "${PANEL_DIR}/requirements.txt" ]]; then
  echo "==> Обновляю зависимости Python (venv сохраняется)"
  "${PANEL_DIR}/venv/bin/pip" install -q --upgrade -r "${PANEL_DIR}/requirements.txt" || {
    echo "    ПРЕДУПРЕЖДЕНИЕ: не удалось обновить зависимости, продолжаю на старых." >&2
  }
fi

# -------------------------------------------------------------------------
# 4. Миграции БД. init_db.py написан идемпотентно (CREATE TABLE IF NOT
#    EXISTS + ALTER TABLE только если колонки нет), поэтому его безопасно
#    прогонять на существующей БД — он не тронет существующие данные,
#    только добавит недостающие таблицы/колонки, если код их ждёт.
# -------------------------------------------------------------------------
if [[ -f "${PANEL_DIR}/instance/settings.env" && -f "${PANEL_DIR}/venv/bin/python" ]]; then
  echo "==> Прогоняю миграции БД (существующие данные сохраняются)"
  # ВАЖНО: не делаем `source` всего settings.env — этот файл пишется как
  # systemd EnvironmentFile, где значение это весь остаток строки после "=",
  # и в старых установках некоторые значения (например список CIDR для
  # доступа к панели) могут быть БЕЗ кавычек и содержать пробелы. Bash при
  # `source` такой строки попытается выполнить второе "слово" как команду
  # и упадёт с "No such file or directory". Поэтому достаём точечно только
  # то единственное значение, которое реально нужно init_db.py при повторном
  # запуске — PANEL_DB (DEFAULT_* значения на существующей БД всё равно
  # игнорируются через INSERT OR IGNORE, они не нужны).
  PANEL_DB_VALUE="$(python3 - "${PANEL_DIR}/instance/settings.env" << 'PY'
import sys
path = sys.argv[1]
try:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("PANEL_DB="):
                val = line.split("=", 1)[1].strip()
                val = val.strip('"').strip("'")
                print(val)
                break
except OSError:
    pass
PY
)"
  if [[ -n "$PANEL_DB_VALUE" ]]; then
    PANEL_DB="$PANEL_DB_VALUE" "${PANEL_DIR}/venv/bin/python" "${PANEL_DIR}/init_db.py" || {
      echo "    ПРЕДУПРЕЖДЕНИЕ: init_db.py завершился с ошибкой, проверьте вручную." >&2
    }
  else
    echo "    ПРЕДУПРЕЖДЕНИЕ: не нашёл PANEL_DB в settings.env, миграции пропущены." >&2
  fi
fi

# -------------------------------------------------------------------------
# 5. Перезапуск службы панели.
# -------------------------------------------------------------------------
echo "==> Перезапускаю ovpn-panel"
systemctl restart ovpn-panel.service
sleep 1
if systemctl is-active --quiet ovpn-panel.service; then
  echo "    служба поднялась."
else
  echo ""
  echo "!!! ovpn-panel НЕ поднялась после обновления. Смотрите:" >&2
  echo "    journalctl -u ovpn-panel -n 50 --no-pager" >&2
  echo "    Откатиться на предыдущую версию можно так:" >&2
  echo "      sudo rm -rf ${PANEL_DIR}/templates ${PANEL_DIR}/scripts" >&2
  echo "      sudo cp -a ${BACKUP_DIR}/. ${PANEL_DIR}/" >&2
  echo "      sudo systemctl restart ovpn-panel" >&2
  exit 1
fi

echo ""
echo "======================================================================"
echo " Обновление завершено успешно."
echo " Бэкап предыдущей версии: ${BACKUP_DIR}"
echo " Сертификаты, конфиги OpenVPN и данные панели (админы, журнал,"
echo " настройки) остались нетронутыми."
echo "======================================================================"
