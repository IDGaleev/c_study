#!/usr/bin/env bash
# install.sh — установка XML UI HTTP-сервера на Ubuntu
# Использование: sudo ./install.sh [ПОРТ]
# По умолчанию порт 8080.

set -euo pipefail

# ---------- Параметры ----------
INSTALL_DIR="/opt/idihttpd"
SERVICE_NAME="idhttpd"
PORT="${1:-8080}"
BINARY="${INSTALL_DIR}/${SERVICE_NAME}"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/${SERVICE_NAME}-install.log"

# ---------- Цвета ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; }

# ---------- Проверки ----------
if [[ $EUID -ne 0 ]]; then
    error "Запустите от root: sudo $0"
    exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    error "Некорректный порт: $PORT"
    exit 1
fi

if [[ ! -f "./main.cpp" ]]; then
    error "main.cpp не найден в текущем каталоге ($(pwd))."
    error "Положите скрипт рядом с main.cpp и запустите снова."
    exit 1
fi

info "Установка в ${INSTALL_DIR}, порт ${PORT}"
info "Лог установки: ${LOG_FILE}"

# Перенаправляем весь вывод в лог + на экран
exec > >(tee -a "$LOG_FILE") 2>&1

# ---------- 1. Зависимости ----------
info "Обновление списка пакетов..."
apt-get update -qq

info "Установка зависимостей (g++, boost, pugixml, openssl)..."
apt-get install -y -qq \
    g++ \
    libboost-all-dev \
    libpugixml-dev \
    libssl-dev \
    pkg-config \
    curl \
    xmllint 2>/dev/null || apt-get install -y -qq libxml2-utils

# ---------- 2. Каталог и файлы ----------
info "Создание ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

info "Копирование исходников..."
cp -f ./main.cpp "$INSTALL_DIR/main.cpp"

# interface.xml — создаём только если его нет
if [[ ! -f "${INSTALL_DIR}/interface.xml" ]]; then
    info "Создание демонстрационного interface.xml..."
    cat > "${INSTALL_DIR}/interface.xml" <<'XMLEOF'
<interface>
    <heading>Мой защищённый интерфейс</heading>
    <paragraph>Этот интерфейс сгенерирован из XML.</paragraph>
    <paragraph>Все данные экранируются, теги — из белого списка.</paragraph>
    <input name="username" type="text" />
    <input name="password" type="password" />
    <button id="btn1" label="Войти" />
    <button id="btn2" label="Отмена" />
</interface>
XMLEOF
else
    warn "interface.xml уже существует — оставляем как есть."
fi

# ---------- 3. Сборка ----------
info "Сборка бинарника..."
cd "$INSTALL_DIR"
g++ -std=c++17 -O2 -Wall -Wextra \
    main.cpp -o "$BINARY" \
    -lpugixml -lboost_system -lssl -lcrypto -pthread

if [[ ! -x "$BINARY" ]]; then
    error "Сборка не удалась: бинарник не создан."
    exit 1
fi
info "Бинарник собран: $BINARY"

# ---------- 4. Проверка XML ----------
if command -v xmllint >/dev/null 2>&1; then
    if ! xmllint --noout "${INSTALL_DIR}/interface.xml" 2>/dev/null; then
        warn "interface.xml содержит синтаксическую ошибку — сервер вернёт заглушку."
        warn "Исправьте файл: ${INSTALL_DIR}/interface.xml"
    fi
fi

# ---------- 5. systemd-юнит ----------
info "Создание systemd-юнита ${UNIT_FILE}..."
cat > "$UNIT_FILE" <<UNITEOF
[Unit]
Description=XML UI HTTP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BINARY} ${PORT}
Restart=on-failure
RestartSec=2
User=root
StandardOutput=journal
StandardError=journal

# Базовая изоляция
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
UNITEOF

info "Активация сервиса..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

# ---------- 6. Проверка ----------
info "Ожидание запуска..."
sleep 2

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    error "Сервис не запустился. Логи:"
    journalctl -u "$SERVICE_NAME" -n 50 --no-pager
    exit 1
fi

info "Проверка HTTP-ответа..."
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    info "Сервер отвечает 200 OK."
else
    warn "Сервер вернул код ${HTTP_CODE}. Проверьте: journalctl -u ${SERVICE_NAME} -f"
fi

# ---------- 7. Итог ----------
echo
info "=========================================="
info " Установка завершена"
info "=========================================="
info " Каталог:     ${INSTALL_DIR}"
info " Бинарник:    ${BINARY}"
info " XML:         ${INSTALL_DIR}/interface.xml"
info " Юнит:        ${UNIT_FILE}"
info " Порт:        ${PORT}"
info " Проверка:    curl http://127.0.0.1:${PORT}/"
info " Логи:        journalctl -u ${SERVICE_NAME} -f"
info " Перезапуск:  systemctl restart ${SERVICE_NAME}"
info " Остановка:   systemctl stop ${SERVICE_NAME}"
info " Удаление:    systemctl disable --now ${SERVICE_NAME} && rm -rf ${INSTALL_DIR} ${UNIT_FILE}"
info "=========================================="