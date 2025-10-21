#!/bin/bash


# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Проверка аргументов
if [ -z "$1" ]; then
    echo -e "${RED}Ошибка: Укажите домен для проверки${NC}"
    echo "Использование: $0 example.com [ip_вашего_vps]"
    echo ""
    echo "Параметры:"
    echo "  example.com     - Домен для проверки (обязательный)"
    echo "  ip_вашего_vps   - IP вашего VPS (опциональный)"
    echo ""
    echo "Примеры:"
    echo "  $0 google.com"
    echo "  $0 google.com 45.67.89.10"
    exit 1
fi

DOMAIN=$1
VPS_IP=${2:-""}

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Проверка домена: ${YELLOW}$DOMAIN${NC}"
if [ -n "$VPS_IP" ]; then
    echo -e "${BLUE}IP VPS: ${YELLOW}$VPS_IP${NC}"
fi
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# Переменные для метрик задержки
PING_TIME=""
TCP_TIME=""
TLS_TIME=""
TOTAL_TIME=""

# Счётчики
PASSED=0
FAILED=0
WARNING=0

# Функция для вывода результата
print_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"

    if [ "$status" = "pass" ]; then
        echo -e "[${GREEN}✓${NC}] $test_name"
        [ -n "$message" ] && echo -e "    ${GREEN}→${NC} $message"
        ((PASSED++))
    elif [ "$status" = "fail" ]; then
        echo -e "[${RED}✗${NC}] $test_name"
        [ -n "$message" ] && echo -e "    ${RED}→${NC} $message"
        ((FAILED++))
    elif [ "$status" = "warn" ]; then
        echo -e "[${YELLOW}⚠${NC}] $test_name"
        [ -n "$message" ] && echo -e "    ${YELLOW}→${NC} $message"
        ((WARNING++))
    elif [ "$status" = "info" ]; then
        echo -e "[${CYAN}ℹ${NC}] $test_name"
        [ -n "$message" ] && echo -e "    ${CYAN}→${NC} $message"
    fi
    echo ""
}

# Проверка версии OpenSSL
echo -e "${BLUE}[0/9]${NC} Проверка версии OpenSSL..."
OPENSSL_VERSION=$(openssl version)
echo -e "    ${BLUE}→${NC} $OPENSSL_VERSION"
echo ""

# 1. Проверка доступности домена + PING LATENCY
echo -e "${BLUE}[1/9]${NC} Проверка доступности домена и ICMP задержки..."
PING_OUTPUT=$(ping -c 4 -W 3 "$DOMAIN" 2>&1)
if echo "$PING_OUTPUT" | grep -q "bytes from"; then
    IP=$(dig +short "$DOMAIN" 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -n1)

    # Извлекаем среднюю задержку ping
    if echo "$PING_OUTPUT" | grep -q "avg"; then
        # Linux format: rtt min/avg/max/mdev = 10.1/15.3/20.5/3.2 ms
        PING_TIME=$(echo "$PING_OUTPUT" | grep -oP "min/avg/max[^=]*= [^/]*/\K[0-9.]+" | head -n1)
        [ -z "$PING_TIME" ] && PING_TIME=$(echo "$PING_OUTPUT" | grep -oP "avg = \K[0-9.]+")
        [ -z "$PING_TIME" ] && PING_TIME=$(echo "$PING_OUTPUT" | grep -oP "Average = \K[0-9.]+")
    fi

    if [ -n "$PING_TIME" ]; then
        print_result "Доступность + ICMP Ping" "pass" "IP: $IP, Ping: ${PING_TIME}ms"
    else
        print_result "Доступность" "pass" "IP: $IP"
    fi
else
    print_result "Доступность домена" "fail" "Домен недоступен"
fi

# 2. Проверка TLS 1.3
echo -e "${BLUE}[2/9]${NC} Проверка поддержки TLS 1.3..."

if ! openssl s_client -help 2>&1 | grep -q "tls1_3"; then
    print_result "Поддержка TLS 1.3" "warn" "Ваш OpenSSL не поддерживает TLS 1.3 (нужна версия >= 1.1.1)"
else
    TLS13_OUTPUT=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -connect $DOMAIN:443 -tls1_3 2>&1")

    if echo "$TLS13_OUTPUT" | grep -q "^CONNECTED"; then
        if echo "$TLS13_OUTPUT" | grep -qiE "wrong version|protocol version|handshake failure|no protocols available"; then
            print_result "Поддержка TLS 1.3" "fail" "TLS 1.3 НЕ поддерживается сервером"
        else
            PROTO_LINE=$(echo "$TLS13_OUTPUT" | grep -i "Protocol" | head -n1)
            if echo "$PROTO_LINE" | grep -q "TLSv1.3"; then
                print_result "Поддержка TLS 1.3" "pass" "TLS 1.3 поддерживается ✓"
            else
                print_result "Поддержка TLS 1.3" "pass" "TLS 1.3 вероятно поддерживается"
            fi
        fi
    else
        print_result "Поддержка TLS 1.3" "fail" "Не удалось установить соединение"
    fi
fi

# 3. Проверка HTTP/2
echo -e "${BLUE}[3/9]${NC} Проверка поддержки HTTP/2..."
HTTP2_CHECK=$(timeout 10 curl -sI --http2 "https://$DOMAIN" 2>&1)
if echo "$HTTP2_CHECK" | grep -q "HTTP/2"; then
    print_result "Поддержка HTTP/2 (H2)" "pass" "HTTP/2 поддерживается"
else
    ALPN_CHECK=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -alpn h2 -connect $DOMAIN:443 2>&1" | grep -i "ALPN protocol:")
    if echo "$ALPN_CHECK" | grep -qi "h2"; then
        print_result "Поддержка HTTP/2 (H2)" "pass" "HTTP/2 поддерживается (ALPN)"
    else
        print_result "Поддержка HTTP/2 (H2)" "fail" "HTTP/2 НЕ поддерживается"
    fi
fi

# 4. Измерение задержки через curl (TCP + TLS + HTTP)
echo -e "${BLUE}[4/9]${NC} Измерение задержки соединения (TCP/TLS/HTTP)..."
CURL_TIMING=$(timeout 10 curl -o /dev/null -s -w "dns:%{time_namelookup}|tcp:%{time_connect}|tls:%{time_appconnect}|total:%{time_total}" "https://$DOMAIN" 2>&1)

if [ $? -eq 0 ]; then
    DNS_TIME=$(echo "$CURL_TIMING" | grep -oP "dns:\K[0-9.]+")
    TCP_TIME=$(echo "$CURL_TIMING" | grep -oP "tcp:\K[0-9.]+")
    TLS_TIME=$(echo "$CURL_TIMING" | grep -oP "tls:\K[0-9.]+")
    TOTAL_TIME=$(echo "$CURL_TIMING" | grep -oP "total:\K[0-9.]+")

    # Вычисляем чистое время TLS handshake (TLS - TCP)
    TLS_HANDSHAKE_ONLY=$(echo "$TLS_TIME $TCP_TIME" | awk '{printf "%.3f", ($1 - $2) * 1000}')
    TCP_MS=$(echo "$TCP_TIME" | awk '{printf "%.0f", $1 * 1000}')
    TLS_MS=$(echo "$TLS_TIME" | awk '{printf "%.0f", $1 * 1000}')
    TOTAL_MS=$(echo "$TOTAL_TIME" | awk '{printf "%.0f", $1 * 1000}')

    print_result "Задержка соединения" "pass" "DNS: ${DNS_TIME}s, TCP: ${TCP_MS}ms, TLS: ${TLS_MS}ms (handshake: ${TLS_HANDSHAKE_ONLY}ms), Total: ${TOTAL_MS}ms"
else
    print_result "Задержка соединения" "warn" "Не удалось измерить задержку"
fi

# 5. Проверка алгоритма X25519
echo -e "${BLUE}[5/9]${NC} Проверка алгоритма X25519..."
X25519_CHECK=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -connect $DOMAIN:443 2>&1")
if echo "$X25519_CHECK" | grep -iq "Server Temp Key.*X25519\|Temp Key.*x25519"; then
    print_result "Алгоритм X25519" "pass" "X25519 поддерживается"
else
    CURVE=$(echo "$X25519_CHECK" | grep -i "Server Temp Key:" | head -n1 | sed 's/^[[:space:]]*//')
    if [ -n "$CURVE" ]; then
        print_result "Алгоритм X25519" "warn" "X25519 не обнаружен. $CURVE"
    else
        print_result "Алгоритм X25519" "warn" "Не удалось определить алгоритм"
    fi
fi

# 6. Проверка редиректов
echo -e "${BLUE}[6/9]${NC} Проверка редиректов..."
REDIRECT_CHECK=$(timeout 10 curl -sI "https://$DOMAIN" 2>&1 | grep -i "^location:" | head -n1)
if [ -z "$REDIRECT_CHECK" ]; then
    print_result "Отсутствие редиректов" "pass" "Редиректы не обнаружены"
else
    REDIRECT_URL=$(echo "$REDIRECT_CHECK" | cut -d' ' -f2- | tr -d '\r\n')
    if echo "$REDIRECT_URL" | grep -qE "^https?://(www\.)?$DOMAIN"; then
        print_result "Отсутствие редиректов" "warn" "Редирект на www/https (допустимо)"
    else
        print_result "Отсутствие редиректов" "fail" "Редирект на другой домен"
    fi
fi

# 7. Проверка на CDN
echo -e "${BLUE}[7/9]${NC} Проверка на наличие CDN..."
HEADERS=$(timeout 10 curl -sI "https://$DOMAIN" 2>&1)
CDN_DETECTED=""

if echo "$HEADERS" | grep -iqE "cloudflare|cf-ray|cf-cache"; then
    CDN_DETECTED="Cloudflare"
elif echo "$HEADERS" | grep -iq "x-amz-cf-id"; then
    CDN_DETECTED="Amazon CloudFront"
elif echo "$HEADERS" | grep -iq "fastly"; then
    CDN_DETECTED="Fastly"
elif echo "$HEADERS" | grep -iqE "x-akamai|akamai"; then
    CDN_DETECTED="Akamai"
fi

if [ -z "$CDN_DETECTED" ]; then
    print_result "Отсутствие CDN" "pass" "CDN не обнаружен"
else
    print_result "Отсутствие CDN" "fail" "CDN: $CDN_DETECTED"
fi

# 8. Проверка OCSP Stapling
echo -e "${BLUE}[8/9]${NC} Проверка OCSP Stapling..."
OCSP_CHECK=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -connect $DOMAIN:443 -status 2>&1" | grep "OCSP Response Status:")
if echo "$OCSP_CHECK" | grep -q "successful"; then
    print_result "OCSP Stapling" "pass" "Поддерживается"
else
    print_result "OCSP Stapling" "warn" "Не обнаружен (не критично)"
fi

# 9. Проверка длины цепочки сертификатов
echo -e "${BLUE}[9/9]${NC} Проверка цепочки сертификатов..."
CERT_CHAIN=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -showcerts -connect $DOMAIN:443 2>&1")
CERT_COUNT=$(echo "$CERT_CHAIN" | grep -c "BEGIN CERTIFICATE")
CERT_SIZE=$(echo "$CERT_CHAIN" | wc -c)

if [ "$CERT_SIZE" -ge 3500 ]; then
    print_result "Цепочка сертификатов" "pass" "Размер: $CERT_SIZE байт"
else
    print_result "Цепочка сертификатов" "warn" "Размер: $CERT_SIZE байт (рек. >3500)"
fi

# Дополнительная проверка с IP VPS
if [ -n "$VPS_IP" ]; then
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}ПРОВЕРКА С IP VPS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}[Доп.]${NC} Проверка с resolve на IP VPS..."

    if ! ping -c 1 -W 2 "$VPS_IP" &> /dev/null; then
        print_result "Доступность VPS" "fail" "IP $VPS_IP недоступен"
    else
        if ! timeout 3 bash -c "echo > /dev/tcp/$VPS_IP/443" 2>/dev/null; then
            print_result "Порт 443 на VPS" "info" "Порт закрыт (нормально до настройки Reality)"
        else
            RESOLVE_OUTPUT=$(timeout 10 curl -v --resolve "$DOMAIN:443:$VPS_IP" "https://$DOMAIN" 2>&1)
            if echo "$RESOLVE_OUTPUT" | grep -qE "SSL certificate problem|certificate verify failed"; then
                print_result "Resolve на VPS" "warn" "Ошибка сертификата (нормально до настройки Reality)"
            elif echo "$RESOLVE_OUTPUT" | grep -qE "HTTP/[12]"; then
                print_result "Resolve на VPS" "pass" "Работает!"
            else
                print_result "Resolve на VPS" "info" "Проверьте после настройки Reality"
            fi
        fi
    fi
fi

# Итоговая сводка по задержкам
echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}СВОДКА ПО ЗАДЕРЖКАМ${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════${NC}"
echo ""

if [ -n "$PING_TIME" ] || [ -n "$TCP_TIME" ]; then
    echo -e "${YELLOW}Метрики производительности:${NC}"
    [ -n "$PING_TIME" ] && echo -e "  🔸 ICMP Ping:         ${GREEN}${PING_TIME} ms${NC}"
    [ -n "$TCP_TIME" ] && echo -e "  🔸 TCP Connection:    ${GREEN}$(echo $TCP_TIME | awk '{printf "%.0f", $1*1000}') ms${NC}"
    [ -n "$TLS_TIME" ] && echo -e "  🔸 TLS Handshake:     ${GREEN}${TLS_HANDSHAKE_ONLY} ms${NC}"
    [ -n "$TOTAL_TIME" ] && echo -e "  🔸 Total Time:        ${GREEN}$(echo $TOTAL_TIME | awk '{printf "%.0f", $1*1000}') ms${NC}"
    echo ""

    # Оценка скорости
    if [ -n "$PING_TIME" ]; then
        PING_NUM=$(echo "$PING_TIME" | awk '{print int($1)}')
        if [ "$PING_NUM" -lt 50 ]; then
            echo -e "  ${GREEN}✓ ОТЛИЧНО${NC} - Очень низкая задержка (<50ms)"
        elif [ "$PING_NUM" -lt 100 ]; then
            echo -e "  ${GREEN}✓ ХОРОШО${NC} - Низкая задержка (50-100ms)"
        elif [ "$PING_NUM" -lt 200 ]; then
            echo -e "  ${YELLOW}⚠ НОРМАЛЬНО${NC} - Средняя задержка (100-200ms)"
        else
            echo -e "  ${YELLOW}⚠ ВЫСОКАЯ ЗАДЕРЖКА${NC} - >200ms (ищите домен ближе)"
        fi
    fi
else
    echo -e "${YELLOW}Не удалось измерить задержку${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}РЕЗУЛЬТАТЫ ПРОВЕРКИ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Пройдено:${NC} $PASSED"
echo -e "  ${YELLOW}Предупреждения:${NC} $WARNING"
echo -e "  ${RED}Не пройдено:${NC} $FAILED"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Итоговое заключение
echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Домен $DOMAIN ПОДХОДИТ для VLESS+Reality${NC}"
    [ -n "$PING_TIME" ] && echo -e "${GREEN}  Задержка: ${PING_TIME}ms${NC}"
    exit 0
elif [ $FAILED -le 2 ]; then
    echo -e "${YELLOW}⚠ Домен $DOMAIN частично подходит${NC}"
    exit 1
else
    echo -e "${RED}✗ Домен $DOMAIN НЕ подходит${NC}"
    exit 2
fi
