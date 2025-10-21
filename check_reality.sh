#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Проверка аргументов
if [ -z "$1" ]; then
    echo -e "${RED}Ошибка: Укажите домен для проверки${NC}"
    echo "Использование: $0 example.com [опционально ip_вашего_vps]"
    exit 1
fi

DOMAIN=$1
VPS_IP=${2:-""}

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Проверка домена: ${YELLOW}$DOMAIN${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

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
    fi
    echo ""
}

# Проверка версии OpenSSL
echo -e "${BLUE}[0/8]${NC} Проверка версии OpenSSL..."
OPENSSL_VERSION=$(openssl version)
echo -e "    ${BLUE}→${NC} $OPENSSL_VERSION"
echo ""

# 1. Проверка доступности домена
echo -e "${BLUE}[1/8]${NC} Проверка доступности домена..."
if ping -c 2 -W 3 "$DOMAIN" &> /dev/null; then
    IP=$(dig +short "$DOMAIN" 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -n1)
    if [ -n "$IP" ]; then
        print_result "Доступность домена" "pass" "IP: $IP"
    else
        print_result "Доступность домена" "warn" "Домен доступен, но IP не получен"
    fi
else
    print_result "Доступность домена" "fail" "Домен недоступен"
fi

# 2. Проверка TLS 1.3
echo -e "${BLUE}[2/8]${NC} Проверка поддержки TLS 1.3..."

# Проверяем поддержку опции -tls1_3
if ! openssl s_client -help 2>&1 | grep -q "tls1_3"; then
    print_result "Поддержка TLS 1.3" "warn" "Ваш OpenSSL не поддерживает TLS 1.3 (нужна версия >= 1.1.1)"
else
    # Правильная проверка: ищем "CONNECTED" и отсутствие ошибок
    TLS13_OUTPUT=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -connect $DOMAIN:443 -tls1_3 2>&1")

    # Проверяем наличие успешного соединения
    if echo "$TLS13_OUTPUT" | grep -q "^CONNECTED"; then
        # Проверяем, что не было ошибок версии
        if echo "$TLS13_OUTPUT" | grep -qiE "wrong version|protocol version|handshake failure|no protocols available"; then
            print_result "Поддержка TLS 1.3" "fail" "TLS 1.3 НЕ поддерживается сервером"
        else
            # Дополнительно проверяем строку Protocol
            PROTO_LINE=$(echo "$TLS13_OUTPUT" | grep -i "Protocol" | head -n1)
            if echo "$PROTO_LINE" | grep -q "TLSv1.3"; then
                print_result "Поддержка TLS 1.3" "pass" "TLS 1.3 поддерживается ✓"
            else
                # Если соединение успешно и нет ошибок, значит скорее всего TLS 1.3 работает
                print_result "Поддержка TLS 1.3" "pass" "TLS 1.3 вероятно поддерживается (соединение установлено)"
            fi
        fi
    else
        print_result "Поддержка TLS 1.3" "fail" "Не удалось установить соединение"
    fi
fi

# 3. Проверка HTTP/2
echo -e "${BLUE}[3/8]${NC} Проверка поддержки HTTP/2..."
HTTP2_CHECK=$(timeout 10 curl -sI --http2 "https://$DOMAIN" 2>&1)
if echo "$HTTP2_CHECK" | grep -q "HTTP/2"; then
    print_result "Поддержка HTTP/2 (H2)" "pass" "HTTP/2 поддерживается"
else
    # Дополнительная проверка через openssl ALPN
    ALPN_CHECK=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -alpn h2 -connect $DOMAIN:443 2>&1" | grep -i "ALPN protocol:")
    if echo "$ALPN_CHECK" | grep -qi "h2"; then
        print_result "Поддержка HTTP/2 (H2)" "pass" "HTTP/2 поддерживается (ALPN: h2)"
    else
        print_result "Поддержка HTTP/2 (H2)" "fail" "HTTP/2 НЕ поддерживается"
    fi
fi

# 4. Проверка алгоритма обмена ключами X25519
echo -e "${BLUE}[4/8]${NC} Проверка алгоритма X25519..."
X25519_CHECK=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -connect $DOMAIN:443 2>&1")
if echo "$X25519_CHECK" | grep -iq "Server Temp Key.*X25519\|Temp Key.*x25519"; then
    print_result "Алгоритм X25519" "pass" "X25519 поддерживается"
else
    # Показываем какой алгоритм используется
    CURVE=$(echo "$X25519_CHECK" | grep -i "Server Temp Key:" | head -n1 | sed 's/^[[:space:]]*//')
    if [ -n "$CURVE" ]; then
        print_result "Алгоритм X25519" "warn" "X25519 не обнаружен. $CURVE"
    else
        print_result "Алгоритм X25519" "warn" "Не удалось определить алгоритм обмена ключами"
    fi
fi

# 5. Проверка редиректов
echo -e "${BLUE}[5/8]${NC} Проверка редиректов..."
REDIRECT_CHECK=$(timeout 10 curl -sI "https://$DOMAIN" 2>&1 | grep -i "^location:" | head -n1)
if [ -z "$REDIRECT_CHECK" ]; then
    print_result "Отсутствие редиректов" "pass" "Редиректы не обнаружены"
else
    # Проверяем, является ли редирект допустимым (на www или https)
    REDIRECT_URL=$(echo "$REDIRECT_CHECK" | cut -d' ' -f2- | tr -d '\r\n')
    if echo "$REDIRECT_URL" | grep -qE "^https?://(www\.)?$DOMAIN"; then
        print_result "Отсутствие редиректов" "warn" "Редирект на www/https (допустимо)"
    else
        print_result "Отсутствие редиректов" "fail" "Редирект на другой домен: $REDIRECT_URL"
    fi
fi

# 6. Проверка на CDN (Cloudflare, Fastly, Akamai и др.)
echo -e "${BLUE}[6/8]${NC} Проверка на наличие CDN..."
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
elif echo "$HEADERS" | grep -iq "x-cdn"; then
    CDN_DETECTED="Unknown CDN"
fi

if [ -z "$CDN_DETECTED" ]; then
    print_result "Отсутствие CDN" "pass" "CDN не обнаружен"
else
    print_result "Отсутствие CDN" "fail" "Обнаружен CDN: $CDN_DETECTED (не подходит для Reality)"
fi

# 7. Проверка OCSP Stapling
echo -e "${BLUE}[7/8]${NC} Проверка OCSP Stapling..."
OCSP_CHECK=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -connect $DOMAIN:443 -status 2>&1" | grep "OCSP Response Status:")
if echo "$OCSP_CHECK" | grep -q "successful"; then
    print_result "OCSP Stapling" "pass" "OCSP Stapling поддерживается (рекомендуется)"
else
    print_result "OCSP Stapling" "warn" "OCSP Stapling не обнаружен (не критично)"
fi

# 8. Проверка длины цепочки сертификатов
echo -e "${BLUE}[8/8]${NC} Проверка длины цепочки сертификатов..."
CERT_CHAIN=$(timeout 5 bash -c "(echo; sleep 1) | openssl s_client -showcerts -connect $DOMAIN:443 2>&1")
CERT_COUNT=$(echo "$CERT_CHAIN" | grep -c "BEGIN CERTIFICATE")
CERT_SIZE=$(echo "$CERT_CHAIN" | wc -c)

if [ "$CERT_SIZE" -ge 3500 ]; then
    print_result "Длина цепочки сертификатов" "pass" "Размер: $CERT_SIZE байт, Сертификатов: $CERT_COUNT"
else
    print_result "Длина цепочки сертификатов" "warn" "Размер: $CERT_SIZE байт (рекомендуется >3500 для пост-квантовой защиты)"
fi

# Дополнительная проверка с resolve на IP VPS (если указан)
if [ -n "$VPS_IP" ]; then
    echo -e "${BLUE}[Доп.]${NC} Проверка с resolve на IP VPS..."
    RESOLVE_CHECK=$(timeout 10 curl -v --resolve "$DOMAIN:443:$VPS_IP" "https://$DOMAIN" 2>&1)
    if echo "$RESOLVE_CHECK" | grep -qE "HTTP/[12]"; then
        print_result "Проверка с IP VPS" "pass" "Домен успешно резолвится на IP VPS"
    else
        print_result "Проверка с IP VPS" "fail" "Ошибка при резолве на IP VPS"
    fi
fi

# Итоговая статистика
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Результаты проверки:${NC}"
echo -e "  ${GREEN}Пройдено:${NC} $PASSED"
echo -e "  ${YELLOW}Предупреждения:${NC} $WARNING"
echo -e "  ${RED}Не пройдено:${NC} $FAILED"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Итоговое заключение
echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Домен $DOMAIN ПОДХОДИТ для использования с VLESS+Reality${NC}"
    exit 0
elif [ $FAILED -le 2 ]; then
    echo -e "${YELLOW}⚠ Домен $DOMAIN ЧАСТИЧНО подходит, но есть проблемы${NC}"
    echo -e "${YELLOW}  Рекомендуется найти другой домен или исправить проблемы${NC}"
    exit 1
else
    echo -e "${RED}✗ Домен $DOMAIN НЕ подходит для использования с VLESS+Reality${NC}"
    exit 2
fi
