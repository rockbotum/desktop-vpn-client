# VPN - HuiPN

Я тут говна насрал, если в жопу стрельнет - подниму свой сервер в галактике Андромеда и будет у меня шифрование через червоточину, рукопожимать буду дата центрам у Гроксов

---

## Возможности

- Создание TUN-интерфейса (на Windows - через Wintun).
- Шифрование пакетов ChaCha20-Poly1305 (AEAD).
- Формат пакета: `[nonce][ciphertext]`.
- Две горутины транспорта: `Send` (tun → udp) и `Get` (udp → tun).
- Control plane `VPNService`: `Connect` / `Disconnect` / `GetStatus`.
- Десктопный UI с кнопками Connect / Disconnect и индикатором статуса.
- Graceful shutdown по `context.WithCancel` + `sync.WaitGroup`.

## Что НЕ реализовано

- Handshake и обмен ключами (ключ генерируется случайно и **не передаётся**).
- Настройка TUN (IP, MTU, up) — делается вручную))
- Маршрутизация (`default dev tun0`) — вручную.
- DNS через туннель.
- Replay protection на приёме (nonce-счётчик есть только на отправке).
- Kill switch, MTU discovery, ротация ключей, IPv6.
- VPN-сервер (только заготовка — см. раздел ниже).

---

## Архитектура

```
┌─────────────────────────────────────┐
│         Frontend (Wails)            │  HTML / CSS / TypeScript
├─────────────────────────────────────┤
│      VPNService (control plane)     │  Connect / Disconnect / GetStatus
├─────────────────────────────────────┤
│      Transport (data plane)         │  tun ↔ cryptor ↔ udp
└─────────────────────────────────────┘
```

**Правило зависимостей (строго):**

```
frontend → VPNService → Transport → cryptor / tun / udp
```

- Frontend **не знает** про `tun`, `cryptor`, `udp` — только `VPNService.*` через биндинги.
- `VPNService` **не знает** про UI.
- Transport **не знает** ни про UI, ни про статус.

## Структура проекта

```
SigmaVPN/
├── vpnsigma/                     # Wails-приложение
│   ├── main.go                   # Точка входа: application.New, регистрация сервиса
│   ├── greetservice.go           # Пример сервиса (не используется)
│   ├── Taskfile.yml              # Задачи сборки (wails3 task ...)
│   ├── build/                    # Ассеты сборки (иконки, манифесты, Taskfile по ОС)
│   └── frontend/                 # UI (vanilla TS + Vite)
│       ├── index.html
│       ├── src/main.ts           # Connect / Disconnect через биндинги
│       ├── bindings/             # Автогенерируемые Wails-биндинги (не редактировать)
│       └── vite.config.ts
├── internal/
│   ├── service/                  # VPNService (control plane)
│   │   └── vpnservice.go
│   ├── middleware/handler/       # Transport (data plane)
│   │   ├── handler-output-packages.go   # циклы Send / Get
│   │   └── framing.go                   # SendEncryptedPacket / ReceiveAndDecryptPacket
│   └── cryptor/                  # AEAD, nonce, счётчик
│       └── cryptor.go
├── pkg/                          # зарезервировано (пусто)
├── go.mod
├── AGENTS.md                     # Контекст для агентов/разработки
└── README.md
```

---

## Требования

- **Go** 1.27+ (см. `go.mod`).
- **Node.js** 18+ и npm (для frontend).
- **Wails CLI v3**:
  ```bash
  go install github.com/wailsapp/wails/v3/cmd/wails3@latest
  ```
- **Windows**: WebView2 Runtime (обычно уже есть на Win10/11) и `wintun.dll` (amd64).
- **Права администратора** для создания TUN на Windows.

## Сборка и запуск

Все команды выполняются из каталога приложения `vpnsigma/`.

```bash
# Dev-режим (горячая перезагрузка фронта)
wails3 dev

# Production-сборка → vpnsigma/bin/vpnsigma.exe
wails3 build
```

Сгенерировать биндинги вручную (после правки Go-сервисов):

```bash
cd vpnsigma
wails3 generate bindings -ts -i
```

### Windows: запуск

1. Положить `wintun.dll` (amd64) **рядом** с исполняемым файлом
   (`vpnsigma/bin/vpnsigma.exe`), иначе будет
   `Error loading wintun.dll ... The specified module could not be found`.
2. Запустить `vpnsigma.exe` **от имени администратора** — иначе создание TUN
   вернёт `Access is denied`.
3. IP, MTU и маршруты на TUN настраиваются вручную (в проекте не автоматизировано).

## Тесты

```bash
go test ./internal/...
```

Покрыты `cryptor` и `handler` (включая сквозной тест транспорта через реальные
UDP-сокеты на `127.0.0.1`). Внешний интернет не используется, админ-права не нужны.

Проверка кода:

```bash
go vet ./internal/... ./vpnsigma
```

> `go build ./...` намеренно **не** используется: каталоги `vpnsigma/build/ios`
> и `vpnsigma/build/android` — это build-ассеты Wails (инжектятся через overlay
> при мобильной сборке), они не компилируются как отдельные пакеты.

---

## Как это работает

1. UI вызывает `VPNService.Connect(serverAddress)`.
2. `Connect` создаёт TUN (`water`), криптор (`cryptor.New()`), UDP-соединение и
   запускает две горутины транспорта.
3. `Send`: читает пакет из TUN → шифрует → отправляет по UDP.
4. `Get`: читает пакет из UDP → расшифровывает → пишет в TUN.
5. `Disconnect` отменяет контекст, закрывает TUN и сокет, дожидается горутин.

**Формат пакета в сети:**

```
[ nonce (12 байт) ][ ciphertext (AEAD, +16 байт тега) ]
```

**Ключ:** `cryptor.New()` создаёт **случайный** 32-байтный ключ на сессию и
никуда его не передаёт. Для общения с сервером нужен общий ключ — см. ниже.

---

## Будущий сервер

Здесь описан минимальный путь, если захочется поднять собственный сервер.
Сейчас в репозитории **только клиент**, серверной логики нет.

### Что нужно на стороне сервера

1. **Тот же транспорт.** Сервер получает по UDP `[nonce][ciphertext]`,
   расшифровывает и пишет IP-пакеты в свой TUN; обратный путь — зеркально.
   Логику можно переиспользовать из `internal/middleware/handler`
   (`SendEncryptedPacket` / `ReceiveAndDecryptPacket`).
2. **Свой TUN** (`water.New`) на сервере.
3. **Общий ключ.** Самый простой вариант — договориться о ключе и создать
   криптор через `cryptor.NewWithKey(key)`.
4. **Маршрутизация/NAT** на сервере (например, `iptables` MASQUERADE) —
   чтобы трафик клиентов уходил в интернет.
5. На клиенте — маршрутизация трафика в TUN (`default dev tun0`) и DNS.

### Ключевые вещи, которых пока нет

- **Handshake / Key exchange.** В идеале — Diffie-Hellman (X25519) с выводом
  сессионного ключа. Сейчас ключ случайный и не согласуется, поэтому клиент и
  сервер не смогут общаться. Быстрый обходной путь — общий статический ключ
  через `cryptor.NewWithKey`.
- **Replay protection на приёме.** `NextNonce` увеличивает счётчик на отправке,
  но принимающая сторона не проверяет уникальность nonce — нужно окно
  принятых nonce.
- **`NewWithKey` существует и покрыт тестами, но в приложении не вызывается** —
  это готовая точка входа для общего ключа.

### Идея целевой схемы

ХЗ че тут мне клод тут порасписал, сначала сам ручками - фу-фу-фу, потом колдик объясни че я сделал
```
клиент TUN ─► cryptor ─► UDP ─► сеть ─► UDP ─► cryptor ─► сервер TUN ─► NAT ─► интернет
```

Протокол обмена, формат handshake и управление сессиями намеренно оставлены
на будущее — сначала нужно зафиксировать, как договариваться о ключе.

---
