# ChatGPT → Vercel → Telegram Relay

Небольшой приватный relay для отправки сообщений в личный Telegram через Telegram Bot API и Vercel Functions.

## Что улучшено

- секрет `RELAY_KEY` больше не хранится в URL, `localStorage` или `sessionStorage`;
- вход создаёт подписанную `HttpOnly + Secure + SameSite=Strict` cookie на 12 часов;
- `/api/send` и `/api/logout` принимают только `POST`;
- есть same-origin проверка, ограничение размера запросов и строгая валидация URL;
- добавлены security headers и CSP;
- интерфейс работает без перезагрузок, показывает статус и счётчик символов;
- можно приложить до трёх HTTPS-кнопок;
- `/api/health` показывает готовность конфигурации и состояние авторизации без раскрытия секретов;
- тесты не отправляют реальные сообщения в Telegram.

## Environment Variables

В Vercel Project Settings → Environment Variables добавьте как Sensitive:

- `TELEGRAM_BOT_TOKEN` — токен Telegram-бота;
- `TELEGRAM_CHAT_ID` — ID чата, куда отправляются сообщения;
- `RELAY_KEY` — длинный случайный секрет для входа.

Ни один реальный секрет не должен попадать в Git.

## Локальная разработка

```bash
cp .env.example .env
vercel dev
```

## Тесты

```bash
go test ./...
```

Тестовый HTTP-сервер подменяет Telegram Bot API, поэтому запуск тестов безопасен и не создаёт сообщений в реальном чате.
