# Authentication Service API

## 📌 Оглавление
1. [Архитектура проекта](#-архитектура-проекта)
2. [Запуск проекта](#-запуск-проекта)
3. [Документация API](#-документация-api)
4. [Функционал](#-функционал)


## Архитектура проекта


```
authentification_service/
├── config/            # Конфигурация приложения
├── docs/              # Swagger документация
├── handlers/          # HTTP обработчики
│   ├── auth.go        # Получение токенов
│   ├── refresh.go     # Обновление токенов
│   ├── me.go          # Получение данных пользователя
│   └── logout.go      # Выход из системы
├── models/            # Модели данных
├── storage/           # Работа с хранилищами
│   ├── database.go    # Подключение к PostgreSQL
│   └── tokens.go      # Работа с токенами
└── utils/             # Вспомогательные утилиты
    ├── jwt.go         # JWT операции
    └── webhook.go     # Webhook уведомления
```

## 🚀 Запуск проекта

### 1. Клонирование репозитория
```bash
https://github.com/Lalipop1/authentication_service.git
```

### 2. Запуск через Docker
```bash
docker-compose -f docker-compose.yml up -d
```

Должны быть запущены 2 сервиса:
- `auth-service` (порт 8080)
- `postgres` (порт 5432)

## 📚 Документация API

После запуска сервиса документация доступна по адресу:

🔗 [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

### Авторизация в Swagger:
1. Нажмите кнопку **Authorize**
2. Введите: `Bearer <ваш_access_token>`
3. Нажмите **Authorize**

## 💡 Функционал

### Основные возможности:
- Генерация JWT access/refresh токенов
- Обновление пары токенов
- Получение информации о текущем пользователе
- Выход из системы (инвалидация токенов)
- Webhook-уведомления о смене IP
