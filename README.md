# One-Time Secrets Service

Микросервис для безопасного хранения и одноразового доступа к конфиденциальным данным.

## 📌 О проекте

Сервис предоставляет API для:
- Создания секретов с ограниченным временем жизни (TTL)
- Получения секрета **только один раз**
- Удаления секретов до истечения TTL
- Логирования всех операций

## 🛠 Технологии

- **Python 3.9+**
- **FastAPI** (веб-фреймворк)
- **PostgreSQL** (хранение метаданных)
- **Redis** (кеширование секретов)
- **Docker** (контейнеризация)
- **Fernet** (шифрование данных)

## 🚀 Быстрый старт

### Требования
- Docker 20.10+
- Docker Compose 2.0+

### Запуск проекта

1. Склонируйте репозиторий:
   ```bash
   git clone https://github.com/yourusername/one-time-secrets.git
   cd one-time-secrets
   Создайте файл .env на основе примера:
   cp .env.example .env
 Отредактируйте .env, указав свои настройки.

Запустите сервисы:
 docker-compose up -d --build
Инициализируйте базу данных (выполнить один раз):
 docker-compose exec app python -c "from main import init_db; import asyncio; asyncio.run(init_db())"

Сервис будет доступен по адресу:
http://localhost:8000

## 📚 Документация API
### Доступна после запуска:

Swagger UI: /docs
ReDoc: /redoc

## 🌐 Примеры использования
### Создание секрета
 curl -X POST "http://localhost:8000/secret" \
 -H "Content-Type: application/json" \
 -d '{"secret": "мой супер секрет", "ttl_seconds": 3600}'
Ответ:
 {"secret_key": "уникальный_идентификатор"}

### Получение секрета
curl "http://localhost:8000/secret/уникальный_идентификатор"
Ответ (только при первом запросе):
{"secret": "мой супер секрет"}

### Удаление секрета
 curl -X DELETE "http://localhost:8000/secret/уникальный_идентификатор" \
 -H "Content-Type: application/json" \
 -d '{"passphrase": "пароль_если_нужен"}'
Ответ:
 {"status": "secret_deleted"}

## 🛠 Управление сервисом
 docker-compose up -d	Запуск сервисов
 docker-compose down	Остановка сервисов
 docker-compose logs -f	Просмотр логов
 docker-compose down -v	Полная очистка (включая данные)
## 📈 Мониторинг
Для проверки работы сервиса можно использовать:
 docker-compose ps

🤝 Как внести вклад
Форкните репозиторий
Создайте ветку для вашей фичи (git checkout -b feature/AmazingFeature)
Сделайте коммит изменений (git commit -m 'Add some AmazingFeature')
Запушьте в ветку (git push origin feature/AmazingFeature)
Откройте Pull Request

📜 Лицензия
Распространяется под лицензией MIT. См. файл LICENSE.
