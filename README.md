# Auth Service

## Команды Makefile

### 1. **Запуск приложения**
```bash
make run
```
Запускает сервис с использованием конфигурационного файла `config/config.yaml`.
Для этого необходимо предварительно поднять контейнер posgresql и поменять в config.yaml database.host на "localhost"

---

### 2. **Тестирование**
```bash
make test
```
Запускает тесты с использованием тестовой базы данных PostgreSQL, включающей следующие этапы:
- **start-test-db**: Поднимает контейнер с тестовой базой данных PostgreSQL.
- **run-tests**: Выполняет тесты из модулей `internal/storage/postgres` и `internal/handlers`.
- **stop-test-db**: Завершает работу тестовой базы данных и очищает все связанные ресурсы (сети, volume и т.д.).

---

### 3. **Сборка и запуск Docker-контейнеров**
```bash
make build
```
Собирает и запускает все контейнеры, описанные в `docker-compose.yaml`.
```