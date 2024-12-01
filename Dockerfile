# Используем официальный образ Golang для сборки и финального контейнера
FROM golang:1.23 AS builder

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файлы модулей и загружаем зависимости
COPY go.mod go.sum ./
RUN go mod download

# Копируем остальные исходные файлы
COPY . .

# Сборка приложения
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth_service ./cmd/auth_service

# Используем тот же образ Golang для финального контейнера
FROM alpine:latest

# Устанавливаем рабочую директорию
WORKDIR /root/

# Копируем бинарный файл и файл конфигурации из предыдущей стадии
COPY --from=builder /app/auth_service .
COPY --from=builder /app/config ./config

# Копируем файлы миграций
COPY --from=builder /app/internal/storage/migrations ./internal/storage/migrations

# Открываем порт
EXPOSE 8080

# Команда для запуска приложения
CMD ["./auth_service"]
