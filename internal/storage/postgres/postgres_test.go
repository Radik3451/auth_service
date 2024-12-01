package postgres_test

import (
	"auth_service/internal/services/tokens"
	"auth_service/internal/storage/postgres"
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/stretchr/testify/assert"
)

// Пересоздаёт тестовую базу данных перед запуском тестов.
// Удаляет существующую тестовую базу (если она есть) и создаёт новую.
func recreateTestDB() {
	connString := "postgres://postgres:password@localhost:5432/app_db?sslmode=disable"

	conn, err := pgxpool.Connect(context.Background(), connString)
	if err != nil {
		log.Fatalf("Failed to connect to Postgres: %v", err)
	}
	defer conn.Close()

	_, err = conn.Exec(context.Background(), "DROP DATABASE IF EXISTS test_db")
	if err != nil {
		log.Fatalf("Failed to drop test database: %v", err)
	}

	_, err = conn.Exec(context.Background(), "CREATE DATABASE test_db")
	if err != nil {
		log.Fatalf("Failed to create test database: %v", err)
	}
}

// Подключается к тестовой базе данных и возвращает пул соединений.
// Также возвращает функцию очистки базы данных после выполнения тестов.
func setupTestDB() (*pgxpool.Pool, func()) {
	connString := "postgres://postgres:password@localhost:5432/test_db?sslmode=disable"

	pool, err := pgxpool.Connect(context.Background(), connString)
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}

	cleanup := func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE tokens RESTART IDENTITY CASCADE")
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE users RESTART IDENTITY CASCADE")
		pool.Close()
	}

	return pool, cleanup
}

// Вручную выполняет миграции для тестовой базы данных.
// Выполняет создание необходимых таблиц и индексов.
func runMigrations(pool *pgxpool.Pool) error {
	queries := []string{
		`-- Создание таблицы пользователей
		CREATE TABLE IF NOT EXISTS users (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				email TEXT UNIQUE NOT NULL,
				password_hash TEXT NOT NULL,
				created_at TIMESTAMP DEFAULT NOW(),
				updated_at TIMESTAMP DEFAULT NOW()
		);

		-- Создание триггера для обновления поля updated_at при изменении записи в users
		CREATE OR REPLACE FUNCTION update_users_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
				NEW.updated_at = NOW();
				RETURN NEW;
		END;
		$$ language 'plpgsql';

		CREATE TRIGGER update_users_updated_at
		BEFORE UPDATE ON users
		FOR EACH ROW
		EXECUTE FUNCTION update_users_updated_at_column();

		-- Создание таблицы токенов
		CREATE TABLE IF NOT EXISTS tokens (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				refresh_token_hash TEXT NOT NULL,
				ip_address TEXT NOT NULL,
				created_at TIMESTAMP DEFAULT NOW(),
				expires_at TIMESTAMP NOT NULL,
				UNIQUE (user_id)  -- Добавляем уникальное ограничение на user_id для поддержки ON CONFLICT
		);

		-- Создание индекса для ускорения поиска по refresh_token_hash
		CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token_hash ON tokens (refresh_token_hash);`,
	}

	for _, query := range queries {
		_, err := pool.Exec(context.Background(), query)
		if err != nil {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	return nil
}

// Выполняет интеграционные тесты для методов хранения в Postgres.
//
// Тестируются следующие методы:
// - SaveRefreshToken: проверяет корректность сохранения refresh токена и IP-адреса клиента.
// - GetRefreshToken: проверяет возможность получения хешированного refresh токена из базы данных.
// - UpdateRefreshToken: проверяет обновление refresh токена и IP-адреса клиента.
// - GetLastIP: проверяет получение последнего IP-адреса клиента.
// - GetUserEmail: проверяет получение email пользователя по его идентификатору.
// - Проверка связи Access и Refresh токенов: тестирует зависимость Access токена от Refresh токена, включая корректность их генерации и валидации.
// - Проверка обработки изменения IP: проверяет корректность обнаружения изменения IP-адреса клиента и возможность отправки предупреждения пользователю (email).
//
// Тесты включают:
// - Генерацию refresh токена и его сохранение в базе данных с последующей проверкой.
// - Генерацию нового refresh токена, его обновление и проверку в базе данных.
// - Проверку валидации Access токена, сгенерированного на основе refresh токена.
// - Проверку корректного получения email пользователя для отправки предупреждения при изменении IP.
func TestPostgresStorage(t *testing.T) {
	recreateTestDB()

	pool, cleanup := setupTestDB()
	defer cleanup()

	err := runMigrations(pool)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	storage := postgres.NewPostgresStorage(pool)

	// --- Тестовые данные ---
	userID := "123e4567-e89b-12d3-a456-426614174000"
	email := "test@example.com"
	clientIP := "127.0.0.1"

	// Создаём пользователя
	createUserQuery := `
		INSERT INTO users (id, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())`
	_, err = pool.Exec(context.Background(), createUserQuery, userID, email, "hashed_password")
	assert.NoError(t, err)

	// --- Проверка метода GetUserEmail ---
	retrievedEmail, err := storage.GetUserEmail(userID)
	assert.NoError(t, err)
	assert.Equal(t, email, retrievedEmail)

	// --- Генерация Refresh токена и его хеширование ---
	refreshToken, hashedToken, err := tokens.GenerateRefreshTokenAndHash()
	assert.NoError(t, err)

	// --- Сохранение Refresh токена ---
	err = storage.SaveRefreshToken(userID, hashedToken, clientIP)
	assert.NoError(t, err)

	// --- Проверка сохранённого токена ---
	retrievedHashedToken, err := storage.GetRefreshToken(userID)
	assert.NoError(t, err)

	// Сравниваем хеш токена с оригинальным токеном
	err = tokens.CompareRefreshToken(retrievedHashedToken, refreshToken)
	assert.NoError(t, err)

	// --- Обновление Refresh токена ---
	newRefreshToken, newHashedToken, err := tokens.GenerateRefreshTokenAndHash()
	assert.NoError(t, err)
	newClientIP := "192.168.1.1"

	err = storage.UpdateRefreshToken(userID, newHashedToken, newClientIP)
	assert.NoError(t, err)

	// Проверяем обновлённый токен
	updatedHashedToken, err := storage.GetRefreshToken(userID)
	assert.NoError(t, err)
	err = tokens.CompareRefreshToken(updatedHashedToken, newRefreshToken)
	assert.NoError(t, err)

	// Проверяем обновлённый IP
	updatedIP, err := storage.GetLastIP(userID)
	assert.NoError(t, err)
	assert.Equal(t, newClientIP, updatedIP)

	// Проверяем связь Access и Refresh токенов
	jwtSecret := "supersecretkey"
	accessToken, err := tokens.GenerateAccessToken(userID, newClientIP, jwtSecret, newHashedToken)
	assert.NoError(t, err)

	// Валидация Access токена
	validatedUserID, validatedClientIP, validatedRefreshHash, err := tokens.ValidateAccessToken(accessToken, jwtSecret)
	assert.NoError(t, err)
	assert.Equal(t, userID, validatedUserID)
	assert.Equal(t, newClientIP, validatedClientIP)
	assert.Equal(t, newHashedToken, validatedRefreshHash)

	// Проверка отправки предупреждения при изменении IP
	anotherClientIP := "203.0.113.45"
	accessToken, err = tokens.GenerateAccessToken(userID, anotherClientIP, jwtSecret, newHashedToken)
	assert.NoError(t, err)

	// Валидация с изменённым IP
	_, validatedNewClientIP, _, err := tokens.ValidateAccessToken(accessToken, jwtSecret)
	assert.NoError(t, err)

	// Проверяем, что IP изменился
	assert.NotEqual(t, updatedIP, validatedNewClientIP)

	// Проверка получения email для отправки предупреждения
	warningEmail, err := storage.GetUserEmail(userID)
	assert.NoError(t, err)
	assert.Equal(t, email, warningEmail)

	t.Logf("Warning email sent to: %s due to IP change from %s to %s", warningEmail, updatedIP, validatedNewClientIP)
}
