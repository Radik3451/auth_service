package postgres_test

import (
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
// - SaveRefreshToken
// - GetRefreshToken
// - UpdateRefreshToken
// - GetLastIP
func TestPostgresStorage(t *testing.T) {
	recreateTestDB()

	pool, cleanup := setupTestDB()
	defer cleanup()

	err := runMigrations(pool)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	storage := postgres.NewPostgresStorage(pool)

	userID := "123e4567-e89b-12d3-a456-426614174000"
	hashedToken := "hashed_refresh_token_example"
	clientIP := "127.0.0.1"

	createUserQuery := `
		INSERT INTO users (id, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())`

	_, err = pool.Exec(context.Background(), createUserQuery, userID, "test@example.com", "hashed_password")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Тест сохранения Refresh Token
	err = storage.SaveRefreshToken(userID, hashedToken, clientIP)
	assert.NoError(t, err)

	// Тест получения Refresh Token
	retrievedToken, err := storage.GetRefreshToken(userID)
	assert.NoError(t, err)
	assert.Equal(t, hashedToken, retrievedToken)

	// Тест обновления Refresh Token
	newHashedToken := "new_hashed_refresh_token_example"
	newClientIP := "192.168.1.1"
	err = storage.UpdateRefreshToken(userID, newHashedToken, newClientIP)
	assert.NoError(t, err)

	updatedToken, err := storage.GetRefreshToken(userID)
	assert.NoError(t, err)
	assert.Equal(t, newHashedToken, updatedToken)

	updatedIP, err := storage.GetLastIP(userID)
	assert.NoError(t, err)
	assert.Equal(t, newClientIP, updatedIP)
}
