package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
)

// Хранилище для работы с PostgreSQL.
type PostgresStorage struct {
	pool *pgxpool.Pool
}

// Создаёт новый экземпляр PostgresStorage.
//
// Принимает:
// - pool: указатель на пул соединений с базой данных.
//
// Возвращает:
// - экземпляр PostgresStorage.
func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

// Cохраняет refresh-токен и IP клиента в базе данных.
//
// Принимает:
// - userID: идентификатор пользователя.
// - hashedToken: хешированный refresh-токен.
// - clientIP: IP-адрес клиента.
//
// Возвращает:
// - ошибку, если не удалось сохранить токен.
func (ps *PostgresStorage) SaveRefreshToken(userID, hashedToken, clientIP string) error {
	query := `
			INSERT INTO tokens (user_id, refresh_token_hash, ip_address, created_at, expires_at)
			VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '30 days')
			ON CONFLICT (user_id) DO UPDATE
			SET refresh_token_hash = $2, ip_address = $3, created_at = NOW(), expires_at = NOW() + INTERVAL '30 days';
	`
	_, err := ps.pool.Exec(context.Background(), query, userID, hashedToken, clientIP)
	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}
	return nil
}

// Возвращает refresh-токен пользователя из базы данных.
//
// Принимает:
// - userID: идентификатор пользователя.
//
// Возвращает:
// - строку (хешированный refresh-токен).
// - ошибку, если не удалось получить токен.
func (ps *PostgresStorage) GetRefreshToken(userID string) (string, error) {
	var hashedToken string
	query := `SELECT refresh_token_hash FROM tokens WHERE user_id = $1`
	err := ps.pool.QueryRow(context.Background(), query, userID).Scan(&hashedToken)
	if err != nil {
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}
	return hashedToken, nil
}

// Обновляет refresh-токен и IP клиента в базе данных.
//
// Принимает:
// - userID: идентификатор пользователя.
// - hashedToken: новый хешированный refresh-токен.
// - clientIP: новый IP-адрес клиента.
//
// Возвращает:
// - ошибку, если не удалось обновить токен.
func (ps *PostgresStorage) UpdateRefreshToken(userID, hashedToken, clientIP string) error {
	query := `
			UPDATE tokens
			SET refresh_token_hash = $2, ip_address = $3, created_at = NOW(), expires_at = NOW() + INTERVAL '30 days'
			WHERE user_id = $1;
	`
	_, err := ps.pool.Exec(context.Background(), query, userID, hashedToken, clientIP)
	if err != nil {
		return fmt.Errorf("failed to update refresh token: %w", err)
	}
	return nil
}

// Возвращает последний IP-адрес клиента для указанного пользователя.
//
// Принимает:
// - userID: идентификатор пользователя.
//
// Возвращает:
// - строку (IP-адрес клиента).
// - ошибку, если не удалось получить IP-адрес.
func (ps *PostgresStorage) GetLastIP(userID string) (string, error) {
	var clientIP string
	query := `SELECT ip_address FROM tokens WHERE user_id = $1`
	err := ps.pool.QueryRow(context.Background(), query, userID).Scan(&clientIP)
	if err != nil {
		return "", fmt.Errorf("failed to get last IP: %w", err)
	}
	return clientIP, nil
}

// Возвращает email пользователя из базы данных.
//
// Принимает:
// - userID: идентификатор пользователя.
//
// Возвращает:
// - строку (email пользователя).
// - ошибку, если email не удалось получить.
func (ps *PostgresStorage) GetUserEmail(userID string) (string, error) {
	var email string
	query := `SELECT email FROM users WHERE id = $1`
	err := ps.pool.QueryRow(context.Background(), query, userID).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("failed to get user email: %w", err)
	}
	return email, nil
}
