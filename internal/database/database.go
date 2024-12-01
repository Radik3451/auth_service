package database

import (
	"context"
	"fmt"
	"log/slog"

	"auth_service/internal/config"

	"github.com/jackc/pgx/v4/pgxpool"
)

// Инициализирует подключение к PostgreSQL через пул соединений
func InitDB(cfg *config.Config, log *slog.Logger) (*pgxpool.Pool, error) {
	// Формируем строку подключения к базе данных
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DBName,
	)

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	pool, err := pgxpool.ConnectConfig(context.Background(), poolConfig)
	if err != nil {
		log.Error("Unable to connect to database", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Info("Successfully connected to database", slog.String("database", cfg.Database.DBName))
	return pool, nil
}
