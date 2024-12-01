package migrations

import (
	"auth_service/internal/config"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Примененяет миграций бд.
//
// Принимает:
//   - databaseURL: строка с URL для подключения к базе данных в формате
//     postgres://user:password@host:port/dbname?sslmode=disable.
//   - migrationsPath: путь к файлам миграций (например, file://path/to/migrations).
//   - log: указатель на logger для логирования событий.
func ApplyMigrations(databaseURL string, migrationsPath string, log *slog.Logger) {
	m, err := migrate.New(migrationsPath, databaseURL)
	if err != nil {
		log.Error("Failed to initialize migrations", slog.String("error", err.Error()))
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Error("Failed to apply migrations", slog.String("error", err.Error()))
	}

	log.Info("Migrations applied successfully")
}

// Иинициализирует параметры подключения и вызовает ApplyMigrations.
//
// Принимает:
// - cfg: указатель на структуру конфигурации приложения (config.Config).
// - log: указатель на logger для логирования событий.
// Формирует URL подключения к базе данных на основе конфигурации и вызывает ApplyMigrations.
func InitAndRunMigrations(cfg *config.Config, log *slog.Logger) {
	migrationsPath := "file://internal/storage/migrations/"
	databaseURL := "postgres://%s:%s@%s:%d/%s?sslmode=disable"

	fullDatabaseURL := fmt.Sprintf(databaseURL,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DBName,
	)

	ApplyMigrations(fullDatabaseURL, migrationsPath, log)
	log.Info("Migrations completed successfully")
}
