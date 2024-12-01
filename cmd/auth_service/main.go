package main

import (
	"auth_service/internal/config"
	"auth_service/internal/database"
	"auth_service/internal/handlers"
	"auth_service/internal/migrations"
	"auth_service/internal/storage/postgres"
	"auth_service/lib/logger/sl"
	"log/slog"
	"net/http"
	"os"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	// Загрузка конфигурации
	cfg := config.MustLoad()

	// Настройка логгера
	log := setupLogger(cfg.Env)

	log.Info("Starting auth_service...", slog.String("env", cfg.Env))
	log.Debug("Debug messages are enabled")

	// Инициализация БД
	pool, err := database.InitDB(cfg, log)
	if err != nil {
		log.Error("Failed to connect to database: %v", sl.Err(err))
		os.Exit(1)
	}
	defer pool.Close()

	// Инициализация и запуск миграций
	migrations.InitAndRunMigrations(cfg, log)

	// Создание экземпляра хранилища
	storage := postgres.NewPostgresStorage(pool)

	// Маршруты
	http.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		handlers.GenerateTokensHandler(w, r, log, cfg, storage)
	})
	http.HandleFunc("/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		handlers.RefreshTokensHandler(w, r, log, cfg, storage)
	})

	// Запуск сервера
	log.Info("Auth service is up and running", slog.String("address", cfg.HTTPServer.Address))
	if err := http.ListenAndServe(cfg.HTTPServer.Address, nil); err != nil {
		log.Error("Failed to start HTTP server", sl.Err(err))
	}

	//TODO:
	// задокументировать код,

}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level:     slog.LevelDebug,
				AddSource: true,
			}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level:     slog.LevelDebug,
				AddSource: true,
			}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level:     slog.LevelInfo,
				AddSource: true,
			}),
		)
	}

	return log
}
