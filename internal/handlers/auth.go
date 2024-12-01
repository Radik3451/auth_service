package handlers

import (
	"auth_service/internal/config"
	"auth_service/internal/services/tokens"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Интерфейс для работы с хранилищем токенов и IP-адресов.
type Storage interface {
	SaveRefreshToken(userID, hashedToken, clientIP string) error
	GetRefreshToken(userID string) (string, error)
	UpdateRefreshToken(userID, hashedToken, clientIP string) error
	GetLastIP(userID string) (string, error)
	GetUserEmail(userID string) (string, error)
}

// Обрабатывает запросы на генерацию новых токенов.
//
// Принимает:
// - w: http.ResponseWriter для отправки ответа клиенту.
// - r: *http.Request с данными запроса.
// - log: указатель на logger для логирования событий.
// - cfg: ссылка на конфигурацию приложения.
// - db: интерфейс для взаимодействия с хранилищем токенов.
//
// Возвращает:
// - HTTP 200 OK с access и refresh токенами в теле ответа при успешной обработке.
// - HTTP 400 Bad Request, если отсутствует или некорректен параметр user_id.
// - HTTP 500 Internal Server Error, если возникает ошибка при генерации токенов или сохранении в хранилище.
func GenerateTokensHandler(w http.ResponseWriter, r *http.Request, log *slog.Logger, cfg *config.Config, db Storage) {
	log.Info("Handling GenerateTokens request", slog.String("method", r.Method), slog.String("path", r.URL.Path))

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		log.Warn("Missing user_id in request")
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(userID); err != nil {
		log.Warn("Invalid user_id provided", slog.String("user_id", userID))
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	clientIP := r.RemoteAddr
	log.Info("Client IP address obtained", slog.String("clientIP", clientIP))

	// Генерация Refresh токена и его хеша
	refreshToken, hashedToken, err := tokens.GenerateRefreshTokenAndHash()
	if err != nil {
		log.Error("Failed to generate refresh token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Сохранение Refresh токена
	err = db.SaveRefreshToken(userID, hashedToken, clientIP)
	if err != nil {
		log.Error("Failed to save refresh token to database", slog.String("error", err.Error()))
		http.Error(w, "failed to save refresh token", http.StatusInternalServerError)
		return
	}

	accessToken, err := tokens.GenerateAccessToken(userID, clientIP, cfg.JWTSecret, hashedToken)
	if err != nil {
		log.Error("Failed to generate access token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	log.Info("Tokens generated and saved successfully", slog.String("user_id", userID), slog.Int("status", http.StatusOK))

	response := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("Failed to encode response", slog.String("error", err.Error()))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// Обрабатывает запросы на обновление токенов
//
// Принимает:
// - w: http.ResponseWriter для отправки ответа клиенту.
// - r: *http.Request с данными запроса.
// - log: указатель на logger для логирования событий.
// - cfg: ссылка на конфигурацию приложения.
// - db: интерфейс для взаимодействия с хранилищем токенов.
//
// Возвращает:
// - HTTP 200 OK с новыми токенами в теле ответа при успешной обработке.
// - HTTP 400 Bad Request, если тело запроса некорректное.
// - HTTP 401 Unauthorized, если предоставленные токены недействительны.
// - HTTP 500 Internal Server Error, если возникает ошибка при обновлении токенов или сохранении в хранилище.
func RefreshTokensHandler(w http.ResponseWriter, r *http.Request, log *slog.Logger, cfg *config.Config, db Storage) {
	log.Info("Handling RefreshTokens request", slog.String("method", r.Method), slog.String("path", r.URL.Path))

	var req TokenResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("Invalid request body", slog.String("error", err.Error()))
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	userID, clientIP, storedHash, err := tokens.ValidateAccessToken(req.AccessToken, cfg.JWTSecret)
	if err != nil {
		log.Warn("Invalid access token provided", slog.String("error", err.Error()))
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	storedToken, err := db.GetRefreshToken(userID)
	if err != nil {
		log.Error("Failed to retrieve refresh token from database", slog.String("error", err.Error()))
		http.Error(w, "refresh token not found", http.StatusUnauthorized)
		return
	}

	err = tokens.CompareRefreshToken(storedToken, req.RefreshToken)
	if err != nil {
		log.Warn("Invalid refresh token provided", slog.String("user_id", userID))
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	lastIP, err := db.GetLastIP(userID)
	if err != nil {
		log.Error("Failed to retrieve last IP from database", slog.String("error", err.Error()))
		http.Error(w, "failed to retrieve last IP", http.StatusInternalServerError)
		return
	}

	if clientIP != lastIP {
		log.Warn("Client IP has changed", slog.String("user_id", userID), slog.String("lastIP", lastIP), slog.String("currentIP", clientIP))

		email, err := db.GetUserEmail(userID)
		if err != nil {
			log.Error("Failed to retrieve user email", slog.String("error", err.Error()))
			http.Error(w, "failed to retrieve user email", http.StatusInternalServerError)
			return
		}

		log.Warn("Sending warning email", slog.String("email", email), slog.String("user_id", userID))
		// Здесь можно добавить реальную интеграцию с почтовым сервисом.
	}

	// Генерация новых токенов
	newAccessToken, err := tokens.GenerateAccessToken(userID, clientIP, cfg.JWTSecret, storedHash)
	if err != nil {
		log.Error("Failed to generate access token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newHashedToken, err := tokens.GenerateRefreshTokenAndHash()
	if err != nil {
		log.Error("Failed to generate refresh token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Обновление токена в базе
	err = db.UpdateRefreshToken(userID, newHashedToken, clientIP)
	if err != nil {
		log.Error("Failed to update refresh token in database", slog.String("error", err.Error()))
		http.Error(w, "failed to update refresh token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("Failed to encode response", slog.String("error", err.Error()))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
