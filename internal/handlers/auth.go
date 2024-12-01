package handlers

import (
	"auth_service/internal/config"
	"auth_service/internal/services/tokens"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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

	accessToken, err := tokens.GenerateAccessToken(userID, clientIP, cfg.JWTSecret)
	if err != nil {
		log.Error("Failed to generate access token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := tokens.GenerateRefreshToken()
	if err != nil {
		log.Error("Failed to generate refresh token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Failed to hash refresh token", slog.String("error", err.Error()))
		http.Error(w, "failed to hash refresh token", http.StatusInternalServerError)
		return
	}

	err = db.SaveRefreshToken(userID, string(hashedToken), clientIP)
	if err != nil {
		log.Error("Failed to save refresh token to database", slog.String("error", err.Error()))
		http.Error(w, "failed to save refresh token", http.StatusInternalServerError)
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

	userID, clientIP, err := tokens.ValidateAccessToken(req.AccessToken, cfg.JWTSecret)
	if err != nil {
		log.Warn("Invalid access token provided", slog.String("error", err.Error()))
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	log.Info("Access token validated", slog.String("user_id", userID), slog.String("clientIP", clientIP))

	storedToken, err := db.GetRefreshToken(userID)
	if err != nil {
		log.Error("Failed to retrieve refresh token from database", slog.String("error", err.Error()))
		http.Error(w, "refresh token not found", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedToken), []byte(req.RefreshToken))
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
	}

	newAccessToken, err := tokens.GenerateAccessToken(userID, clientIP, cfg.JWTSecret)
	if err != nil {
		log.Error("Failed to generate access token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := tokens.GenerateRefreshToken()
	if err != nil {
		log.Error("Failed to generate refresh token", slog.String("error", err.Error()))
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	newHashedToken, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Failed to hash refresh token", slog.String("error", err.Error()))
		http.Error(w, "failed to hash refresh token", http.StatusInternalServerError)
		return
	}

	err = db.UpdateRefreshToken(userID, string(newHashedToken), clientIP)
	if err != nil {
		log.Error("Failed to update refresh token in database", slog.String("error", err.Error()))
		http.Error(w, "failed to update refresh token", http.StatusInternalServerError)
		return
	}

	log.Info("Tokens updated successfully", slog.String("user_id", userID), slog.Int("status", http.StatusOK))

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
