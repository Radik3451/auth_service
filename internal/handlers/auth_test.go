package handlers_test

import (
	"auth_service/internal/config"
	"auth_service/internal/handlers"
	"auth_service/internal/services/tokens"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type MockStorage struct {
	users         map[string]bool
	refreshTokens map[string]string
	ipAddresses   map[string]string
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		users:         make(map[string]bool),
		refreshTokens: make(map[string]string),
		ipAddresses:   make(map[string]string),
	}
}

// Добавляет пользователя в storage.
// Принимает userID (строка) — идентификатор пользователя.
func (m *MockStorage) CreateUser(userID string) {
	m.users[userID] = true
}

// Сохраняет refresh-токен для пользователя.
// Принимает:
// - userID (строка): идентификатор пользователя.
// - hashedToken (строка): хешированный refresh-токен.
// - clientIP (строка): IP-адрес клиента.
// Возвращает ошибку, если пользователь не существует.
func (m *MockStorage) SaveRefreshToken(userID, hashedToken, clientIP string) error {
	if _, exists := m.users[userID]; !exists {
		return fmt.Errorf("user does not exist")
	}
	m.refreshTokens[userID] = hashedToken
	m.ipAddresses[userID] = clientIP
	return nil
}

// Возвращает refresh-токен пользователя.
// Принимает userID (строка) — идентификатор пользователя.
// Возвращает:
// - строку (refresh-токен).
// - ошибку, если пользователь или токен не найдены.
func (m *MockStorage) GetRefreshToken(userID string) (string, error) {
	if _, exists := m.users[userID]; !exists {
		return "", fmt.Errorf("user does not exist")
	}
	token, exists := m.refreshTokens[userID]
	if !exists {
		return "", fmt.Errorf("refresh token not found")
	}
	return token, nil
}

// Обновляет refresh-токен пользователя.
// Принимает:
// - userID (строка): идентификатор пользователя.
// - hashedToken (строка): новый хешированный refresh-токен.
// - clientIP (строка): IP-адрес клиента.
// Возвращает ошибку, если пользователь не существует.
func (m *MockStorage) UpdateRefreshToken(userID, hashedToken, clientIP string) error {
	if _, exists := m.users[userID]; !exists {
		return fmt.Errorf("user does not exist")
	}
	m.refreshTokens[userID] = hashedToken
	m.ipAddresses[userID] = clientIP
	return nil
}

// Возвращает последний IP-адрес пользователя.
// Принимает userID (строка) — идентификатор пользователя.
// Возвращает:
// - строку (IP-адрес).
// - ошибку, если пользователь или IP-адрес не найдены
func (m *MockStorage) GetLastIP(userID string) (string, error) {
	if _, exists := m.users[userID]; !exists {
		return "", fmt.Errorf("user does not exist")
	}
	ip, exists := m.ipAddresses[userID]
	if !exists {
		return "", fmt.Errorf("IP address not found")
	}
	return ip, nil
}

// Тестирование обработчика GenerateTokensHandler.
// Проверяка генерацию access и refresh токенов для валидного user_id.
func TestGenerateTokensHandler(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "secret",
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	storage := NewMockStorage()

	userID := "123e4567-e89b-12d3-a456-426614174000"
	storage.CreateUser(userID)

	req := httptest.NewRequest(http.MethodGet, "/auth/tokens?user_id="+userID, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateTokensHandler(rec, req, logger, cfg, storage)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp handlers.TokenResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

// Тестирование обработчика GenerateTokensHandler.
// Проверка поведения при отсутствии user_id в запросе.
func TestGenerateTokensHandler_MissingUserID(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "secret",
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	storage := NewMockStorage()

	req := httptest.NewRequest(http.MethodGet, "/auth/tokens", nil)
	rec := httptest.NewRecorder()

	handlers.GenerateTokensHandler(rec, req, logger, cfg, storage)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "user_id is required")
}

// Тестирует обработчика RefreshTokensHandler.
// Проверка обновления токенов для валидного запроса.
func TestRefreshTokensHandler(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "secret",
	}

	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}),
	)

	storage := NewMockStorage()

	userID := "123e4567-e89b-12d3-a456-426614174000"
	clientIP := "127.0.0.1"

	storage.CreateUser(userID)

	accessToken, err := tokens.GenerateAccessToken(userID, clientIP, cfg.JWTSecret)
	assert.NoError(t, err)

	refreshToken, err := tokens.GenerateRefreshToken()
	assert.NoError(t, err)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	assert.NoError(t, err)

	err = storage.SaveRefreshToken(userID, string(hashedToken), clientIP)
	assert.NoError(t, err)

	reqBody, err := json.Marshal(handlers.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = clientIP

	rec := httptest.NewRecorder()

	handlers.RefreshTokensHandler(rec, req, logger, cfg, storage)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp handlers.TokenResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

// Тестирование обработчика RefreshTokensHandler.
// Проверка поведения при недействительном access токене.
func TestRefreshTokensHandler_InvalidAccessToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "secret",
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	storage := NewMockStorage()

	reqBody, _ := json.Marshal(handlers.TokenResponse{
		AccessToken:  "invalid_token",
		RefreshToken: "test_refresh_token",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.RefreshTokensHandler(rec, req, logger, cfg, storage)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid access token")
}
