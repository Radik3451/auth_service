package tokens

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenExpiry = 15 * time.Minute
)

// Генерирует Access Token с указанным userID и clientIP.
// Принимает:
// - userID (string): уникальный идентификатор пользователя.
// - clientIP (string): IP-адрес клиента для дополнительной верификации.
// - jwtSecret (string): секретный ключ для подписи токена.
// Возвращает:
// - строку (сгенерированный Access Token).
// - ошибку, если токен не удалось создать или подписать.
func GenerateAccessToken(userID, clientIP, jwtSecret, refreshHash string) (string, error) {
	now := time.Now()
	expirationTime := now.Add(accessTokenExpiry).Unix()

	claims := jwt.MapClaims{
		"sub":          userID,
		"ip":           clientIP,
		"refresh_hash": refreshHash,
		"exp":          expirationTime,
		"iat":          now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", errors.New("failed to sign access token")
	}
	return signedToken, nil
}

// Генерирует Refresh токен и его bcrypt-хеш.
//
// Возвращает:
// - строку (сгенерированный Refresh Token).
// - строку (bcrypt-хеш Refresh токена).
// - ошибку, если токен не удалось создать.
func GenerateRefreshTokenAndHash() (string, string, error) {
	rawToken := uuid.New().String()
	encodedToken := base64.StdEncoding.EncodeToString([]byte(rawToken))

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(encodedToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return encodedToken, string(hashedToken), nil
}

// Проверяет валидность Access токена и извлекает userID, clientIP и refreshHash.
//
// Принимает:
// - accessToken (string): токен, который необходимо проверить.
// - jwtSecret (string): секретный ключ для валидации подписи токена.
//
// Возвращает:
// - строку (userID): идентификатор пользователя, извлеченный из токена.
// - строку (clientIP): IP-адрес клиента, извлеченный из токена.
// - строку (refreshHash): хешированный refresh-токен, связанный с Access токеном.
// - ошибку, если токен недействителен, либо отсутствуют необходимые данные.
func ValidateAccessToken(accessToken, jwtSecret string) (string, string, string, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return "", "", "", errors.New("failed to parse token: " + err.Error())
	}

	if !token.Valid {
		return "", "", "", errors.New("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", "", errors.New("invalid token claims format")
	}

	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", "", "", errors.New("userID (sub) is missing or invalid in token claims")
	}

	clientIP, ok := claims["ip"].(string)
	if !ok || clientIP == "" {
		return "", "", "", errors.New("clientIP (ip) is missing or invalid in token claims")
	}

	refreshHash, ok := claims["refresh_hash"].(string)
	if !ok || refreshHash == "" {
		return "", "", "", errors.New("refresh_hash is missing or invalid in token claims")
	}

	return userID, clientIP, refreshHash, nil
}

// Проверяет соответствие оригинального Refresh токена и его bcrypt-хеша.
//
// Принимает:
// - hashedToken (string): хешированный Refresh токен.
// - refreshToken (string): оригинальный Refresh токен.
//
// Возвращает:
// - ошибку, если токен не соответствует хешу.
func CompareRefreshToken(hashedToken, refreshToken string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
}
