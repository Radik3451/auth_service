package tokens

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
func GenerateAccessToken(userID, clientIP, jwtSecret string) (string, error) {
	now := time.Now()
	expirationTime := now.Add(accessTokenExpiry).Unix()

	claims := jwt.MapClaims{
		"sub": userID,
		"ip":  clientIP,
		"exp": expirationTime,
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", errors.New("failed to sign access token")
	}
	return signedToken, nil
}

// Генерирует случайный UUID в качестве Refresh токена.
// Возвращает:
// - строку (сгенерированный Refresh Token).
// - ошибку, если токен не удалось создать.
func GenerateRefreshToken() (string, error) {
	refreshToken := uuid.New().String()
	return refreshToken, nil
}

// Проверяет валидность Access токена и извлекает userID и clientIP.
// Принимает:
// - accessToken (string): токен, который необходимо проверить.
// - jwtSecret (string): секретный ключ для валидации подписи токена.
// Возвращает:
// - строку (userID): идентификатор пользователя, извлеченный из токена.
// - строку (clientIP): IP-адрес клиента, извлеченный из токена.
// - ошибку, если токен недействителен, либо отсутствуют необходимые данные.
func ValidateAccessToken(accessToken, jwtSecret string) (string, string, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return "", "", errors.New("failed to parse token: " + err.Error())
	}

	if !token.Valid {
		return "", "", errors.New("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid token claims format")
	}

	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", "", errors.New("userID (sub) is missing or invalid in token claims")
	}

	clientIP, ok := claims["ip"].(string)
	if !ok || clientIP == "" {
		return "", "", errors.New("clientIP (ip) is missing or invalid in token claims")
	}

	return userID, clientIP, nil
}
