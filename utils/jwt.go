package utils

import (
	"authentification_service/config"
	"authentification_service/models"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

func GenerateAccessToken(userGUID string, cfg *config.Config) (string, error) {
	expirationTime := time.Now().Add(cfg.AccessTokenExpiry)

	claims := &models.Claims{
		UserGUID: userGUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(cfg.JWTSecretKey))
}

func ParseToken(tokenString string, cfg *config.Config) (*models.Claims, error) {
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.JWTSecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
