package models

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	UserGUID string `json:"user_guid"`
	jwt.RegisteredClaims
}

type StandardClaims struct {
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss,omitempty"`
}

type WebhookPayload struct {
	UserGUID    string `json:"user_guid"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	AttemptTime string `json:"attempt_time"`
}

type SessionInfo struct {
	UserGUID  string    `json:"user_guid"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}
