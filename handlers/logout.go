package handlers

import (
	"net/http"
	"strings"
	"time"

	"authentification_service/config"
	"authentification_service/storage"
	"authentification_service/utils"
)

type LogoutHandler struct {
	cfg    *config.Config
	tokens *storage.TokenStorage
}

func NewLogoutHandler(cfg *config.Config, tokens *storage.TokenStorage) *LogoutHandler {
	return &LogoutHandler{cfg: cfg, tokens: tokens}
}

func (h *LogoutHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := utils.ParseToken(tokenString, h.cfg)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Удаляем refresh токен
	if err := h.tokens.DeleteRefreshToken(r.Context(), claims.UserGUID); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	// Помечаем access токен как отозванный
	expiry := time.Now().Add(h.cfg.AccessTokenExpiry)
	if err := h.tokens.StoreRevokedToken(r.Context(), tokenString, expiry); err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully logged out"))
}
