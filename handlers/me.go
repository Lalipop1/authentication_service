package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"authentification_service/config"
	"authentification_service/storage"
	"authentification_service/utils"
)

type MeHandler struct {
	cfg    *config.Config
	tokens *storage.TokenStorage
}

func NewMeHandler(cfg *config.Config, tokens *storage.TokenStorage) *MeHandler {
	return &MeHandler{cfg: cfg, tokens: tokens}
}

func (h *MeHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	// Проверка отозван ли токен
	revoked, err := h.tokens.IsTokenRevoked(r.Context(), tokenString)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if revoked {
		http.Error(w, "Access token is revoked", http.StatusUnauthorized)
		return
	}

	// Проверка наличия refresh токена (чтобы убедиться что пользователь не разлогинен)
	_, err = h.tokens.GetRefreshTokenHash(r.Context(), claims.UserGUID)
	if err != nil {
		http.Error(w, "User is not authorized", http.StatusUnauthorized)
		return
	}

	response := map[string]string{"user_guid": claims.UserGUID}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
