package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"authentification_service/config"
	"authentification_service/models"
	"authentification_service/storage"
	"authentification_service/utils"
)

type AuthHandler struct {
	cfg    *config.Config
	tokens *storage.TokenStorage
}

func NewAuthHandler(cfg *config.Config, tokens *storage.TokenStorage) *AuthHandler {
	return &AuthHandler{cfg: cfg, tokens: tokens}
}

// GetTokenPair godoc
// @Summary Get access and refresh tokens
// @Description Generates new pair of access and refresh tokens for specified user GUID
// @Tags auth
// @Accept json
// @Produce json
// @Param guid query string true "User GUID"
// @Success 200 {object} models.TokenPair
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /tokens [get]

func (h *AuthHandler) GetTokenPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userGUID := r.URL.Query().Get("guid")
	if userGUID == "" {
		http.Error(w, "GUID parameter is required", http.StatusBadRequest)
		return
	}

	// Генерация access токена
	accessToken, err := utils.GenerateAccessToken(userGUID, h.cfg)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Генерация refresh токена
	refreshToken, refreshTokenHash, err := h.tokens.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Сохранение refresh токена
	if err := h.tokens.StoreRefreshToken(r.Context(), userGUID, refreshTokenHash); err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Кодирование refresh токена в base64
	encodedRefresh := base64.StdEncoding.EncodeToString([]byte(refreshToken))

	response := models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: encodedRefresh,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
