package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"

	"authentification_service/config"
	"authentification_service/models"
	"authentification_service/storage"
	"authentification_service/utils"
)

type RefreshHandler struct {
	cfg    *config.Config
	tokens *storage.TokenStorage
}

func NewRefreshHandler(cfg *config.Config, tokens *storage.TokenStorage) *RefreshHandler {
	return &RefreshHandler{cfg: cfg, tokens: tokens}
}

func (h *RefreshHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Декодирование refresh токена
	refreshTokenBytes, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token format", http.StatusBadRequest)
		return
	}
	refreshToken := string(refreshTokenBytes)

	// Извлечение access токена
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := utils.ParseToken(tokenString, h.cfg)
	if err != nil {
		http.Error(w, "Invalid access token: "+err.Error(), http.StatusUnauthorized)
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

	userGUID := claims.UserGUID

	// Проверка refresh токена
	storedHash, err := h.tokens.GetRefreshTokenHash(r.Context(), userGUID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if storedHash == "" {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(refreshToken)); err != nil {
		// Неудачная попытка - удаляем refresh токен
		h.tokens.DeleteRefreshToken(r.Context(), userGUID)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Проверка User-Agent
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		http.Error(w, "User-Agent header is required", http.StatusBadRequest)
		return
	}

	// Получаем информацию о предыдущей сессии
	prevSession, err := h.tokens.GetSessionInfo(r.Context(), userGUID)
	if err != nil && err != pgx.ErrNoRows {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Получаем текущий IP
	currentIP := getClientIP(r)

	// Если есть предыдущая сессия, проверяем изменения
	if prevSession != nil {
		// Проверка User-Agent
		if prevSession.UserAgent != userAgent {
			h.tokens.DeleteRefreshToken(r.Context(), userGUID)
			http.Error(w, "User-Agent changed. Please re-authenticate", http.StatusUnauthorized)
			return
		}

		// Проверка IP (если изменился, отправляем webhook)
		if prevSession.IPAddress != currentIP {
			if err := utils.SendIPChangeWebhook(h.cfg.WebhookURL, userGUID, currentIP, userAgent); err != nil {
				// Логируем ошибку, но не прерываем процесс
				fmt.Printf("Failed to send webhook: %v\n", err)
			}
		}
	}

	// Обновляем информацию о сессии
	if err := h.tokens.StoreSessionInfo(r.Context(), userGUID, currentIP, userAgent); err != nil {
		http.Error(w, "Failed to update session info", http.StatusInternalServerError)
		return
	}

	// Генерация новой пары токенов
	newAccessToken, err := utils.GenerateAccessToken(userGUID, h.cfg)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newRefreshTokenHash, err := h.tokens.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Обновление токенов в БД
	if err := h.tokens.StoreRefreshToken(r.Context(), userGUID, newRefreshTokenHash); err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Помечаем старый access токен как отозванный
	expiry := time.Now().Add(h.cfg.AccessTokenExpiry)
	if err := h.tokens.StoreRevokedToken(r.Context(), tokenString, expiry); err != nil {
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	// Кодирование нового refresh токена
	encodedRefresh := base64.StdEncoding.EncodeToString([]byte(newRefreshToken))

	response := models.TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: encodedRefresh,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Возвращаем реальный IP клиента с учетом прокси
func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
