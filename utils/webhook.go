package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"authentification_service/models"
)

func SendIPChangeWebhook(webhookURL, userGUID, ip, userAgent string) error {
	if webhookURL == "" {
		return nil
	}

	payload := models.WebhookPayload{
		UserGUID:    userGUID,
		IPAddress:   ip,
		UserAgent:   userAgent,
		AttemptTime: time.Now().Format(time.RFC3339),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status code: %d", resp.StatusCode)
	}

	return nil
}
