package storage

import (
	"authentification_service/models"
	"context"
	"github.com/jackc/pgx/v4"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenStorage struct {
	db *Database
}

func NewTokenStorage(db *Database) *TokenStorage {
	return &TokenStorage{db: db}
}

func (s *TokenStorage) StoreRefreshToken(ctx context.Context, userGUID, tokenHash string) error {
	query := `
		INSERT INTO refresh_tokens (user_guid, token_hash, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_guid) 
		DO UPDATE SET token_hash = $2, created_at = $3`

	_, err := s.db.Pool.Exec(ctx, query, userGUID, tokenHash, time.Now())
	return err
}

func (s *TokenStorage) GetRefreshTokenHash(ctx context.Context, userGUID string) (string, error) {
	var tokenHash string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT token_hash FROM refresh_tokens WHERE user_guid = $1", userGUID).Scan(&tokenHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return tokenHash, nil
}

func (s *TokenStorage) DeleteRefreshToken(ctx context.Context, userGUID string) error {
	_, err := s.db.Pool.Exec(ctx,
		"DELETE FROM refresh_tokens WHERE user_guid = $1", userGUID)
	return err
}

func (s *TokenStorage) StoreRevokedToken(ctx context.Context, token string, expiry time.Time) error {
	_, err := s.db.Pool.Exec(ctx,
		"INSERT INTO revoked_tokens (token, expires_at) VALUES ($1, $2)", token, expiry)
	return err
}

func (s *TokenStorage) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	var exists bool
	err := s.db.Pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token = $1)", token).Scan(&exists)
	return exists, err
}

func (s *TokenStorage) GenerateRefreshToken() (string, string, error) {
	token := uuid.New().String()
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return token, string(hash), nil
}

func (s *TokenStorage) StoreSessionInfo(ctx context.Context, userGUID, ip, userAgent string) error {
	query := `
        INSERT INTO sessions (user_guid, ip_address, user_agent, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_guid) 
        DO UPDATE SET ip_address = $2, user_agent = $3, created_at = $4`

	_, err := s.db.Pool.Exec(ctx, query, userGUID, ip, userAgent, time.Now())
	return err
}

func (s *TokenStorage) GetSessionInfo(ctx context.Context, userGUID string) (*models.SessionInfo, error) {
	var session models.SessionInfo
	err := s.db.Pool.QueryRow(ctx,
		"SELECT user_guid, ip_address, user_agent, created_at FROM sessions WHERE user_guid = $1",
		userGUID).Scan(
		&session.UserGUID,
		&session.IPAddress,
		&session.UserAgent,
		&session.CreatedAt)

	if err == pgx.ErrNoRows {
		return nil, nil // Сессия не найдена
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}
