package config

import (
	"os"
	"time"
)

type Config struct {
	JWTSecretKey      string
	WebhookURL        string
	AccessTokenExpiry time.Duration
	DBHost            string
	DBPort            string
	DBUser            string
	DBPassword        string
	DBName            string
}

func LoadConfig() *Config {
	return &Config{
		JWTSecretKey:      os.Getenv("JWT_SECRET_KEY"),
		WebhookURL:        os.Getenv("WEBHOOK_URL"),
		AccessTokenExpiry: 15 * time.Minute,
		DBHost:            os.Getenv("DB_HOST"),
		DBPort:            os.Getenv("DB_PORT"),
		DBUser:            os.Getenv("DB_USER"),
		DBPassword:        os.Getenv("DB_PASSWORD"),
		DBName:            os.Getenv("DB_NAME"),
	}
}
