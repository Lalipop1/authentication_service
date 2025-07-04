package main

import (
	"log"
	"net/http"

	"authentification_service/config"
	_ "authentification_service/docs"
	"authentification_service/handlers"
	"authentification_service/storage"
	"github.com/swaggo/http-swagger"
)

// @title Authentication Service API
// @version 1.0
// @description JWT-based authentication service with refresh tokens

// @contact.name API Support
// @contact.url http://example.com/support
// @contact.email support@example.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	cfg := config.LoadConfig()

	db, err := storage.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	tokenStorage := storage.NewTokenStorage(db)

	authHandler := handlers.NewAuthHandler(cfg, tokenStorage)
	refreshHandler := handlers.NewRefreshHandler(cfg, tokenStorage)
	meHandler := handlers.NewMeHandler(cfg, tokenStorage)
	logoutHandler := handlers.NewLogoutHandler(cfg, tokenStorage)

	http.HandleFunc("/tokens", authHandler.GetTokenPair)
	http.HandleFunc("/refresh", refreshHandler.RefreshToken)
	http.HandleFunc("/me", meHandler.GetCurrentUser)
	http.HandleFunc("/logout", logoutHandler.Logout)

	// Swagger
	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	log.Println("Server started on :8080")
	log.Println("Swagger UI available at http://localhost:8080/swagger/index.html")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
