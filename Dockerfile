# Build stage
FROM golang:1.24-alpine AS builder

# Install swag
RUN apk add --no-cache git
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.2


WORKDIR /authentification_service
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Generate Swagger docs
RUN swag init -g main.go --output docs --parseDependency --parseInternal

# Build application
RUN CGO_ENABLED=0 GOOS=linux go build -o authentification_service .

# Final stage
FROM alpine:latest

WORKDIR /authentification_service

COPY --from=builder /authentification_service .
COPY --from=builder /authentification_service/config/config.go ./config/

ENV JWT_SECRET_KEY=default_secret_key
ENV WEBHOOK_URL=http://example.com/webhook
ENV DB_HOST=postgres
ENV DB_PORT=5432
ENV DB_USER=postgres
ENV DB_PASSWORD=postgres
ENV DB_NAME=auth_service

EXPOSE 8080
CMD ["./authentification_service"]