run:
	CONFIG_PATH=config/config.yaml go run ./cmd/auth_service/main.go

test: start-test-db run-tests stop-test-db

start-test-db:
	docker compose -f docker-compose.test.yaml build postgres
	docker compose -f docker-compose.test.yaml up -d postgres
	docker ps

run-tests:
	@echo "Waiting for PostgreSQL to start..."
	sleep 5
	@echo "======================================="
	@echo "Running tests..."
	@echo "======================================="
	CONFIG_PATH=config/config.yaml go test ./internal/storage/postgres -v
	CONFIG_PATH=config/config.yaml go test ./internal/handlers -v

stop-test-db:
	docker compose -f docker-compose.test.yaml down --remove-orphans
	docker network prune -f
	docker volume prune -f

build:
	@echo "======================================="
	@echo "Starting Docker Build Process"
	@echo "======================================="
	docker compose -f docker-compose.yaml build
	@echo ""
	@echo "======================================="
	@echo "Bringing up all services"
	@echo "======================================="
	docker compose -f docker-compose.yaml up

.PHONY: test start-test-db run-tests stop-test-db build