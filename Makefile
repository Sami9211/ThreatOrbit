# ThreatOrbit - one-command workflows.
# Run `make help` (or just `make`) to see what's available.

.DEFAULT_GOAL := help
.PHONY: help up down logs test test-backend test-postgres test-frontend build dev-api dev-frontend seed

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Deploy the full stack (3 APIs + frontend) with Docker
	docker compose up --build -d
	@echo ""
	@echo "  Frontend:       http://localhost:3000"
	@echo "  Dashboard API:  http://localhost:8002  (login: admin@threatorbit.space / ChangeMe123!)"
	@echo "  Threat API:     http://localhost:8000"
	@echo "  Log API:        http://localhost:8001"

down: ## Stop the Docker stack
	docker compose down

logs: ## Tail logs from all services
	docker compose logs -f

test: test-backend test-frontend ## Run every test suite + frontend type-check

test-backend: ## Run all three Python API test suites
	python -m pytest dashboard_api/tests -q
	cd threat_api && python -m pytest -q
	cd log_api && python -m pytest -q

test-postgres: ## Run the dashboard suite against Postgres (what CI's backend-postgres job runs)
	@# A green SQLite run is NOT evidence the Postgres job passes: the wrappers
	@# differ (cursor iteration, placeholder handling), and CI sat red for three
	@# commits because only SQLite was ever run locally. Needs Docker.
	docker run -d --rm --name to-pgtest -e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=threatorbit -p 5432:5432 postgres:16 >/dev/null
	@echo "waiting for postgres..."
	@until docker exec to-pgtest pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	-DASHBOARD_DB_BACKEND=postgres \
		DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/threatorbit \
		python -m pytest dashboard_api/tests -q
	@docker rm -f to-pgtest >/dev/null

test-frontend: ## Type-check the frontend (fast; use `make build` for a full build)
	cd frontend && npx tsc --noEmit

build: ## Production-build the frontend (static export to frontend/out)
	cd frontend && npm run build

dev-api: ## Run the dashboard API locally with auto-reload (:8002)
	uvicorn dashboard_api.main:app --reload --port 8002

dev-frontend: ## Run the frontend dev server (:3000)
	cd frontend && npm run dev

seed: ## Force-rebuild the dashboard demo data
	python -m dashboard_api.seed
