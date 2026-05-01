SERVICES := api-gateway policy-engine analysis-service audit-service notification-service
BIN_DIR  := bin

.PHONY: all build test lint clean tidy docker-up docker-down

all: build

build: $(SERVICES)

$(SERVICES):
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$@ ./services/$@/...

test:
	go test ./...

lint:
	go vet ./...

tidy:
	@for svc in $(SERVICES); do \
		echo "→ tidy services/$$svc"; \
		cd services/$$svc && go mod tidy && cd ../..; \
	done
	cd pkg && go mod tidy && cd ..

clean:
	rm -rf $(BIN_DIR)

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v
