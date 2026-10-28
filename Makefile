BIN := bin
IMAGE := ldap-console
PORT ?= 8389
CA_FILE ?=
# make does not expand ~; a missing file would make Docker mount an empty directory.
CA_PATH = $(abspath $(patsubst ~/%,$(HOME)/%,$(CA_FILE)))
HOST_TZ := $(shell readlink /etc/localtime 2>/dev/null | sed 's|.*zoneinfo/||')
DEMO_BIND_DN := CN=svc-ldap,OU=Service,DC=corp,DC=local
DEMO_PASSWORD := test-only-password

.PHONY: help build install test cover lint run demo clean docker-build docker-run docker-stop docker-logs

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build ldap-console and ldap-demo into bin/
	go build -o $(BIN)/ldap-console ./cmd/ldap-console
	go build -o $(BIN)/ldap-demo ./cmd/ldap-demo

install: ## Install ldap-console into $(go env GOPATH)/bin
	go install ./cmd/ldap-console

test: ## Go tests with the race detector, plus JS unit tests when node is installed
	go test -race ./...
	@if command -v node >/dev/null; then node --test web/test/*.test.mjs; else echo "node not installed, JS tests skipped"; fi

cover: ## Aggregate coverage of internal packages
	@mkdir -p $(BIN)
	go test -count=1 -race -coverpkg=./internal/... -coverprofile=$(BIN)/cover.out ./...
	go tool cover -func=$(BIN)/cover.out | tail -1

lint: ## gofmt check, go vet, and gosec when installed
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }
	go vet ./...
	@if command -v gosec >/dev/null; then gosec -quiet -exclude-dir=internal/ldaptest -exclude-dir=cmd/ldap-demo ./...; \
	else echo "gosec not installed, skipped"; fi

run: build ## Run against a real server: LDAP_URL=... LDAP_BIND_DN=... make run
	$(BIN)/ldap-console

demo: build ## Run the console against the built-in fake AD (Ctrl-C stops both)
	@$(BIN)/ldap-demo >/dev/null 2>&1 & pid=$$!; trap "kill $$pid" EXIT INT TERM; sleep 1; \
	LDAP_BIND_PASSWORD=$(DEMO_PASSWORD) $(BIN)/ldap-console -url ldap://127.0.0.1:3389 -bind-dn "$(DEMO_BIND_DN)"

clean: ## Remove build output
	rm -rf $(BIN)

docker-build: ## Build the container image
	docker build -t $(IMAGE) .

# Published on 127.0.0.1 only: the console has no login of its own.
docker-run: docker-build ## Run in the background on 127.0.0.1:$(PORT), restarting with Docker (CA_FILE=company-ca.pem)
	@$(if $(CA_FILE),test -f "$(CA_PATH)" || { echo "CA_FILE $(CA_PATH) does not exist"; exit 1; })
	@docker rm -f $(IMAGE) >/dev/null 2>&1 || true
	docker run -d --name $(IMAGE) --restart unless-stopped \
		-p 127.0.0.1:$(PORT):8389 \
		-v ldap-console-config:/home/nonroot/.config/ldap-console \
		$(if $(HOST_TZ),-e TZ=$(HOST_TZ)) \
		$(if $(CA_FILE),-v "$(CA_PATH)":/certs/ca.pem:ro -e LDAP_CA_FILE=/certs/ca.pem) \
		$(IMAGE)
	@echo "LDAP Console → http://127.0.0.1:$(PORT)"

docker-stop: ## Stop and remove the container (saved settings are kept)
	docker rm -f $(IMAGE)

docker-logs: ## Follow the container's log
	docker logs -f $(IMAGE)
