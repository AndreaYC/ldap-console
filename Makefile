BIN := bin
DEMO_BIND_DN := CN=svc-ldap,OU=Service,DC=corp,DC=local
DEMO_PASSWORD := test-only-password

.PHONY: help build install test cover lint run demo clean

help: ## List targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

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
	go test -race -coverpkg=./internal/... -coverprofile=$(BIN)/cover.out ./...
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
