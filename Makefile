MODULE = $(shell go list -m)

swagger: 
	@swag init -g cmd/router/main.go -o api

build: swagger
	@go build -o bin/app -v cmd/router/main.go

run: build
	@./bin/app

.PHONY: generate build test lint build-docker compose compose-down migrate
generate:
	go generate ./...

test:
	go clean -testcache
	go test ./... -v

lint:
	gofmt -l .
