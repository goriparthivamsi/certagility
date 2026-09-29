.PHONY: build test lint run
build:
	go build -o bin/certagility ./cmd/certagility
test:
	go test -race ./...
lint:
	gofmt -l . && go vet ./...
run: build
	./bin/certagility scan -e example.com
