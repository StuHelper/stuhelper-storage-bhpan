GOWORK ?= off
export GOWORK

.PHONY: setup check test build hooks docs
setup:
	LEFTHOOK=0 pnpm install --frozen-lockfile
check:
	pnpm exec stuhelper-check repository
	node scripts/check-adapter.mjs
	pnpm run check:docs
	test -z "$$(gofmt -l *.go cmd)"
	go vet ./...
	go test -race ./...
	go build -mod=readonly ./...
	pnpm exec stuhelper-check workflows
test:
	go test -race ./...
build:
	go build -mod=readonly ./...
hooks:
	pnpm exec lefthook install
docs:
	uvx --with mkdocs-material mkdocs serve
