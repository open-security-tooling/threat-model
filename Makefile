.PHONY: build build-web test fuzz wasm web web-release release-build clean

GO ?= go

build:
	$(GO) build -trimpath -o bin/threat ./cmd/threat

# With the web app embedded (run `make web` first).
build-web:
	$(GO) build -trimpath -tags webapp -o bin/threat ./cmd/threat

test:
	$(GO) vet ./...
	$(GO) test ./...

fuzz:
	$(GO) test ./internal/model -run '^$$' -fuzz FuzzParse -fuzztime 60s
	$(GO) test ./internal/edit -run '^$$' -fuzz FuzzUpsert -fuzztime 60s

# Builds the core for the web app into web/public.
wasm:
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags="-s -w" -o web/public/core.wasm ./wasm
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" web/public/wasm_exec.js

# The web app, built for embedding: no npm install scripts, output only to ignored paths.
web: wasm
	cd web && npm ci --ignore-scripts && npm run build
	rm -rf internal/webassets/dist && cp -R web/dist internal/webassets/dist

web-release: web

# Local equivalent of one release binary (with the web app), for rebuild checks.
release-build: web
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=true -tags webapp \
		-ldflags="-s -w -X main.version=$(VERSION)" -o bin/threat ./cmd/threat

clean:
	rm -rf bin web/dist web/public/core.wasm web/public/wasm_exec.js internal/webassets/dist
