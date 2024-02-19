# cargo_cmd := cargo remote -r dev --
cargo_cmd := cargo
debug ?= debug

$(info debug is $(debug))

ifdef debug
	release :=
	target :=debug
	extension :=debug
else
	release :=--release
	target :=release
	extension :=
endif

fmt:
	$(cargo_cmd) fmt

build:
	$(cargo_cmd) build $(release)

wasm-build:
	pushd card-protocol-wasm && wasm-pack build $(release)

build-all: build wasm-build

help:
	@echo "usage: make $(prog) [debug=1]"
