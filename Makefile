debug ?=

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

build:
	cargo build $(release)

wasm-build:
	pushd card-protocol-wasm && wasm-pack build $(release)

build-all: build wasm-build


help:
	@echo "usage: make $(prog) [debug=1]"
