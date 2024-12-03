
all: build-debug

clean:
	cargo clean

debug-build:
	cargo build

fastdev-build:
	cargo build --profile fastdev

release-build:
	cargo build --release

release-prepare:
	set-cargo-version ./Cargo.toml `convco version --bump`

release:
	git tag v`convco version --bump`
