
all: build-debug

clean:
	cargo clean

debug-build:
	cargo build

release-build:
	cargo build --release

release-prepare:
	set-cargo-version ./Cargo.toml `convco version --bump`

release:
	git tag v`convco version --bump`
