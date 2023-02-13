
all: build-debug

clean:
	cargo clean

debug-build:
	cargo build

release-build:
	cargo build --release

generate-release:
	git tag v$(convco version --bump)
