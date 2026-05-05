# Chaco-256 Makefile
# Convenient build commands for all platforms

.PHONY: all build test clean install examples docs bench help

# Default target
all: build test

# Build Rust library
build:
	@echo "Building Chaco-256..."
	cargo build --release

# Build with FFI support for C/C++
build-ffi:
	@echo "Building Chaco-256 with FFI support..."
	cargo build --release --features ffi

# Run all tests
test:
	@echo "Running Rust tests..."
	cargo test --release
	@echo "Running Python tests..."
	python3 chaco256.py || python chaco256.py

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	cargo bench

# Build documentation
docs:
	@echo "Building documentation..."
	cargo doc --open

# Build and run examples
examples: build-ffi
	@echo "Building C example..."
	gcc -o target/example_c bindings/examples/example.c -Ltarget/release -lchaco256 -Ibindings
	@echo "Building C++ example..."
	g++ -o target/example_cpp bindings/examples/example.cpp -Ltarget/release -lchaco256 -Ibindings -std=c++17
	@echo "Running examples..."
	cargo run --release --example basic_usage
	cargo run --release --example comprehensive_demo

# Generate test vectors
test-vectors:
	@echo "Generating test vectors..."
	python3 examples/generate_test_vectors.py > test_vectors.txt
	@echo "Test vectors saved to test_vectors.txt"

# Install Python package
install-python:
	@echo "Installing Python package..."
	pip install -e .

# Install C/C++ library (Unix/Linux/macOS)
install-c: build-ffi
	@echo "Installing C/C++ library..."
	sudo cp bindings/chaco256.h /usr/local/include/
	sudo cp target/release/libchaco256.* /usr/local/lib/ 2>/dev/null || true
	sudo ldconfig 2>/dev/null || true
	@echo "Installation complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -f test_vectors.txt
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Format code
format:
	@echo "Formatting Rust code..."
	cargo fmt

# Run linter
lint:
	@echo "Running Rust linter..."
	cargo clippy -- -D warnings

# Check code without building
check:
	@echo "Checking Rust code..."
	cargo check

# Full CI pipeline
ci: format lint build test

# Help
help:
	@echo "Chaco-256 Makefile Commands:"
	@echo ""
	@echo "  make build          - Build Rust library"
	@echo "  make build-ffi      - Build with C/C++ FFI support"
	@echo "  make test           - Run all tests"
	@echo "  make bench          - Run benchmarks"
	@echo "  make docs           - Build and open documentation"
	@echo "  make examples       - Build and run examples"
	@echo "  make test-vectors   - Generate test vectors"
	@echo "  make install-python - Install Python package"
	@echo "  make install-c      - Install C/C++ library (requires sudo)"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make format         - Format Rust code"
	@echo "  make lint           - Run Rust linter"
	@echo "  make check          - Check code without building"
	@echo "  make ci             - Run full CI pipeline"
	@echo "  make help           - Show this help message"
	@echo ""
	@echo "For more information, see INSTALLATION.md"
