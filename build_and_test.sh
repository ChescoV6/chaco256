#!/bin/bash
# Build and test script for Chaco-256

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Chaco-256 Build and Test Script                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust/Cargo not found. Please install from https://rustup.rs/"
    exit 1
fi

echo "✓ Rust/Cargo found"
echo ""

# Build the project
echo "┌─ Building Chaco-256 ─────────────────────────────────────┐"
cargo build --release
echo "✓ Build successful"
echo ""

# Run tests
echo "┌─ Running Tests ──────────────────────────────────────────┐"
cargo test --release
echo "✓ All tests passed"
echo ""

# Run examples
echo "┌─ Running Examples ───────────────────────────────────────┐"
echo "Running basic_usage example..."
cargo run --release --example basic_usage
echo ""

echo "Running comprehensive_demo example..."
cargo run --release --example comprehensive_demo
echo ""

# Run Python reference implementation
if command -v python3 &> /dev/null; then
    echo "┌─ Running Python Reference Implementation ────────────────┐"
    python3 chaco256.py
    echo ""
    
    echo "┌─ Generating Test Vectors ────────────────────────────────┐"
    python3 examples/generate_test_vectors.py > test_vectors.txt
    echo "✓ Test vectors saved to test_vectors.txt"
    echo ""
else
    echo "⚠ Python3 not found, skipping Python tests"
    echo ""
fi

# Run benchmarks (optional)
read -p "Run benchmarks? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "┌─ Running Benchmarks ─────────────────────────────────────┐"
    cargo bench
    echo ""
fi

echo "╔════════════════════════════════════════════════════════════╗"
echo "║              All Tests Completed Successfully!             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  • Read QUICKSTART.md for usage examples"
echo "  • Read SPECIFICATION.md for technical details"
echo "  • Read SECURITY_ANALYSIS.md for security discussion"
echo "  • Run 'cargo doc --open' for API documentation"
echo ""
echo "⚠ Remember: Chaco-256 is experimental. Use AES-256-GCM or"
echo "  ChaCha20-Poly1305 for production systems."
