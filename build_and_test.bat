@echo off
REM Build and test script for Chaco-256 (Windows)

echo ================================================================
echo          Chaco-256 Build and Test Script
echo ================================================================
echo.

REM Check if Rust is installed
where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Rust/Cargo not found. Please install from https://rustup.rs/
    exit /b 1
)

echo [OK] Rust/Cargo found
echo.

REM Build the project
echo ================================================================
echo Building Chaco-256...
echo ================================================================
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo Error: Build failed
    exit /b 1
)
echo [OK] Build successful
echo.

REM Run tests
echo ================================================================
echo Running Tests...
echo ================================================================
cargo test --release
if %ERRORLEVEL% NEQ 0 (
    echo Error: Tests failed
    exit /b 1
)
echo [OK] All tests passed
echo.

REM Run examples
echo ================================================================
echo Running Examples...
echo ================================================================
echo Running basic_usage example...
cargo run --release --example basic_usage
echo.

echo Running comprehensive_demo example...
cargo run --release --example comprehensive_demo
echo.

REM Run Python reference implementation
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo ================================================================
    echo Running Python Reference Implementation...
    echo ================================================================
    python chaco256.py
    echo.
    
    echo ================================================================
    echo Generating Test Vectors...
    echo ================================================================
    python examples\generate_test_vectors.py > test_vectors.txt
    echo [OK] Test vectors saved to test_vectors.txt
    echo.
) else (
    echo [WARNING] Python not found, skipping Python tests
    echo.
)

echo ================================================================
echo          All Tests Completed Successfully!
echo ================================================================
echo.
echo Next steps:
echo   - Read QUICKSTART.md for usage examples
echo   - Read SPECIFICATION.md for technical details
echo   - Read SECURITY_ANALYSIS.md for security discussion
echo   - Run 'cargo doc --open' for API documentation
echo.
echo [WARNING] Remember: Chaco-256 is experimental. Use AES-256-GCM or
echo           ChaCha20-Poly1305 for production systems.
echo.

pause
