#!/bin/bash

# Build TQUIC as a Shared Library for Mojo FFI
# This script modifies TQUIC's Cargo configuration to build a shared library (.so)
# instead of the default static library (.a)

set -e  # Exit on error

echo "================================"
echo "Building TQUIC Shared Library"
echo "================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TQUIC_DIR="$PROJECT_ROOT/deps/tquic"

echo "Project root: $PROJECT_ROOT"
echo "TQUIC directory: $TQUIC_DIR"
echo ""

# Check if TQUIC directory exists
if [ ! -d "$TQUIC_DIR" ]; then
    echo -e "${RED}Error: TQUIC directory not found at $TQUIC_DIR${NC}"
    echo "Please run: git submodule update --init --recursive"
    exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo not found${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites check passed${NC}"
echo ""

# Navigate to TQUIC directory
cd "$TQUIC_DIR"

# Backup original Cargo.toml
if [ ! -f "Cargo.toml.backup" ]; then
    echo "Creating backup of Cargo.toml..."
    cp Cargo.toml Cargo.toml.backup
fi

# Modify Cargo.toml to build as shared library
echo "Configuring TQUIC to build as shared library..."

# Check if [lib] section already exists
if grep -q '^\[lib\]' Cargo.toml; then
    echo "  [lib] section already exists, modifying..."
    # Use awk to replace crate-type line
    awk '/^\[lib\]/{print; getline; print "crate-type = [\"cdylib\", \"rlib\"]"; next}1' \
        Cargo.toml > Cargo.toml.tmp
    mv Cargo.toml.tmp Cargo.toml
else
    echo "  Adding [lib] section..."
    # Add [lib] section before [dependencies] if not present
    awk '/^\[dependencies\]/{print "[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n"; print; next}1' \
        Cargo.toml > Cargo.toml.tmp
    mv Cargo.toml.tmp Cargo.toml
fi

# Verify the modification
if grep -q 'crate-type.*cdylib' Cargo.toml; then
    echo -e "${GREEN}✓ Cargo.toml configured for shared library build${NC}"
else
    echo -e "${YELLOW}Warning: Could not verify Cargo.toml modification${NC}"
    echo "Please manually add to Cargo.toml:"
    echo ""
    echo "[lib]"
    echo "crate-type = [\"cdylib\", \"rlib\"]"
    echo ""
fi

# Build TQUIC with FFI feature
echo ""
echo "Building TQUIC (this may take a few minutes)..."
echo ""

# Check if BoringSSL submodule is initialized
if [ ! -d "deps/boringssl/.git" ]; then
    echo "Initializing BoringSSL submodule..."
    git submodule update --init --recursive
fi

# Build with release profile and FFI feature
cargo build --release -F ffi

# Check if build was successful
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Build successful!${NC}"
    echo ""

    # Check for shared library
    SO_FILE="target/release/libtquic.so"
    if [ -f "$SO_FILE" ]; then
        echo -e "${GREEN}✓ Shared library created: $SO_FILE${NC}"
        echo ""
        echo "Library information:"
        echo "  Size: $(du -h "$SO_FILE" | cut -f1)"
        echo "  Type: $(file "$SO_FILE")"
        echo ""

        # List exported symbols (first 10)
        echo "Sample exported symbols:"
        if command -v nm &> /dev/null; then
            nm -D "$SO_FILE" | grep " T " | head -10 | awk '{print "  " $3}'
        else
            echo "  (nm not available, skipping symbol list)"
        fi

    else
        echo -e "${YELLOW}Warning: Shared library not found at $SO_FILE${NC}"
        echo "Available files in target/release:"
        ls -lh target/release/libtquic.* 2>/dev/null || echo "  No libtquic files found"
    fi

else
    echo -e "${RED}✗ Build failed${NC}"
    echo "Please check the error messages above"
    exit 1
fi

# Return to original directory
cd "$PROJECT_ROOT"

echo ""
echo "================================"
echo "Build Complete!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Verify the library: ldd $TQUIC_DIR/target/release/libtquic.so"
echo "2. Run Mojo example: cd mojo && mojo http3_server.mojo 0.0.0.0 4433"
echo ""
echo "To restore original Cargo.toml:"
echo "  cp $TQUIC_DIR/Cargo.toml.backup $TQUIC_DIR/Cargo.toml"
echo ""
