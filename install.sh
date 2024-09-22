#!/bin/bash

# Define the installation directory and script location
INSTALL_DIR="$HOME/.local/bin"
SCRIPT_SOURCE="HFSKv2.py"  # Update this with the actual path to HFSK.py

# Create the installation directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Copy the script to the installation directory
cp "$SCRIPT_SOURCE" "$INSTALL_DIR/HFSK"

# Make the script executable
chmod +x "$INSTALL_DIR/HFSK"

# Add the installation directory to PATH if not already included
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.bashrc"
    echo "Installation complete! Please run 'source ~/.bashrc' to update your PATH."
else
    echo "HFSK installed successfully! You can run it by typing 'HFSK'."
fi
