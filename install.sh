#!/bin/bash

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Create a symbolic link for HFSK
ln -s "$(pwd)/HFSKv2.py" /usr/local/bin/HFSK

echo "Installation completed. You can now use 'HFSK' from the terminal."
