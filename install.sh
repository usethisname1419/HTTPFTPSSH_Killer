#!/bin/bash

# Define the script location
SCRIPT_SOURCE="HFSKv5.py"  # Update this with the actual path to HFSKv2.py

# Copy the script to /usr/local/bin
sudo cp "$SCRIPT_SOURCE" /usr/local/bin/HFSK

# Make the script executable
sudo chmod +x /usr/local/bin/HFSK

echo "HFSK installed successfully! You can run it by typing 'HFSK' from the terminal."
