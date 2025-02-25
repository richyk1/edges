#!/bin/bash

# Navigate to the directory containing main.py (edges folder)
cd "$(dirname "$0")"  # Adjust if the script is not in the same directory as main.py

# Find all .i64 files under eu4_downloader and process them
find ./eu4_downloader -type f -name "*.i64" | while read -r binary; do
    echo "Processing: $binary"
    BINARY_PATH="$binary" python main.py --mode export
done
