#!/bin/bash

# Navigate to the directory containing main.py (edges folder)
cd "$(dirname "$0")"  # Adjust if the script is not in the same directory as main.py

# Find all .i64 files under eu4_downloader and process them
find ./eu4_downloader -type f -name "*.i64" | while read -r binary; do
    # Extract base name (e.g., "eu4_win_1.35.0" from path)
    binary_base=$(basename "$binary" .i64)

    # Construct expected GCG JSON path
    gcg_file="./gcgs/gcg_${binary_base}.json"

    # Only process if JSON doesn't exist
    if [ ! -f "$gcg_file" ]; then
        echo "Processing: $binary (No existing GCG found)"
        BINARY_PATH="$binary" python main.py --mode export
    else
        echo "Skipping: $binary (GCG exists at $gcg_file)"
    fi
done