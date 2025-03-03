#!/bin/bash


# Find all Windows binaries and process them
find eu4_downloader -type f -name '*mac*.i64' -print0 | while IFS= read -r -d $'\0' binary; do
    # Get base name for output prefix (e.g., "eu4_win_1.35.0")
    prefix=$(basename "$binary" .i64)

    # Set binary path for this iteration
    export BINARY_PATH="$binary"

    # Run the analysis with filename-based prefix
    echo "Processing $binary..."
    python stringsearch.py --prefix "$prefix"

    echo "----------------------------------------"
done

echo "All Windows binaries processed."