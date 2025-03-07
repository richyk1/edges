#!/bin/bash

for file in gcgs/*win*.json; do
    # Get the base filename without extension
    base=$(basename "$file" .json)

    # Extract the operating system and version from the filename.
    # Expected pattern: gcg_eu4_<os>_<version>.json
    os=$(echo "$base" | cut -d'_' -f3)
    version=$(echo "$base" | cut -d'_' -f4)

    # Build the save path dynamically
    SAVE_PATH="cgn/eu4_${os}_${version}"

    # Skip if conversion already exists
    if [ -d "$SAVE_PATH" ]; then
        echo "Skipping $file - conversion already exists at $SAVE_PATH"
        continue
    fi

    # Construct binary path based on the OS and version.
    # Example: eu4_downloader/eu4_1.33.0/eu4_lin_1.33.0.i64
    BINARY_PATH="eu4_downloader/eu4_${version}/eu4_${os}_${version}.i64"

    # Log the processing details
    echo "Processing $file with OS ${os} and version ${version}"

    # Run the conversion command using the specified binary path
    BINARY_PATH="$BINARY_PATH" python main.py --mode convert --save-path "$SAVE_PATH" --filepath "$file"
done

for file in gcgs/*lin*.json; do
    # Get the base filename without extension
    base=$(basename "$file" .json)

    # Extract the operating system and version from the filename.
    # Expected pattern: gcg_eu4_<os>_<version>.json
    os=$(echo "$base" | cut -d'_' -f3)
    version=$(echo "$base" | cut -d'_' -f4)

    # Build the save path dynamically
    SAVE_PATH="cgn/eu4_${os}_${version}"

    # Skip if conversion already exists
    if [ -d "$SAVE_PATH" ]; then
        echo "Skipping $file - conversion already exists at $SAVE_PATH"
        continue
    fi

    # Construct binary path based on the OS and version.
    # Example: eu4_downloader/eu4_1.33.0/eu4_lin_1.33.0.i64
    BINARY_PATH="eu4_downloader/eu4_${version}/eu4_${os}_${version}.i64"

    # Log the processing details
    echo "Processing $file with OS ${os} and version ${version}"

    # Run the conversion command using the specified binary path
    BINARY_PATH="$BINARY_PATH" python main.py --mode convert --save-path "$SAVE_PATH" --filepath "$file"
done

for file in gcgs/*mac*.json; do
    # Get the base filename without extension
    base=$(basename "$file" .json)

    # Extract the operating system and version from the filename.
    # Expected pattern: gcg_eu4_<os>_<version>.json
    os=$(echo "$base" | cut -d'_' -f3)
    version=$(echo "$base" | cut -d'_' -f4)

    # Build the save path dynamically
    SAVE_PATH="cgn/eu4_${os}_${version}"

    # Skip if conversion already exists
    if [ -d "$SAVE_PATH" ]; then
        echo "Skipping $file - conversion already exists at $SAVE_PATH"
        continue
    fi

    # Construct binary path based on the OS and version.
    # Example: eu4_downloader/eu4_1.33.0/eu4_lin_1.33.0.i64
    BINARY_PATH="eu4_downloader/eu4_${version}/eu4_${os}_${version}.i64"

    # Log the processing details
    echo "Processing $file with OS ${os} and version ${version}"

    # Run the conversion command using the specified binary path
    BINARY_PATH="$BINARY_PATH" python main.py --mode convert --save-path "$SAVE_PATH" --filepath "$file"
done
