import argparse
import json
import os
import glob
import re
from collections import defaultdict
from typing import List, Dict, Tuple
from tqdm import tqdm
import orjson


def load_json_file(file_path: str) -> List[Dict]:
    """Load JSON data from a file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return orjson.loads(f.read())


def find_similar_functions(
    file1: List[Dict], file2: List[Dict], threshold: int = 2
) -> Dict:
    """
    Find functions with similar string references using an inverted index for efficiency.
    """
    # Index file1 by the set of strings
    file1_index = defaultdict(list)
    for func in file1:
        string_set = frozenset(func["string_refs"])
        file1_index[string_set].append(func["name"])

    # Index file2 by the set of strings
    file2_index = defaultdict(list)
    for func in file2:
        string_set = frozenset(func["string_refs"])
        file2_index[string_set].append(func["name"])

    # Build inverted index for file2: map each string to sets containing it
    file2_string_to_sets = defaultdict(set)
    for s_set in file2_index:
        for s in s_set:
            file2_string_to_sets[s].add(s_set)

    matches = {}

    # Compare each set in file1 with relevant sets in file2
    for set1, names1 in tqdm(file1_index.items(), desc="Processing file1 sets"):
        # Collect all sets in file2 that share any string with set1
        candidate_sets = set()
        for s in set1:
            candidate_sets.update(file2_string_to_sets.get(s, set()))

        # Check each candidate set in file2
        for set2 in candidate_sets:
            common = set1 & set2
            if len(common) >= threshold:
                names2 = tuple(file2_index[set2])
                key = (tuple(names1), names2)
                # Update matches if this pair has higher or equal count
                current = matches.get(key, {"count": 0})
                if len(common) > current["count"]:
                    matches[key] = {
                        "common_strings": list(common),
                        "count": len(common),
                    }

    return matches


def main():
    f_in_string_refs = glob.glob(os.path.join("string_refs", "*_mac_*.json"))
    os.makedirs("unmatched_strings", exist_ok=True)

    for f in tqdm(f_in_string_refs, desc="Processing file pairs"):
        aggregated = {}
        win_file = f.replace("mac", "win")

        if not os.path.exists(win_file):
            print(f"Windows file {win_file} not found. Skipping.")
            continue

        try:
            win_data = load_json_file(win_file)
            mac_data = load_json_file(f)
        except Exception as e:
            print(f"Error loading files: {e}")
            continue

        # Process mac_data
        mac_data_filtered = []
        for func in mac_data:
            mac_data_filtered.append(
                {"name": func["name"], "string_refs": func["string_refs"]}
            )

        # Process win_data
        win_data_filtered = []
        for func in win_data:
            win_data_filtered.append(
                {"name": func["name"], "string_refs": func["string_refs"]}
            )

        # Find similar functions with pre-filtered data
        partial_matches = find_similar_functions(
            mac_data_filtered, win_data_filtered, 2
        )

        # Aggregate results as before
        for (mac_funcs, win_funcs), details in partial_matches.items():
            if len(win_funcs) != 1:
                continue

            mac_funcs_sorted = tuple(sorted(mac_funcs))
            unique_win_func = win_funcs[0]

            if mac_funcs_sorted not in aggregated:
                aggregated[mac_funcs_sorted] = {
                    "file1_functions": list(mac_funcs_sorted),
                    "file2_functions": set(),
                    "common_strings": set(details["common_strings"]),
                    "common_strings_count": len(details["common_strings"]),
                }
            else:
                aggregated[mac_funcs_sorted]["common_strings"].update(
                    details["common_strings"]
                )
                aggregated[mac_funcs_sorted]["common_strings_count"] = len(
                    aggregated[mac_funcs_sorted]["common_strings"]
                )

            aggregated[mac_funcs_sorted]["file2_functions"].add(unique_win_func)

        # Prepare final output
        final_output = []
        for mac_funcs_sorted, data in aggregated.items():
            if len(data["file2_functions"]) != 1:
                continue
            if "sub_" in data["file1_functions"][0]:
                continue
            final_output.append(
                {
                    "file1_functions": data["file1_functions"],
                    "file2_functions": sorted(data["file2_functions"]),
                    "common_strings": sorted(data["common_strings"]),
                    "common_strings_count": data["common_strings_count"],
                }
            )

        print(
            f"Found {len(final_output)} similar function sets in {os.path.basename(f)}"
        )

        # Write output file
        output_file = f.replace("mac", "shared")
        try:
            with open(output_file, "w", encoding="utf-8") as f_out:
                json.dump(final_output, f_out, indent=2)
            print(f"Results saved to {output_file}")
        except Exception as e:
            print(f"Error writing to {output_file}: {e}")


if __name__ == "__main__":
    main()
