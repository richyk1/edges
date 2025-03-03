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


def filter_bad_strings(strings: List[str]) -> Tuple[List[str], List[str], List[str]]:
    """
    Filter out unwanted parts of strings (e.g., Jenkins paths) or normalize them.
    Returns:
        - Filtered strings
        - Unmatched Jenkins paths (strings containing Jenkins paths but not matching regex)
        - Non-Jenkins strings kept as-is
    """
    good_strings = []
    unmatched_jenkins = []
    non_jenkins = []

    pattern_unix = re.compile(r"[^\/]+(?:\/[^\/]+)*\/([^\/]+\.(?:h|cpp|c|ipp))(.*)")
    pattern_win = re.compile(
        r"[DdCc]:\\(?:[\w\s\.\-]+\\)*([\w\s.\-]+\.(?:c|cpp|h|ipp))(.*)"
    )
    pattern_win_mnt = re.compile(r"([C:\\mnt[^\\]+\\)*([^\\]+\.cpp)")

    for s in strings:
        if "jenkins" in s:
            match = pattern_unix.search(s)
            if match:
                good_strings.append(match.group(1) + match.group(2))
            else:
                match = pattern_win.search(s)

                if match:
                    good_strings.append(match.group(1) + match.group(2))
                else:
                    unmatched_jenkins.append(s)
        else:
            good_strings.append(s)
            non_jenkins.append(s)

    return good_strings, unmatched_jenkins, non_jenkins


def find_similar_functions(
    file1: List[Dict], file2: List[Dict], threshold: int = 2
) -> Dict:
    """
    Find functions with similar string references between two sets of functions.
    Assumes that string_refs in file1 and file2 have already been filtered.
    """
    file1_index = defaultdict(list)
    file2_index = defaultdict(list)

    # Index file1 by the set of strings
    for func in file1:
        string_set = frozenset(func["string_refs"])
        file1_index[string_set].append(func["name"])

    # Index file2 by the set of strings
    for func in file2:
        string_set = frozenset(func["string_refs"])
        file2_index[string_set].append(func["name"])

    # Compare sets to find matches with at least `threshold` common items
    matches = {}

    file1_items = list(file1_index.items())
    for set1, names1 in tqdm(file1_items, desc="Comparing sets from file1"):
        for set2, names2 in file2_index.items():
            common = set1 & set2
            if len(common) >= threshold:
                key = (tuple(names1), tuple(names2))
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

        # Pre-process data to collect filtered strings and unmatched info
        all_unmatched_jenkins = []
        all_non_jenkins = []

        # Process mac_data
        mac_data_filtered = []
        for func in mac_data:
            filtered, unmatched_j, non_j = filter_bad_strings(func["string_refs"])
            mac_data_filtered.append({"name": func["name"], "string_refs": filtered})
            all_unmatched_jenkins.extend(unmatched_j)
            all_non_jenkins.extend(non_j)

        # Process win_data
        win_data_filtered = []
        for func in win_data:
            filtered, unmatched_j, non_j = filter_bad_strings(func["string_refs"])
            win_data_filtered.append({"name": func["name"], "string_refs": filtered})
            all_unmatched_jenkins.extend(unmatched_j)
            all_non_jenkins.extend(non_j)

        # Save unmatched strings info
        unmatched_output = {
            "unmatched_jenkins_paths": all_unmatched_jenkins,
            "non_jenkins_strings": all_non_jenkins,
        }
        base_name = os.path.basename(f)
        unmatched_file = os.path.join(
            "unmatched_strings", base_name.replace("_mac_", "_unmatched_")
        )
        with open(unmatched_file, "w", encoding="utf-8") as f_out:
            json.dump(unmatched_output, f_out, indent=2, ensure_ascii=False)
        print(f"Unmatched strings saved to {unmatched_file}")

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
