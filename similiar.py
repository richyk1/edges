import argparse
import json
import os
import glob
import re
from collections import defaultdict
from typing import List, Dict
from tqdm import tqdm


def load_json_file(file_path: str) -> List[Dict]:
    """Load JSON data from a file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def filter_bad_strings(strings: List[str]) -> List[str]:
    """
    Filter out unwanted parts of strings (e.g., Jenkins paths) or normalize them.
    Adjust as needed for your environment.
    """
    good_strings = []
    pattern_unix = re.compile(r"(/[^\s:]+/)*([^/]+\.cpp)")
    pattern_win = re.compile(r"(D:\\[^\\]+\\)*([^\\]+\.cpp)")

    for s in strings:
        if "/Users/jenkins" in s:
            match = pattern_unix.search(s)
            if match:
                good_strings.append(match.group(2))
        elif "D:\\jenkins" in s:
            match = pattern_win.search(s)
            if match:
                good_strings.append(match.group(2))
        else:
            # Keep the original string
            good_strings.append(s)

    return good_strings


def find_similar_functions(
    file1: List[Dict], file2: List[Dict], threshold: int = 2
) -> Dict:
    """
    Find functions with similar string references between two sets of functions.
    Returns a dictionary with matching function pairs and their common strings.

    Structure of return value:
      {
        (('macFuncA', ...), ('winFuncX', ...)): {
          'common_strings': [...],
          'count': integer
        },
        ...
      }
    """
    file1_index = defaultdict(list)
    file2_index = defaultdict(list)

    # Index file1 by the set of strings
    for func in file1:
        string_set = frozenset(filter_bad_strings(func["string_refs"]))
        file1_index[string_set].append(func["name"])

    # Index file2 by the set of strings
    for func in file2:
        string_set = frozenset(filter_bad_strings(func["string_refs"]))
        file2_index[string_set].append(func["name"])

    # Compare sets to find matches with at least `threshold` common items
    matches = {}

    file1_items = list(file1_index.items())  # to use with tqdm
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
    parser = argparse.ArgumentParser(
        description="Compare one Mac JSON file against many Windows JSON files (one-to-many)."
    )
    parser.add_argument("--mac", required=True, help="Mac JSON file")
    parser.add_argument(
        "--win_dir", required=True, help="Directory of Windows JSON files"
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=2,
        help="Minimum number of common strings required for a function match",
    )
    parser.add_argument(
        "-o", "--output", help="Output JSON file for final aggregated matches"
    )

    args = parser.parse_args()

    # 1) Load Mac data
    mac_data = load_json_file(args.mac)

    # 2) Gather all .json in the Windows directory
    win_files = glob.glob(os.path.join(args.win_dir, "*.json"))
    if not win_files:
        print(f"No .json files found in {args.win_dir}")
        return

    # We'll accumulate results in a dict keyed by the *sorted* tuple of Mac functions:
    # aggregated[mac_func_tuple] = {
    #    "file1_functions": [...],
    #    "file2_functions": set(),        # so we don't get duplicates
    #    "common_strings": set(...),      # union of all common strings found
    #    "common_strings_count": <int>,
    # }
    aggregated = {}

    # 3) Compare the Mac file against each Windows file
    for wfile in tqdm(win_files, desc="Processing Windows JSON files"):
        win_data = load_json_file(wfile)

        partial_matches = find_similar_functions(mac_data, win_data, args.threshold)

        # For each match in partial_matches, we only keep it if:
        #   len(win_funcs) == 1
        # That enforces "the only function in that windows file that has those common strings."
        for (mac_funcs, win_funcs), details in partial_matches.items():
            # If multiple windows functions share exactly the same set of strings, skip
            if len(win_funcs) != 1:
                continue

            # We found exactly one Windows function
            mac_funcs_sorted = tuple(sorted(mac_funcs))
            unique_win_func = win_funcs[0]  # single function in that tuple

            # Insert/update aggregated data
            if mac_funcs_sorted not in aggregated:
                aggregated[mac_funcs_sorted] = {
                    "file1_functions": list(mac_funcs_sorted),
                    "file2_functions": set(),
                    "common_strings": set(details["common_strings"]),
                    "common_strings_count": len(details["common_strings"]),
                }
            else:
                # Union the common strings
                aggregated[mac_funcs_sorted]["common_strings"].update(
                    details["common_strings"]
                )
                aggregated[mac_funcs_sorted]["common_strings_count"] = len(
                    aggregated[mac_funcs_sorted]["common_strings"]
                )

            aggregated[mac_funcs_sorted]["file2_functions"].add(unique_win_func)

    # 4) Convert sets back to lists, finalize the structure
    final_output = []
    for mac_funcs_sorted, data in aggregated.items():
        f2_list = sorted(list(data["file2_functions"]))
        common_strs = sorted(list(data["common_strings"]))
        final_output.append(
            {
                "file1_functions": data["file1_functions"],
                "file2_functions": f2_list,
                "common_strings_count": len(common_strs),
                "common_strings": common_strs,
            }
        )

    # Sort final output by the number of common strings, descending
    final_output.sort(key=lambda x: x["common_strings_count"], reverse=True)

    print(f"\nAggregated results: {len(final_output)} matched Mac-function sets.")

    # 5) Save or print
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(final_output, indent=2))


if __name__ == "__main__":
    main()
