import argparse
import json
from collections import defaultdict
from typing import List, Dict, Set
import re


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
    for s in strings:
        if "/Users/jenkins" in s:
            # Capture *.cpp file names (UNIX-like paths)
            pattern = re.compile(r"(/[^\s:]+/)*([^/]+\.cpp)")
            match = pattern.search(s)
            if match:
                good_strings.append(match.group(2))
        elif "D:\\jenkins" in s:
            # Capture *.cpp file names (Windows-like paths)
            pattern = re.compile(r"(D:\\[^\\]+\\)*([^\\]+\.cpp)")
            match = pattern.search(s)
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
    Find functions with similar string references between two files.
    Returns a dictionary with matching function pairs and their common strings.

    Structure of return value:
      {
        (('funcA', 'funcB'), ('funcX',)): {
          'common_strings': [...],
          'count': integer
        },
        ...
      }
    """
    file1_index = defaultdict(list)
    file2_index = defaultdict(list)

    # Index file1
    for func in file1:
        # Normalize strings
        string_set = frozenset(filter_bad_strings(func["string_refs"]))
        file1_index[string_set].append(func["name"])

    # Index file2
    for func in file2:
        # Normalize strings
        string_set = frozenset(filter_bad_strings(func["string_refs"]))
        file2_index[string_set].append(func["name"])

    # Compare sets to find matches with at least `threshold` common items
    matches = defaultdict(dict)
    for set1, names1 in file1_index.items():
        for set2, names2 in file2_index.items():
            common = set1 & set2
            if len(common) >= threshold:
                key = (tuple(names1), tuple(names2))
                matches[key]["common_strings"] = list(common)
                matches[key]["count"] = len(common)

    return matches


def bipartite_match(graph: Dict[str, List[str]]) -> Dict[str, str]:
    """
    Given a bipartite graph represented as:
        graph[file1_func] = [file2_func1, file2_func2, ...]
    Returns a dictionary 'match' where:
        match[file2_func] = file1_func
    showing the maximum matching from the perspective of file2 functions.
    """
    match = {}  # file2_func -> file1_func

    def can_match(f1_func, visited):
        """
        Try to match 'f1_func' (or improve an existing match) via DFS.
        """
        for f2_func in graph[f1_func]:
            if f2_func in visited:
                continue
            visited.add(f2_func)
            # If 'f2_func' is free or we can re-match the file1_func
            # that currently occupies 'f2_func'
            if f2_func not in match or can_match(match[f2_func], visited):
                match[f2_func] = f1_func
                return True
        return False

    for f1_func in graph:
        visited = set()
        can_match(f1_func, visited)

    return match


def filter_one_to_one_matches(output_list: List[Dict]) -> List[Dict]:
    """
    1) Keep only entries that have exactly 1 file1_functions and 1 file2_functions.
    2) Build a bipartite graph and run maximum bipartite matching.
    3) Return only the edges used in the matching.
    """
    one_to_one_edges = []
    edge_lookup = {}

    # 1) Filter
    for item in output_list:
        if len(item["file1_functions"]) == 1 and len(item["file2_functions"]) == 1:
            f1 = item["file1_functions"][0]
            f2 = item["file2_functions"][0]
            one_to_one_edges.append((f1, f2, item))

    # 2) Build bipartite graph
    graph = defaultdict(list)
    for f1, f2, item in one_to_one_edges:
        graph[f1].append(f2)
        edge_lookup[(f1, f2)] = item

    # Run matching
    match_result = bipartite_match(graph)  # match_result[f2] = f1

    # 3) Keep only matched edges
    final = []
    for f2, f1 in match_result.items():
        final.append(edge_lookup[(f1, f2)])
    return final


def main():
    parser = argparse.ArgumentParser(
        description="Compare JSON files for function-based string matches and list unmatched strings."
    )
    parser.add_argument("file1", help="First JSON file")
    parser.add_argument("file2", help="Second JSON file")
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=2,
        help="Minimum number of common strings required for a function match",
    )
    parser.add_argument(
        "-o", "--output", help="Output JSON file name for matched functions"
    )
    parser.add_argument(
        "--unmatched1",
        default="file1_unmatched_strings.txt",
        help="Output text file for unmatched strings in file1",
    )
    parser.add_argument(
        "--unmatched2",
        default="file2_unmatched_strings.txt",
        help="Output text file for unmatched strings in file2",
    )

    args = parser.parse_args()

    # Load JSON data
    data1 = load_json_file(args.file1)
    data2 = load_json_file(args.file2)

    # 1) Find similar (matched) functions
    matches = find_similar_functions(data1, data2, args.threshold)

    # 2) Prepare output for matched functions
    output = []
    for (file1_funcs, file2_funcs), details in matches.items():
        output.append(
            {
                "file1_functions": file1_funcs,
                "file2_functions": file2_funcs,
                "common_strings_count": details["count"],
                "common_strings": details["common_strings"],
            }
        )

    # Sort by number of common strings (descending)
    output.sort(key=lambda x: x["common_strings_count"], reverse=True)

    # 3) Filter to keep only one-to-one matches
    final_output = filter_one_to_one_matches(output)

    # (Optional) You could re-sort final_output by count if you prefer
    final_output.sort(key=lambda x: x["common_strings_count"], reverse=False)

    print(f"Found {len(final_output)} matched functions")

    # 4) Write out matched function data (JSON)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=2)
        print(f"Match results saved to {args.output}")
    else:
        print(json.dumps(final_output, indent=2))


if __name__ == "__main__":
    main()
