import json
from collections import defaultdict
from typing import List, Dict, Tuple
import argparse


def analyze_prefixes(
    data: List[Dict], delimiters: str = "_:\\/", max_depth: int = 2, min_count: int = 5
) -> Dict[str, Tuple[int, List[str]]]:
    """
    Analyze string references for common prefixes.

    Args:
        data: JSON data containing string references
        delimiters: Characters to use for splitting strings into segments
        max_depth: Maximum number of initial segments to consider as prefix
        min_count: Minimum occurrence count to consider a prefix significant

    Returns:
        Dictionary of prefixes with count and example strings
    """
    prefix_stats = defaultdict(lambda: {"count": 0, "examples": set()})
    all_strings = [s for func in data for s in func["string_refs"]]

    for string in all_strings:
        # Split string using any of the delimiters
        segments = []
        current_segment = []
        for char in string:
            if char in delimiters:
                if current_segment:
                    segments.append("".join(current_segment))
                    current_segment = []
            else:
                current_segment.append(char)
        if current_segment:
            segments.append("".join(current_segment))

        # Generate prefixes of different depths
        for depth in range(1, min(max_depth + 1, len(segments) + 1)):
            prefix = "_".join(segments[:depth])
            prefix_stats[prefix]["count"] += 1
            prefix_stats[prefix]["examples"].add(string)
            if len(prefix_stats[prefix]["examples"]) > 5:  # Keep only 5 examples
                prefix_stats[prefix]["examples"].pop()

    # Filter and format results
    results = {}
    for prefix, stats in prefix_stats.items():
        if stats["count"] >= min_count:
            results[prefix] = (
                stats["count"],
                sorted(stats["examples"], key=lambda x: len(x))[
                    :5
                ],  # Get shortest examples
            )

    return dict(sorted(results.items(), key=lambda x: x[1][0], reverse=True))


def main():
    parser = argparse.ArgumentParser(description="Analyze string prefixes in JSON data")
    parser.add_argument("input_file", help="Path to JSON file with string references")
    parser.add_argument(
        "--delimiters",
        default="_:\\/",
        help='Characters used to split strings into segments (default: "_:\/")',
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum number of initial segments to consider (default: 2)",
    )
    parser.add_argument(
        "--min-count",
        type=int,
        default=5,
        help="Minimum occurrences to show prefix (default: 5)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Number of top prefixes to show (default: 20)",
    )

    args = parser.parse_args()

    with open(args.input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    prefixes = analyze_prefixes(data, args.delimiters, args.max_depth, args.min_count)

    print(f"Top {args.top} common prefixes:")
    print("-" * 60)
    for i, (prefix, (count, examples)) in enumerate(list(prefixes.items())[: args.top]):
        print(f"{i+1}. {prefix} (count: {count})")
        print("   Examples:")
        for ex in examples:
            print(f"   - {ex[:80]}{'...' if len(ex) > 80 else ''}")
        print()


if __name__ == "__main__":
    main()
