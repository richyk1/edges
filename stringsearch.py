#!/usr/bin/env python3
import os
from collections import defaultdict
from typing import DefaultDict, List, Union

import orjson
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

from headless_ida import HeadlessIda

headlessida = HeadlessIda(
    os.getenv("IDA_DIR"),
    os.getenv("BINARY_PATH"),
)

import argparse
import logging
import time

import ida_nalt
import idautils
import idc
import idaapi
import re
import orjson
from typing import Tuple

# Set up logger.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# Predefined namespaces to exclude
EXCLUDED_NS = {"std::", "boost::", "tbb::", "__acrt", "__crt"}


def get_demangled_name(func_addr: int) -> str | None:
    """Get demangled function name with caching."""
    mangled = idc.get_func_name(func_addr)
    if not mangled:
        return None
    # Check for excluded namespaces in mangled name (GCC/Clang specific)
    if mangled.startswith(("_ZSt", "_ZNSt", "_ZNKSt", "_ZTv", "_ZTh", "_ZTW")):
        return None
    demangled = idc.demangle_name(mangled, idc.get_inf_attr(idc.INF_SHORT_DN))
    if not demangled:
        return None

    if any(ns in demangled for ns in EXCLUDED_NS):
        return ""
    return demangled


def filter_bad_strings(strings: List[str]) -> List[str]:
    """
    Filter out unwanted parts of strings (e.g., Jenkins paths) or normalize them.
    Returns:
        - Filtered strings
        - Unmatched Jenkins paths (strings containing Jenkins paths but not matching regex)
        - Non-Jenkins strings kept as-is
    """
    good_strings = []

    pattern_unix = re.compile(r"[^\/]+(?:\/[^\/]+)*\/([^\/]+\.(?:h|cpp|c|ipp))")
    pattern_win = re.compile(
        r"[DdCc]:\\(?:[\w\s\.\-]+\\)*([\w\s.\-]+\.(?:cpp|c|h|ipp))"
    )

    for s in strings:
        if ".c" in s:
            match = pattern_unix.search(s)
            if match:
                good_strings.append(match.group(1))
            else:
                match = pattern_win.search(s)

                if match:
                    good_strings.append(match.group(1))
        else:
            good_strings.append(s)

    return good_strings


def collect_string_refs(target_func: int | None) -> DefaultDict[int, List[str]]:
    """Collect string references by analyzing cross-references to strings."""
    string_refs: DefaultDict[int, List[str]] = defaultdict(list)

    # Iterate through all strings in the binary
    for s in tqdm(idautils.Strings(), desc="Processing strings"):
        str_ea = s.ea  # type: ignore
        try:
            # Get string content (auto-detects string type)
            content = idc.get_strlit_contents(
                str_ea, strtype=ida_nalt.STRTYPE_TERMCHR
            ).decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, AttributeError):
            continue

        # Process cross-references to this string
        for xref in idautils.XrefsTo(str_ea):
            xref_ea = xref.frm  # type: ignore
            # Skip data references outside code segments
            if not idaapi.is_code(idaapi.get_flags(xref_ea)):
                continue

            # Get containing function
            func = idaapi.get_func(xref_ea)
            if not func:
                continue

            func_addr = func.start_ea
            # Apply target function filter
            if target_func and func_addr != target_func:
                continue

            # Add string to function's references (unique entries only)
            if content not in string_refs[func_addr]:
                string_refs[func_addr].append(content)

    filtered_refs = defaultdict(list)
    for func_addr, strings in string_refs.items():
        filtered_strings, _, _ = filter_bad_strings(strings)
        filtered_refs[func_addr] = filtered_strings

    return filtered_refs


def collect_string_refs_optimized(
    target_func: Union[int, None] = None
) -> DefaultDict[int, List[str]]:
    """Optimized string reference collector with early filtering and efficient storage."""
    # Use sets for O(1) lookups and automatic deduplication
    string_refs: DefaultDict[int, set] = defaultdict(set)

    for s in tqdm(idautils.Strings(), desc="Processing strings"):
        str_ea = s.ea

        # Get string content once per string
        try:
            content = idc.get_strlit_contents(str_ea, strtype=ida_nalt.STRTYPE_TERMCHR)
            if not content:
                continue
            decoded_content = content.decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, AttributeError):
            continue

        # Pre-filter xrefs and batch process
        relevant_funcs = set()
        for xref in idautils.XrefsTo(str_ea):
            xref_ea = xref.frm

            # Fast code segment check
            if not idaapi.is_code(idaapi.get_flags(xref_ea)):
                continue

            # Get containing function once per xref
            func = idaapi.get_func(xref_ea)
            if not func:
                continue

            func_addr = func.start_ea

            # Early target filtering
            if target_func and func_addr != target_func:
                continue

            relevant_funcs.add(func_addr)

        # Batch add to all relevant functions
        for func_addr in relevant_funcs:
            string_refs[func_addr].add(decoded_content)

    filtered_refs = defaultdict(list)
    for func_addr, strings in string_refs.items():
        filtered_refs[func_addr] = filter_bad_strings(strings)

    return filtered_refs


def main_check(target_func: int | None, prefix: str) -> None:
    st = time.monotonic()
    save_path = os.path.join(os.getcwd(), "string_refs")
    os.makedirs(save_path, exist_ok=True)

    # Step 1: Collect string references using optimized method
    string_refs = collect_string_refs_optimized(target_func)
    logger.info(f"Collected {len(string_refs)} functions with string references")

    # Step 2: Process functions with string references
    all_functions = []
    processed = 0
    for func_addr, strings in tqdm(string_refs.items(), desc="Analyzing functions"):
        # Basic function size check (faster than instruction counting)
        func = idaapi.get_func(func_addr)
        if not func:
            continue

        size = func.end_ea - func.start_ea
        # Skip functions with size smaller than 40 bytes
        if size < 40:
            continue

        demangled_name = get_demangled_name(func_addr)

        if not demangled_name:
            demangled_name = f"sub_{func_addr:X}"

        # Create output structure
        func_data = {"name": demangled_name, "string_refs": strings}
        all_functions.append(func_data)
        processed += 1

    # Save all results to a single JSON file
    if all_functions:
        output_path = os.path.join(save_path, f"{prefix}_string_refs.json")
        try:
            with open(output_path, "wb") as f:
                f.write(orjson.dumps(all_functions))
        except OSError as e:
            logger.error(f"Error saving {output_path}: {e}")
    else:
        logger.warning("No functions with string references found")

    et = time.monotonic()
    logger.info(
        f"Processed {processed} functions with strings in {et - st:.2f} seconds"
    )


def main():
    parser = argparse.ArgumentParser(description="Optimized string reference analyzer.")
    parser.add_argument(
        "--target-func",
        type=lambda x: int(x, 0),
        default=None,
        help="Specific function address to analyze",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="",
        help="Prefix to add to the output JSON file",
    )
    args = parser.parse_args()
    main_check(args.target_func, args.prefix)


if __name__ == "__main__":
    logger.info("Starting optimized analysis...")
    main()
