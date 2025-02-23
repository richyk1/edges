#!/usr/bin/env python3

import os

from dotenv import load_dotenv

load_dotenv()

import argparse
import logging
import time

# Set up logger.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def get_function_signature(func_addr, seg_start, seg_end, min_bytes=4, max_bytes=256):
    import ida_bytes
    import ida_ua
    import idaapi
    import idautils

    """
    Generate a signature for the function at func_addr that is as small as possible
    while uniquely matching the function start within [seg_start, seg_end).
    """
    func = idaapi.get_func(func_addr)
    if not func:
        raise ValueError(f"Function at {func_addr:#x} not found.")

    all_bytes = bytearray()
    insn = ida_ua.insn_t()

    # Gather up to max_bytes of normalized instruction bytes
    for ea in idautils.FuncItems(func.start_ea):
        if len(all_bytes) >= max_bytes:
            break

        if ida_ua.decode_insn(insn, ea) == 0:
            raise ValueError(f"Failed to decode instruction at {ea:#x}")

        insn_bytes = ida_bytes.get_bytes(ea, insn.size)
        if insn_bytes is None:
            continue
        bytes_ = bytearray(insn_bytes)

        # Zero out immediate/displacement bytes to account for relocation variability
        for op in insn.ops:  # type: ignore
            if op.type == ida_ua.o_void:
                break
            if op.type in (
                ida_ua.o_near,
                ida_ua.o_far,
                ida_ua.o_imm,
                ida_ua.o_mem,
                ida_ua.o_phrase,
                ida_ua.o_displ,
            ):
                if op.offb == idaapi.BADADDR:
                    continue

                FL_RIPREL = 0x20  # x86_64 RIP-relative flag
                is_rip_relative = op.type == ida_ua.o_displ and (
                    op.specflag1 & FL_RIPREL
                )
                if op.type in (ida_ua.o_near, ida_ua.o_far) or is_rip_relative:
                    size = 4
                else:
                    size = ida_ua.get_dtype_size(op.dtype)
                    if size < 1:
                        size = 4

                end_index = op.offb + size
                if end_index > len(bytes_):
                    end_index = len(bytes_)
                bytes_[op.offb : end_index] = b"\x00" * (end_index - op.offb)

        remaining = max_bytes - len(all_bytes)
        all_bytes.extend(bytes_[:remaining])
        if len(all_bytes) >= max_bytes:
            break

    if not all_bytes:
        raise ValueError(f"Function at {func_addr:#x} has no instructions.")

    # Try progressively longer prefixes until a unique signature is found
    for n in range(max(min_bytes, 1), len(all_bytes) + 1):
        candidate = []
        for b in all_bytes[:n]:
            candidate.append(f"{b:02X}" if b != 0 else "?")
        # Optionally, remove trailing wildcards (they are less useful)
        while candidate and candidate[-1] == "?":
            candidate.pop()
        pattern = " ".join(candidate)
        matches = signature_search(pattern, seg_start, seg_end)
        if len(matches) == 1:
            return pattern

    # If none of the shorter patterns are unique, return the full pattern.
    candidate = [f"{b:02X}" if b != 0 else "?" for b in all_bytes]
    while candidate and candidate[-1] == "?":
        candidate.pop()
    return " ".join(candidate)


def signature_search(signature: str, start_ea: int, end_ea: int) -> list[int]:
    import ida_bytes
    import idaapi

    """Search for functions matching the given signature using find_bytes."""

    # Convert pattern string to byte sequence and mask
    byte_pattern = bytearray()
    mask = bytearray()
    for part in signature.split():
        if part == "?":
            byte_pattern.append(0x00)
            mask.append(0x00)  # Wildcard byte
        else:
            byte_pattern.append(int(part, 16))
            mask.append(0xFF)  # Fixed byte

    matches = []
    current_ea = start_ea
    pattern_len = len(byte_pattern)

    while current_ea <= end_ea - pattern_len:
        # Use find_bytes for faster searching with mask support
        found_ea = ida_bytes.find_bytes(
            bytes(byte_pattern),
            current_ea,
            range_end=end_ea,
            mask=bytes(mask),
            flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
        )

        if found_ea == idaapi.BADADDR:
            break

        # Verify we're at function start
        func = idaapi.get_func(found_ea)
        if func and func.start_ea == found_ea:
            matches.append(found_ea)
            if len(matches) > 1:  # Early exit for non-unique
                return []

        # Skip past this match position
        current_ea = found_ea + 1

    return matches


def main_check():
    import idautils
    import idc

    # TESTING START
    st = time.monotonic()

    start_ea = None
    end_ea = None

    # Search in all executable segments (not just the first .text/__text)
    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        if seg_name not in [".text", "__text"]:
            continue  # Skip non-code segments

        start_ea = idc.get_segm_start(seg_start)
        end_ea = idc.get_segm_end(seg_start)

    if start_ea is None or end_ea is None:
        raise ValueError("Failed to find .text (__text) segment")
    logger.info(f"Searching in segment @ {start_ea:x}-{end_ea:x}")

    signature = get_function_signature(0x140362B80, start_ea, end_ea)
    logger.info(f"Signature: {signature}")

    et = time.monotonic()
    logger.info(f"Time taken to search for all signatures: {et - st:.2f} seconds")


# ---------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Manage a global call graph for IDA.")
    parser.add_argument(
        "--mode",
        choices=["check"],
        required=True,
        help="To be filled...",
    )
    parser.add_argument(
        "--filepath",
        type=str,
        default=None,
        help="Path to the JSON file containing the global call graph",
    )

    args = parser.parse_args()

    if args.mode == "check":
        main_check()
        return
    else:
        raise ValueError(f"Unknown mode: {args.mode}")


if __name__ == "__main__":
    from headless_ida import HeadlessIda

    headlessida = HeadlessIda(
        os.getenv("IDA_DIR"),
        os.getenv("BINARY_PATH"),
    )

    logger.info("Starting...")
    main()
