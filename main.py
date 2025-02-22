#!/usr/bin/env python3

import os
from dotenv import load_dotenv

load_dotenv()

from headless_ida import HeadlessIda

headlessida = HeadlessIda(
    os.getenv("IDA_DIR"),
    os.getenv("BINARY_PATH"),
)

import idautils
import idaapi
import idc
import ida_ua
import ida_bytes
import ida_nalt

import argparse
import datetime
import logging
import rustworkx as rx
import orjson
import hashlib
import time
import random

from typing import Set
from functools import lru_cache
from tqdm import tqdm
from pathlib import Path


# Set up logger.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# Set up an output directory.
SAVE_PATH = os.getcwd()
os.makedirs(SAVE_PATH, exist_ok=True)


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------
@lru_cache(maxsize=None)
def demangle_function_name(name: str) -> str:
    disable_mask = idc.get_inf_attr(idc.INF_SHORT_DN)
    demangled = idc.demangle_name(name, disable_mask)
    return demangled if demangled is not None else name


# linter goes off on .frm because its not parsing the c++ proxy function correctly
def get_callers(func_addr: int) -> Set[int]:
    return {
        idc.get_func_attr(xref.frm, idc.FUNCATTR_START)  # type: ignore
        for xref in idautils.XrefsTo(func_addr, idaapi.XREF_USER)
        if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF)  # type: ignore
        and idc.get_func_attr(xref.frm, idc.FUNCATTR_START) != idc.BADADDR  # type: ignore
    }


def get_callees(func_addr: int) -> Set[int]:
    callees = set()
    func = idaapi.get_func(func_addr)
    if not func:
        logger.error(f"[-] Function at {hex(func_addr)} not found.")
        return callees

    for insn_addr in idautils.FuncItems(func_addr):
        if idc.print_insn_mnem(insn_addr) == "call":
            call_target = idc.get_operand_value(insn_addr, 0)
            func_start = idc.get_func_attr(call_target, idc.FUNCATTR_START)
            if func_start != idc.BADADDR:
                callees.add(func_start)
    return callees


def get_instruction_count_bb(func_addr: int) -> int:
    func = idaapi.get_func(func_addr)
    return sum(
        1
        for head in idautils.Heads(func.start_ea, func.end_ea)
        if idc.is_code(idc.get_full_flags(head))
    )


def get_num_local_vars(func_addr: int) -> int:
    try:
        frame_id = idc.get_frame_id(func_addr)
        return sum(
            1 for member in idautils.StructMembers(frame_id) if "var" in member[1]
        )
    except Exception as e:
        logger.error(f"[-] Error getting local variables for 0x{func_addr:x}: {e}")
        return 0


def get_function_arguments(func_addr: int) -> int:
    tif = idaapi.tinfo_t()
    funcdata = idaapi.func_type_data_t()
    if idaapi.get_tinfo(tif, func_addr) and tif.get_func_details(funcdata):
        return len(funcdata)
    try:
        frame_id = idc.get_frame_id(func_addr)
        return sum(
            1 for member in idautils.StructMembers(frame_id) if "arg" in member[1]
        )
    except Exception as e:
        logger.error(f"[-] Error getting arguments for 0x{func_addr:x}: {e}")
        return 0


# ---------------------------------------------------------------------
# Global Call Graph Build / Export / Import
# ---------------------------------------------------------------------
def build_global_call_graph(max_funcs: int = -1) -> rx.PyDiGraph:
    """
    Build and return a directed PyDiGraph (global call graph)
    for all recognized functions in the IDB.
    """
    G = rx.PyDiGraph(multigraph=False)
    func_to_node = {}

    all_funcs = list(idautils.Functions())
    if max_funcs == -1:
        all_funcs = all_funcs[:max_funcs]

    total_funcs = len(all_funcs)
    logger.debug(f"Discovered {total_funcs} total functions. Building graph...")

    # Create nodes – compute the instruction count once for each function.
    for func_addr in tqdm(all_funcs, desc="Creating nodes", mininterval=5.0):
        ninstrs = get_instruction_count_bb(func_addr)
        if ninstrs < 5:
            continue

        try:
            node_payload = {
                "addr": func_addr,
                "name": idc.get_func_name(func_addr),
                "ninstrs": ninstrs,
                "nlocals": get_num_local_vars(func_addr),
                "nargs": get_function_arguments(func_addr),
            }
            node_index = G.add_node(node_payload)
            func_to_node[func_addr] = node_index
        except Exception as e:
            logger.error(f"Error processing function 0x{func_addr:x}: {e}")

    logger.debug("Finished creating nodes. Now building edges...")

    # Add edges.
    for func_addr, u in tqdm(
        list(func_to_node.items()), desc="Linking edges", mininterval=5.0
    ):
        for callee_addr in get_callees(func_addr):
            if callee_addr in func_to_node:
                v = func_to_node[callee_addr]
                G.add_edge(u, v, None)

    logger.debug("Finished building global call graph.")
    return G


def export_call_graph_to_json(G: rx.PyDiGraph, filepath: str) -> None:
    """
    Export the global call graph G to a JSON file.
    Uses orjson for faster serialization.
    """
    nodes_data = [
        {
            "index": idx,
            "addr": payload["addr"],
            "name": payload["name"],
            "ninstrs": payload["ninstrs"],
            "nlocals": payload["nlocals"],
            "nargs": payload["nargs"],
        }
        for idx, payload in enumerate(G.nodes())
    ]
    edges_data = [{"source": u, "target": v} for u, v in G.edge_list()]

    graph_data = {"nodes": nodes_data, "edges": edges_data}
    with open(filepath, "wb") as f:
        f.write(orjson.dumps(graph_data))


def import_call_graph_from_json(filepath: str) -> rx.PyDiGraph:
    """
    Reconstruct a PyDiGraph from the JSON that was exported.
    """
    # Read and parse the JSON in one step using Path for brevity.
    graph_data = orjson.loads(Path(filepath).read_bytes())

    # Create a new directed graph.
    G = rx.PyDiGraph(multigraph=False)

    # Build the mapping from the old node indices to the new indices,
    # constructing each node's payload on the fly.
    old_index_to_new = {
        node_info["index"]: G.add_node(
            {
                "addr": node_info["addr"],
                "name": node_info["name"],
                "ninstrs": node_info["ninstrs"],
                "nlocals": node_info["nlocals"],
                "nargs": node_info["nargs"],
            }
        )
        for node_info in graph_data["nodes"]
    }

    # Re-create the edges using the mapping.
    for edge_info in graph_data["edges"]:
        src = old_index_to_new[edge_info["source"]]
        tgt = old_index_to_new[edge_info["target"]]
        G.add_edge(src, tgt, None)

    return G


# ---------------------------------------------------------------------
# Subgraph Extraction and Conversion
# ---------------------------------------------------------------------
def extract_call_graphlet(G: rx.PyDiGraph, func_idx: int) -> rx.PyDiGraph:
    """
    Return a subgraph representing the call graphlet as defined in the paper:
      - the target function itself,
      - its direct callers (incoming neighbors),
      - its direct callees (outgoing neighbors),
      - and the callees of its direct callees (second-level outgoing neighbors).
    This excludes callers of callers.
    """
    # Start with the target node.
    nodes = {func_idx}

    # Get direct callers and callees.
    direct_callers = {pred for pred, _, _ in G.in_edges(func_idx)}
    direct_callees = {nbr for _, nbr, _ in G.out_edges(func_idx)}
    nodes.update(direct_callers)
    nodes.update(direct_callees)

    # For each direct callee, add its callees (second-level) only.
    for callee in direct_callees:
        second_level_callees = {nbr for _, nbr, _ in G.out_edges(callee)}
        nodes.update(second_level_callees)

    return G.subgraph(list(nodes))


def main_convert(filepath: str, save_path: str) -> None:
    """
    Convert the global call graph to the adjacency-based JSON format
    (one file per node's subgraph), while deduplicating common call graphlets.
    """
    os.makedirs(save_path, exist_ok=True)
    logger.info("[+] Importing global call graph...")
    graph_path = os.path.join(SAVE_PATH, filepath)
    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    G: rx.PyDiGraph = import_call_graph_from_json(graph_path)
    logger.info(f"[+] Loaded global call graph from {graph_path}")

    # A set to keep track of seen subgraph fingerprints.
    seen_fingerprints = set()

    for subgraph_idx in tqdm(
        G.node_indices(),
        total=G.num_nodes(),
        desc="Converting global graph to subgraphs",
        mininterval=3.0,
    ):
        payload = G.get_node_data(subgraph_idx)
        subgraph: rx.PyDiGraph = extract_call_graphlet(G, subgraph_idx)
        if subgraph.num_edges() == 0:
            # we want subgraphs with more than 0 edges for edge weights
            continue

        nodes = subgraph.node_indices()
        node_map = {node_id: i for i, node_id in enumerate(nodes)}

        graph_data = {
            "nodes": [
                {
                    "id": node_map[node_id],
                    "ninstrs": subgraph.get_node_data(node_id)["ninstrs"],
                    "edges": subgraph.out_degree(node_id) + subgraph.in_degree(node_id),
                    "indegree": subgraph.in_degree(node_id),
                    "outdegree": subgraph.out_degree(node_id),
                    "nlocals": subgraph.get_node_data(node_id)["nlocals"],
                    "nargs": subgraph.get_node_data(node_id)["nargs"],
                }
                for node_id in nodes
            ],
            "edges": [
                {"source": node_map[u], "target": node_map[v]}
                for u, v in subgraph.edge_list()
            ],
        }

        # Compute a fingerprint (hash) of the graph data.
        # We use orjson with sorted keys for a canonical representation.
        fingerprint = hashlib.sha256(
            orjson.dumps(graph_data, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()

        if fingerprint in seen_fingerprints:
            # Duplicate call graphlet found; skip saving.
            continue
        seen_fingerprints.add(fingerprint)

        # for stripped binaries we need to have a way to create signatures
        # probably a fork from https://github.com/kweatherman/sigmakerex
        # filter for macos binaries that are unstripped
        demangled_name = demangle_function_name(payload["name"])
        if (
            "std::" in demangled_name
            or "boost::" in demangled_name
            or "tbb::" in demangled_name
            or "__acrt" in demangled_name
            or "__crt" in demangled_name
        ):
            # Likely a library function; skip.
            continue

        if demangled_name == payload["name"]:
            # for windows binaries we look for functions with sub_ and ifn ot found we skip
            try:
                demangled_name = demangled_name.split("sub_")[1]
            except:
                continue
        else:
            # Remove parentheses from the function name e.g main(int a).
            demangled_name = demangled_name.split("(")[0]

        filename = os.path.join(save_path, f"{demangled_name}_subgraph.json")
        try:
            with open(filename, "wb") as f:
                f.write(orjson.dumps(graph_data))
        except OSError:
            # Filename too long, skip this node.
            continue


def get_function_signature(func_addr, max_bytes=32):
    pattern = []
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"[ERROR] Function at {func_addr:#x} not found.")
        return None

    total_bytes = 0
    for ea in idautils.FuncItems(func.start_ea):
        if total_bytes >= max_bytes:
            break

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            print(f"[ERROR] Error decoding instruction at {ea:#x}")
            continue

        bytes_ = bytearray(ida_bytes.get_bytes(ea, insn.size))

        for i in range(len(insn.ops)):  # type: ignore
            op = insn.ops[i]  # type: ignore
            if op.type == ida_ua.o_void:
                break

            # Check if this operand can contain a build-specific address or offset:
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

                FL_RIPREL = 0x20  # for x86_64 RIP-relative

                # Check if it is RIP-relative
                # IDA sets FL_RIPREL in specflag1 for x86-64 RIP-relative operands
                is_rip_relative = op.type == ida_ua.o_displ and bool(
                    op.specflag1 & FL_RIPREL
                )

                # Determine mask size:
                if op.type in (ida_ua.o_near, ida_ua.o_far):
                    # calls/jumps typically store a 4-byte offset in x86/x64
                    size = 4
                elif is_rip_relative:
                    # 64-bit RIP-relative displacements are 4 bytes
                    size = 4
                else:
                    # fallback: derive from operand data type
                    size = ida_ua.get_dtype_size(op.dtype)
                    if size < 1:
                        size = 4  # fallback if IDA doesn't know

                # Mask the bytes
                for j in range(op.offb, min(op.offb + size, len(bytes_))):
                    bytes_[j] = 0x00

        # Take as many bytes as we still need
        remaining = max_bytes - total_bytes
        if remaining <= 0:
            break

        current_chunk = bytes_[:remaining]
        pattern += [f"{b:02X}" if b != 0 else "?" for b in current_chunk]
        total_bytes += len(current_chunk)

    # Trim trailing wildcards
    while pattern and pattern[-1] == "?":
        pattern.pop()

    if not pattern:
        raise ValueError(f"Function at {func_addr:#x} has no instructions.")

    byte_pattern = " ".join(pattern)

    string_refs = []
    filtered_strings = ["byte", "DJ"]
    for ea in idautils.FuncItems(func.start_ea):
        for ref in idautils.DataRefsFrom(ea):
            name = idc.get_name(ref)
            logger.debug(f"Found string reference: {name} @ {ea:#x}")
            if name and not any(f in name for f in filtered_strings):
                string_refs.append(name)

    # Include up to 3 unique strings in signature
    unique_strings = list(set(string_refs))[:3]
    string_part = "|".join(unique_strings)

    return f"{byte_pattern}|STR:{string_part}"


def signature_search(signature: str) -> list[str]:
    """Search for ALL functions matching the given signature."""
    matches = []

    # Split signature into byte pattern and strings
    parts = signature.split("|STR:")
    byte_pattern = parts[0]
    search_strings = parts[1].split("|") if len(parts) > 1 else []

    # Search in all executable segments (not just the first .text/__text)
    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        if seg_name not in [".text", "__text"]:
            continue  # Skip non-code segments

        start_ea = idc.get_segm_start(seg_start)
        end_ea = idc.get_segm_end(seg_start)

        logger.debug(f"Searching segment {seg_name} @ {start_ea:x}-{end_ea:x}")

        # Compile pattern once per segment
        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled_pattern, start_ea, byte_pattern, 16)
        if err:
            logger.error(f"Pattern error in segment {seg_name}: {err}")
            continue

        # Iterative search until BADADDR
        current_ea = start_ea
        while current_ea < end_ea:
            found_ea = ida_bytes.bin_search(
                current_ea, end_ea, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD
            )
            if not found_ea or found_ea[0] == idaapi.BADADDR:
                break

            match_ea = found_ea[0]
            matches.append(match_ea)
            logger.debug(f"Found match @ {match_ea:x}")
            current_ea = match_ea + 1  # Advance search start

    logger.info(f"Found {len(matches)} unfiltered matches for signature: {signature}")

    if len(matches) == 1:
        return matches

    # Filter matches by string presence
    filtered = []
    for candidate in matches:
        has_all_strings = True
        for s in search_strings:
            found = False
            for ref_ea in idautils.DataRefsTo(idc.get_name_ea_simple(s)):
                if idc.get_func_attr(ref_ea, idc.FUNCATTR_START) == candidate:
                    found = True
                    break
            if not found:
                has_all_strings = False
                break
        if has_all_strings:
            filtered.append(candidate)

    logger.info(f"Filtered {len(matches)}→{len(filtered)} matches using strings")
    return filtered


# ---------------------------------------------------------------------
# Import / Analysis Helpers
# ---------------------------------------------------------------------
def main_import(filepath: str, target_func_addr: int) -> None:
    logger.info("[+] Importing global call graph...")
    graph_path = os.path.join(SAVE_PATH, filepath)
    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    G = import_call_graph_from_json(graph_path)
    logger.info(f"[+] Loaded global call graph from {graph_path}")

    # target_func_idx = next(
    #     (
    #         idx
    #         for idx, payload in enumerate(G.nodes())
    #         if payload["addr"] == target_func_addr
    #     ),
    #     -1,
    # )
    # if target_func_idx < 0:
    #     raise ValueError(f"Function addr 0x{target_func_addr:x} not in global graph.")

    st = time.monotonic()
    # TESTING START

    random.seed(42)  # Set a fixed seed for reproducibility
    all_func_addrs = [payload["addr"] for payload in G.nodes()]
    func_addr_list = random.sample(
        all_func_addrs, min(5, len(all_func_addrs))
    )  # Sample up to 10 addresses
    func_addr_list = [0x140E1E8E0]

    for target_func_addr in func_addr_list:
        _st = time.monotonic()

        signature = get_function_signature(target_func_addr, max_bytes=40)
        if signature is None:
            raise ValueError(f"Function addr 0x{target_func_addr:x} not found.")

        logger.info(f"Signature for 0x{target_func_addr:x}: {signature}")

        matched_func_addr_list = signature_search(signature)
        logger.info(
            f"Found {len(matched_func_addr_list)} functions with matching signature"
        )
        for addr in matched_func_addr_list:
            logger.info(f"Found function at 0x{addr:x}")

        _et = time.monotonic()
        logger.info(f"Time taken to search for signature: {_et - _st:.2f} seconds")

        logger.info("")

    # TESTING END
    et = time.monotonic()
    logger.info(f"Time taken to search for all signatures: {et - st:.2f} seconds")
    exit(0)

    subgraph = extract_call_graphlet(G, target_func_addr)
    logger.debug(f"Subgraph for 0x{target_func_addr:x}")

    edge_centrality = rx.edge_betweenness_centrality(subgraph, normalized=False)
    logger.debug(f"Num edge indices: {len(subgraph.edge_indices())}")
    for edge in subgraph.edge_indices():
        logger.debug(f"Edge {edge}: {edge_centrality[edge]}")

    indegree = G.in_degree(target_func_idx)
    outdegree = G.out_degree(target_func_idx)
    logger.debug(f"Indegree: {indegree}, Outdegree: {outdegree}")

    callee = get_callees(target_func_addr)
    logger.debug(f"Callees ({len(callee)}): {[hex(addr) for addr in callee]}")
    caller = get_callers(target_func_addr)
    logger.debug(f"Callers ({len(caller)}): {[hex(addr) for addr in caller]}")


# ---------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Manage a global call graph for IDA.")
    parser.add_argument(
        "--mode",
        choices=["export", "import", "convert"],
        required=True,
        help="Select whether to export a new global call graph or import an existing one.",
    )
    parser.add_argument(
        "--max-funcs",
        type=int,
        default=None,
        help="Limit number of functions processed for testing",
    )
    parser.add_argument(
        "--filepath",
        type=str,
        default=None,
        help="Path to the JSON file containing the global call graph",
    )
    parser.add_argument(
        "--save-path",
        type=str,
        default=None,
        help="Path to save the subgraphs",
    )
    parser.add_argument(
        "--target-func-addr",
        type=lambda x: int(x, 0),
        default=None,
        help="Address of the target function to analyze",
    )

    args = parser.parse_args()

    if args.mode == "export":
        logger.info("[+] Building and exporting global call graph...")
        G = build_global_call_graph(max_funcs=args.max_funcs)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_path = os.path.join(
            SAVE_PATH, f"global_call_graph_export_{timestamp}.json"
        )
        export_call_graph_to_json(G, output_path)
        logger.info(f"[+] Exported global call graph to {output_path}")
    elif args.mode == "import":
        if args.filepath is None:
            logger.error(
                "[!] Please provide a filepath to the JSON file containing the global call graph"
            )
            return
        if args.target_func_addr is None:
            logger.error("[!] Please provide a target function address")
            return

        main_import(args.filepath, args.target_func_addr)
    elif args.mode == "convert":
        if args.filepath is None:
            logger.error(
                "[!] Please provide a filepath to the JSON file containing the global call graph"
            )
            return
        if args.save_path is None:
            logger.error("[!] Please provide a save path to save the subgraphs")
            return
        main_convert(args.filepath, args.save_path)


if __name__ == "__main__":
    logger.info("Starting...")
    main()
