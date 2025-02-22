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


def get_function_signature(func_addr):
    pattern = []
    func = idaapi.get_func(func_addr)
    if not func:
        logger.error(f"[-] Function at {func_addr} not found.")
        return None

    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            logger.error(f"[-] Error decoding instruction at {ea:x}")

        bytes_ = bytearray(ida_bytes.get_bytes(ea, insn.size))

        # Mask operands that are code references or immediate values
        for i in range(8):  # IDA supports up to 8 operands
            op = insn[i]  # Use indexing instead of direct iteration

            if op.type == ida_ua.o_void:
                break  # No more operands to process

            if op.type in [ida_ua.o_near, ida_ua.o_far, ida_ua.o_imm]:
                offset = op.offb
                size = ida_ua.get_dtype_size(op.dtype)
                for j in range(offset, offset + size):
                    if j < len(bytes_):
                        bytes_[j] = 0x00

        # Format as IDA-style pattern
        pattern.extend([f"{b:02X}" if b != 0 else "?" for b in bytes_])

    return " ".join(pattern)


def signature_search(signature: str):
    """Search for a function with the given signature."""

    # limit search in executable code segments e.g .text for x86 and __text for arm
    start_ea = 0
    end_ea = 0
    for s in idautils.Segments():
        start = idc.get_segm_start(s)
        end = idc.get_segm_end(s)
        if idc.get_segm_name(s) in [".text", "__text"]:
            start_ea = start
            end_ea = end
            break

    logger.info(
        f"Searching for function with signature: {signature} in range {start_ea:x} - {end_ea:x}"
    )

    compiled_pattern = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(compiled_pattern, start_ea, signature, 16)
    if not err:
        ea = ida_bytes.bin_search(
            start_ea, end_ea, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD
        )
        logger.warning(f"EA  - {ea}")
        ea = ea[0]

        ok = ea != idaapi.BADADDR
        if ok:
            logger.debug(f"Succesfully found signature: {signature[:10]} at {ea:x}")
        else:
            logger.debug(f"Signature: {signature[:10]} not found")
    else:
        logger.error(f"Error parsing signature: {signature}")

    return None


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

    target_func_idx = next(
        (
            idx
            for idx, payload in enumerate(G.nodes())
            if payload["addr"] == target_func_addr
        ),
        -1,
    )
    if target_func_idx < 0:
        raise ValueError(f"Function addr 0x{target_func_addr:x} not in global graph.")

    # TESTING START

    # Get the function signature
    st = time.monotonic()

    signature = get_function_signature(target_func_addr)
    if signature is None:
        raise ValueError(f"Function addr 0x{target_func_addr:x} not found.")

    found_func_addr = signature_search(signature)

    et = time.monotonic()
    logger.info(f"Time taken to search for signature: {et - st:.2f} seconds")

    exit(0)
    # TESTING END

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
