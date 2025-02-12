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

import argparse
import datetime
import logging
import rustworkx as rx
import orjson

from collections import deque
from typing import Set
from functools import lru_cache
from tqdm import tqdm
from collections import deque
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
    demangled = idaapi.demangle_name(name, disable_mask)
    return demangled if demangled is not None else name


def get_callers(func_addr: int) -> Set[int]:
    return {
        idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        for xref in idautils.XrefsTo(func_addr, idaapi.XREF_USER)
        if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF)
        and idc.get_func_attr(xref.frm, idc.FUNCATTR_START) != idc.BADADDR
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
def build_global_call_graph(max_funcs: int = None) -> rx.PyDiGraph:
    """
    Build and return a directed PyDiGraph (global call graph)
    for all recognized functions in the IDB.
    """
    G = rx.PyDiGraph(multigraph=False)
    func_to_node = {}

    all_funcs = list(idautils.Functions())
    if max_funcs:
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
def extract_call_graphlet(
    G: rx.PyDiGraph, func_idx: int, max_depth: int = 2
) -> rx.PyDiGraph:
    """
    Return a subgraph of `G` containing the node at index `func_idx`
    and up to `max_depth` levels of its neighbors.
    """
    node_indices = []
    visited = set()
    queue = deque()

    queue.append((func_idx, 0))
    visited.add(func_idx)

    while queue:
        current_idx, depth = queue.popleft()
        node_indices.append(current_idx)

        if depth < max_depth:
            # Expand to outgoing neighbors.
            for _, neighbor_idx, _ in G.out_edges(current_idx):
                if neighbor_idx not in visited:
                    visited.add(neighbor_idx)
                    queue.append((neighbor_idx, depth + 1))
            # Optionally expand to incoming neighbors.
            for pred_idx, _, _ in G.in_edges(current_idx):
                if pred_idx not in visited:
                    visited.add(pred_idx)
                    queue.append((pred_idx, depth + 1))

    return G.subgraph(node_indices)


def main_convert(filepath: str, save_path: str) -> None:
    """
    Convert the global call graph to the adjacency-based JSON format
    (one file per node's subgraph).
    """
    os.makedirs(save_path, exist_ok=True)
    logger.info("[+] Importing global call graph...")
    graph_path = os.path.join(SAVE_PATH, filepath)
    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    G: rx.PyDiGraph = import_call_graph_from_json(graph_path)
    logger.info(f"[+] Loaded global call graph from {graph_path}")

    for subgraph_idx in tqdm(
        G.node_indices(),
        total=G.num_nodes(),
        desc="Converting global graph to subgraphs",
        mininterval=1.0,
    ):
        payload = G.get_node_data(subgraph_idx)
        subgraph: rx.PyDiGraph = extract_call_graphlet(G, subgraph_idx, max_depth=2)

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

        filename = os.path.join(save_path, f"{payload['name']}_subgraph.json")
        try:
            with open(filename, "wb") as f:
                f.write(orjson.dumps(graph_data))
        except OSError:
            # Filename too long, skip this node.
            continue


# ---------------------------------------------------------------------
# Import / Analysis Helpers
# ---------------------------------------------------------------------
def main_import(filepath: str) -> None:
    logger.info("[+] Importing global call graph...")
    graph_path = os.path.join(SAVE_PATH, filepath)
    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    G = import_call_graph_from_json(graph_path)
    logger.info(f"[+] Loaded global call graph from {graph_path}")

    target_func_addr = 0x0000000101850D1E
    subgraph = extract_call_graphlet(G, target_func_addr, max_depth=2)
    logger.debug(f"Subgraph for 0x{target_func_addr:x}")

    edge_centrality = rx.edge_betweenness_centrality(subgraph, normalized=False)
    logger.debug(f"Edge betweenness scores: {dict(edge_centrality)}")

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

    indegree = G.in_degree(target_func_idx)
    outdegree = G.out_degree(target_func_idx)
    logger.debug(f"Indegree: {indegree}, Outdegree: {outdegree}")

    callee = get_callees(target_func_addr)
    logger.debug(f"Callees: {[hex(addr) for addr in callee]}")
    caller = get_callers(target_func_addr)
    logger.debug(f"Callers: {[hex(addr) for addr in caller]}")


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
        main_import(args.filepath)
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
