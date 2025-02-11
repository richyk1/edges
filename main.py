from headless_ida import HeadlessIda

# Initialize HeadlessIda.
headlessida = HeadlessIda(
    "/Applications/IDA Professional 9.0.app/Contents/MacOS/idat",
    "/Users/kerosene/Desktop/eu4_1.27.2.i64",
)

# Import IDA modules.
import idautils
import idaapi
import json
import logging
import os
from typing import Dict, Set, Tuple

import idaapi
import idc
import rustworkx as rx
import argparse
from tqdm import tqdm
import datetime
from collections import deque


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# Set up an output directory.
SAVE_PATH = os.path.join(os.path.expanduser("~"), "Github", "edges")
os.makedirs(SAVE_PATH, exist_ok=True)

# Cache for demangled function names.
_demangle_cache: Dict[str, str] = {}


def demangle_function_name(name: str) -> str:
    if name in _demangle_cache:
        return _demangle_cache[name]
    disable_mask = idc.get_inf_attr(idc.INF_SHORT_DN)
    demangled = idaapi.demangle_name(name, disable_mask)
    result = demangled if demangled is not None else name
    _demangle_cache[name] = result
    return result


def get_callers(func_addr: int) -> Set[int]:
    return {
        idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        for xref in idautils.XrefsTo(func_addr, idaapi.XREF_USER)
        # Include only CALL xrefs (fl_CN, fl_CF) and JMP xrefs (fl_JN, fl_JF)
        if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF)
        and idc.get_func_attr(xref.frm, idc.FUNCATTR_START) != idc.BADADDR
    }


def get_callees(func_addr: int) -> Set[int]:
    callees = set()

    # Get the function object from its start address
    func = idaapi.get_func(func_addr)
    if not func:
        logger.error(f"[-] Function at {hex(func_addr)} not found.")
        return callees

    # Iterate over all instructions in the function
    for insn_addr in idautils.FuncItems(func_addr):
        if idc.print_insn_mnem(insn_addr) == "call":
            # Get the target of the call instruction
            call_target = idc.get_operand_value(insn_addr, 0)

            # Verify it's a function start
            func_start = idc.get_func_attr(call_target, idc.FUNCATTR_START)
            if func_start != idc.BADADDR:
                callees.add(func_start)

    return callees


def get_instruction_count_bb(func_addr: int) -> int:
    func = idaapi.get_func(func_addr)
    count = sum(
        1
        for head in idautils.Heads(func.start_ea, func.end_ea)
        if idc.is_code(idc.get_full_flags(head))
    )
    return count


def get_num_local_vars(func_addr: int) -> int:
    try:
        frame_id = idc.get_frame_id(func_addr)
        count = 0
        for member in idautils.StructMembers(frame_id):
            if "var" in member[1]:
                count += 1
        return count
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
        count = 0
        for member in idautils.StructMembers(frame_id):
            if "arg" in member[1]:
                count += 1
        return count
    except Exception as e:
        logger.error(f"[-] Error getting arguments for 0x{func_addr:x}: {e}")
        return 0


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

    # (A) Create nodes with tqdm
    for func_addr in tqdm(all_funcs, desc="Creating nodes", mininterval=5.0):
        if get_instruction_count_bb(func_addr) < 5:
            continue

        try:
            node_payload = {
                "addr": func_addr,
                "name": idc.get_func_name(func_addr),
                "ninstrs": get_instruction_count_bb(func_addr),
                # indegree and outdegree can be computed from the graph
                "nlocals": get_num_local_vars(func_addr),
                "nargs": get_function_arguments(func_addr),
                # signature unnecessary for now
            }
            node_index = G.add_node(node_payload)
            func_to_node[func_addr] = node_index
        except Exception as e:
            logger.error(f"Error processing function 0x{func_addr:x}: {e}")

    logger.debug("Finished creating nodes. Now building edges...")

    # (B) Add edges with tqdm
    func_items = list(func_to_node.items())  # so we can iterate in tqdm
    for func_addr, u in tqdm(func_items, desc="Linking edges", mininterval=5.0):
        for callee_addr in get_callees(func_addr):
            if callee_addr in func_to_node:
                v = func_to_node[callee_addr]
                G.add_edge(u, v, None)

    logger.debug("Finished building global call graph.")
    return G


def export_call_graph_to_json(G: rx.PyDiGraph, filepath: str) -> None:
    """
    Export the global call graph G to a JSON file.
    Each node is stored with its index and payload.
    Edges are stored as a list of {source, target}.
    """
    nodes_data = []
    for idx, payload in enumerate(G.nodes()):
        node_info = {
            "index": idx,
            "addr": payload["addr"],
            "name": payload["name"],
            "ninstrs": payload["ninstrs"],
            "nlocals": payload["nlocals"],
            "nargs": payload["nargs"],
        }
        nodes_data.append(node_info)

    edges_data = []
    for u, v in G.edge_list():
        edges_data.append({"source": u, "target": v})

    graph_data = {"nodes": nodes_data, "edges": edges_data}

    with open(filepath, "w") as f:
        json.dump(graph_data, f, indent=None)


def import_call_graph_from_json(filepath: str) -> rx.PyDiGraph:
    """
    Reconstruct a PyDiGraph from the JSON that was exported.
    Returns the reconstructed PyDiGraph.
    """
    with open(filepath, "r") as f:
        graph_data = json.load(f)

    G = rx.PyDiGraph(multigraph=False)

    # We'll map "old index" from the JSON to "new index" in G
    old_index_to_new = {}

    # 1) Re-create nodes
    for node_info in graph_data["nodes"]:
        payload = {
            "addr": node_info["addr"],
            "name": node_info["name"],
            "ninstrs": node_info["ninstrs"],
            "nlocals": node_info["nlocals"],
            "nargs": node_info["nargs"],
        }
        new_idx = G.add_node(payload)
        old_index_to_new[node_info["index"]] = new_idx

    # 2) Re-create edges
    for edge_info in graph_data["edges"]:
        u_old = edge_info["source"]
        v_old = edge_info["target"]
        # Map old node indices to new node indices in this fresh graph
        u_new = old_index_to_new[u_old]
        v_new = old_index_to_new[v_old]
        G.add_edge(u_new, v_new, None)

    return G


def extract_call_graphlet(
    G: rx.PyDiGraph, func_idx: int, max_depth: int = 2
) -> rx.PyDiGraph:
    """
    Return a subgraph of `G` containing `func_addr` and
    up to `max_depth` levels of its neighbors in the call graph.
    Edges remain directed caller → callee as in `G`.
    """

    # 1) Get the node index for func_addr in G.
    #    We'll do a small BFS/DFS outward from this node.
    #    Also consider a BFS *backwards* to get callers if you prefer.
    node_indices = []
    visited = set()

    queue = deque()
    start_index = func_idx

    # Enqueue the start node with depth = 0
    queue.append((start_index, 0))
    visited.add(start_index)

    while queue:
        current_idx, depth = queue.popleft()
        node_indices.append(current_idx)

        if depth < max_depth:
            # Outgoing edges (caller → callee)
            for _, neighbor_idx, _ in G.out_edges(current_idx):
                if neighbor_idx not in visited:
                    visited.add(neighbor_idx)
                    queue.append((neighbor_idx, depth + 1))

            # If you also want “incoming edges = callers” in the neighborhood,
            # do an in-edges expansion:
            for pred_idx, _, _ in G.in_edges(current_idx):
                if pred_idx not in visited:
                    visited.add(pred_idx)
                    queue.append((pred_idx, depth + 1))

    # 2) Create the subgraph from the visited node indices
    subgraph = G.subgraph(node_indices)
    return subgraph


def main_convert(filepath: str, save_path: str) -> None:
    """
    Convert a PyDiGraph into the adjacency-based JSON format
    that `kyn` (and NetworkX's json_graph) expects.

    Writes one JSON file per node (function) in the graph.
    """
    os.makedirs(save_path, exist_ok=True)

    logger.info("[+] Importing global call graph...")
    graph_path = os.path.join(SAVE_PATH, filepath)
    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    G = import_call_graph_from_json(graph_path)
    logger.info(f"[+] Loaded global call graph from {graph_path}")

    for idx, payload in tqdm(
        enumerate(G.nodes()),
        total=G.num_nodes(),
        desc="Converting global graph to subgraphs",
        mininterval=1.0,
    ):
        # Get subgraph for the current node
        subgraph = extract_call_graphlet(G, idx, max_depth=2)

        adjacency = []
        nodes_data = []

        total_edges = subgraph.num_edges()

        for i, node_payload in enumerate(subgraph.nodes()):
            neighbors = []
            for src, dst, _ in subgraph.out_edges(i):
                if src == i:
                    neighbors.append({"id": dst})
            adjacency.append(neighbors)

            in_deg = subgraph.in_degree(i)
            out_deg = subgraph.out_degree(i)

            node_dict = {
                "id": i,
                "funcName": node_payload["name"],
                "functionFeatureSubset": {
                    "name": node_payload["name"],
                    "ninstrs": node_payload["ninstrs"],
                    "edges": total_edges,
                    "indegree": in_deg,
                    "outdegree": out_deg,
                    "nlocals": node_payload["nlocals"],
                    "nargs": node_payload["nargs"],
                    "signature": f"{node_payload['name']}(...)",
                },
            }
            nodes_data.append(node_dict)

        graph_json = {
            "directed": "True",
            "multigraph": False,
            "graph": [],
            "adjacency": adjacency,
            "nodes": nodes_data,
        }

        # Construct a filename for each node’s subgraph
        filename = os.path.join(save_path, f"{payload['name']}_subgraph.json")
        try:
            with open(filename, "w") as f:
                json.dump(graph_json, f, indent=None)
        except OSError:
            # Filename too long
            continue


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

    target_func_idx = -1
    for idx, payload in enumerate(G.nodes()):
        if payload["addr"] == target_func_addr:
            target_func_idx = idx
            break
    if target_func_idx < 0:
        raise ValueError(f"Function addr 0x{target_func_addr:x} not in global graph.")

    indegree = G.in_degree(target_func_idx)
    outdegree = G.out_degree(target_func_idx)
    logger.debug(f"Indegree: {indegree}, Outdegree: {outdegree}")

    callee = get_callees(target_func_addr)
    logger.debug(f"Callees: {[hex(addr) for addr in callee]}")
    caller = get_callers(target_func_addr)
    logger.debug(f"Callers: {[hex(addr) for addr in caller]}")

    # Example: run further analysis with the imported graph
    # ...
    # e.g., subgraph = extract_call_graphlet(G, 0x12345678, max_depth=2)
    # edge_weights = compute_edge_weights(subgraph)


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
        time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_path = os.path.join(SAVE_PATH, f"global_call_graph_export_{time}.json")
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
