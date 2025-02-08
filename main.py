import datetime
import json
import os
from typing import Any, Dict, Set, Tuple, cast

import idaapi
import idautils
import idc
import rustworkx as rx

# Set up an output directory.
DATE = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

# TODO: Change the SAVE_PATH to your desired output directory.
VERSION = "1.27.2"
SAVE_PATH = os.path.join(
    os.path.expanduser("~"), "Github", "edges", "cgns", "cgn_" + VERSION
)
os.makedirs(SAVE_PATH, exist_ok=True)

# -------------------------------------------------------------------
# Improvement 1: Cache demangled names.
_demangle_cache: Dict[str, str] = {}


def demangle_function_name(name: str) -> str:
    if name in _demangle_cache:
        return _demangle_cache[name]
    disable_mask = idc.get_inf_attr(idc.INF_SHORT_DN)
    demangled = idaapi.demangle_name(name, disable_mask)
    result = demangled if demangled is not None else name
    _demangle_cache[name] = result
    return result


# -------------------------------------------------------------------
# Improvement 2: Precompute code references.
global_callers: Dict[int, Set[int]] = {}
global_callees: Dict[int, Set[int]] = {}


def precompute_references() -> None:
    for func_addr in idautils.Functions():
        global_callers[func_addr] = set(idautils.CodeRefsTo(func_addr, 0))
        global_callees[func_addr] = set(idautils.CodeRefsFrom(func_addr, 0))


# -------------------------------------------------------------------
# (Existing helper functions remain unchanged.)
def get_instruction_count_bb(func_addr: int) -> int:
    func = idaapi.get_func(func_addr)
    if not func:
        return 0
    count = 0
    for bb in idaapi.FlowChart(func):
        count += sum(
            1
            for head in idautils.Heads(bb.start_ea, bb.end_ea)
            if idc.is_code(idc.get_full_flags(head))
        )
    return count


def get_indegree(func_addr: int) -> int:
    return len(global_callers.get(func_addr, set()))


def get_outdegree(func_addr: int) -> int:
    return len(global_callees.get(func_addr, set()))


def get_total_edges(func_addr: int) -> int:
    return get_indegree(func_addr) + get_outdegree(func_addr)


def get_num_local_vars(func_addr: int) -> int:
    try:
        frame_id = idc.get_frame_id(func_addr)
        count = 0
        for member in idautils.StructMembers(frame_id):
            if "var" in member[1]:
                count += 1
        return count
    except Exception as e:
        print(f"Error getting local variables for 0x{func_addr:x}: {e}")
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
        print(f"Error getting arguments for 0x{func_addr:x}: {e}")
        return 0


# -------------------------------------------------------------------
# Improvement 3: Reuse global graph data.
# Build the global call graph with rustworkx.
# Since rustworkx uses integer indices (assigned in order of node addition),
# we first build a mapping from function address to node index.
def build_call_graph() -> Tuple[rx.PyDiGraph, Dict[int, int]]:
    G = rx.PyDiGraph()
    func_to_node: Dict[int, int] = {}
    # First pass: add nodes.
    for func_addr in idautils.Functions():
        func_name = idc.get_func_name(func_addr)
        node_payload = {
            "name": func_name,
            "ninstrs": get_instruction_count_bb(func_addr),
            "indegree": get_indegree(func_addr),
            "outdegree": get_outdegree(func_addr),
            "nlocals": get_num_local_vars(func_addr),
            "nargs": get_function_arguments(func_addr),
            "signature": demangle_function_name(func_name),
        }
        node_index = G.add_node(node_payload)
        func_to_node[func_addr] = node_index
    # Second pass: add edges.
    for func_addr in idautils.Functions():
        if func_addr not in func_to_node:
            continue
        u = func_to_node[func_addr]
        # Use precomputed callees and callers.
        for callee in global_callees.get(func_addr, set()):
            if callee in func_to_node:
                v = func_to_node[callee]
                G.add_edge(u, v, None)  # Edge payload initially None.
        for caller in global_callers.get(func_addr, set()):
            if caller in func_to_node:
                v = func_to_node[caller]
                G.add_edge(v, u, None)
        # Add second-degree edges: for each direct callee, add its callees.
        for callee in global_callees.get(func_addr, set()):
            if callee not in func_to_node:
                continue
            u_callee = func_to_node[callee]
            for sdc in global_callees.get(callee, set()):
                if sdc in func_to_node:
                    v = func_to_node[sdc]
                    G.add_edge(u_callee, v, None)
    return G, func_to_node


# -------------------------------------------------------------------
# Improvement 4: Avoid duplicate subgraph constructions.
# Compute the union of callers, callees, and callees-of-callees once.
def get_call_graphlet_neighbors(func_addr: int) -> Set[int]:
    callers = global_callers.get(func_addr, set())
    callees = global_callees.get(func_addr, set())
    callees_of_callees = set()
    for callee in callees:
        callees_of_callees |= global_callees.get(callee, set())
    return callers | callees | callees_of_callees | {func_addr}


# In rustworkx, to get a subgraph induced on a set of nodes, we can call G.subgraph(node_indices).
# Also, rustworkx provides an edge betweenness function. (Here we assume it is called as shown.)
def compute_edge_weights(
    G: rx.PyDiGraph, func_addr: int, func_to_node: Dict[int, int]
) -> Dict[Any, float]:
    neighbors = get_call_graphlet_neighbors(func_addr)
    if len(neighbors) > 1000:
        raise ValueError("Call graphlet too large.")
    # Convert function addresses to rustworkx node indices as a list.
    neighbor_nodes = [
        func_to_node[addr] for addr in neighbors if addr in func_to_node
    ]
    subgraph = G.subgraph(neighbor_nodes)
    # Compute edge betweenness centrality.
    edge_centrality = rx.edge_betweenness_centrality(subgraph, normalized=True)
    return dict(edge_centrality)


def export_function_json(
    func_addr: int,
    subgraph: rx.PyDiGraph,
    edge_weights: Dict[Any, float],
    func_to_node: Dict[int, int],
    output_dir: str,
    file_index: int,
) -> None:
    node_indices = list(subgraph.node_indices())
    # Create a new mapping from the subgraph's node indices to new IDs (0, 1, 2, …).
    node_id_map = {node: idx for idx, node in enumerate(node_indices)}
    nodes_json = []
    for node in node_indices:
        payload = subgraph[node]
        node_json = {
            "id": node_id_map[node],
            "funcName": payload.get("name", ""),
            "functionFeatureSubset": {
                "name": payload.get("name", ""),
                "ninstrs": payload.get("ninstrs", 0),
                "edges": payload.get("indegree", 0)
                + payload.get("outdegree", 0),
                "indegree": payload.get("indegree", 0),
                "outdegree": payload.get("outdegree", 0),
                "nlocals": payload.get("nlocals", 0),
                "nargs": payload.get("nargs", 0),
                "signature": payload.get("signature", ""),
            },
        }
        nodes_json.append(node_json)
    # Build the adjacency list from the edge list.
    # Force a list conversion so that Pyright sees an iterable.
    adjacency = [[] for _ in range(len(node_indices))]
    for edge in list(subgraph.edge_list()):
        # Cast the edge to a tuple so that we can safely unpack it.
        edge_tuple = cast(Tuple[Any, ...], edge)
        if len(edge_tuple) == 2:
            u, v = edge_tuple
        elif len(edge_tuple) == 3:
            u, v, _ = edge_tuple
        else:
            continue  # Skip if edge_tuple has an unexpected length.
        u_id = node_id_map[u]
        v_id = node_id_map[v]
        weight = edge_weights.get((u, v), 0.0) if edge_weights else 0.0
        adjacency[u_id].append({"id": v_id, "weight": weight})
    json_obj = {
        "adjacency": adjacency,
        "directed": "True",
        "graph": [],
        "multigraph": False,
        "nodes": nodes_json,
    }
    target_name = idc.get_func_name(func_addr)
    out_filename = os.path.join(output_dir, f"{target_name}.json")
    with open(out_filename, "w") as f:
        json.dump(json_obj, f, indent=None)
    print(f"Saved JSON for function {target_name} to {out_filename}")


# -------------------------------------------------------------------
# Main function.
def main() -> None:
    print(f"Saving JSON files to: {SAVE_PATH}")
    precompute_references()
    call_graph, func_to_node = build_call_graph()
    functions = idautils.Functions()
    file_index = 0
    while True:
        func_addr = next(functions, None)
        if func_addr is None:
            break
        func_name = idc.get_func_name(func_addr)
        print(f"Processing function at 0x{func_addr:x} ({func_name})")
        try:
            edge_weights = compute_edge_weights(
                call_graph, func_addr, func_to_node
            )
            neighbors = get_call_graphlet_neighbors(func_addr)
            # Convert function addresses to rustworkx node indices as a list.
            neighbor_nodes = [
                func_to_node[addr] for addr in neighbors if addr in func_to_node
            ]
            subgraph = call_graph.subgraph(neighbor_nodes)
            # In rustworkx, edge weights are not stored in edge payloads,
            # so we assume our computed edge_weights (a dict mapping (u,v) to weight)
            # can be used later during JSON export.
            export_function_json(
                func_addr,
                subgraph,
                edge_weights,
                func_to_node,
                SAVE_PATH,
                file_index,
            )
            file_index += 1
        except Exception as e:
            print(f"Error processing function at 0x{func_addr:x}: {e}")
            continue
    print("Processing complete.")


if __name__ == "__main__":
    main()
