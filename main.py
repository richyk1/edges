import json
import os
from typing import Any, Dict, Set, cast

import idaapi
import idautils
import idc
import networkx as nx

# Build the save path using os.path.join for OS independence.
SAVE_PATH = os.path.join(os.path.expanduser("~"), "Github", "edges/cgn")
os.makedirs(SAVE_PATH, exist_ok=True)
MAX_FUNCTIONS = 100  # Process up to 100 functions


def get_instruction_count_bb(func_addr: int) -> int:
    """Counts the number of instructions in a function using its basic blocks."""
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
    """Returns the number of times a function is explicitly called."""
    return sum(1 for _ in idautils.CodeRefsTo(func_addr, 0))


def get_outdegree(func_addr: int) -> int:
    """Returns the number of times a function explicitly calls another function."""
    return sum(1 for _ in idautils.CodeRefsFrom(func_addr, 0))


def get_total_edges(func_addr: int) -> int:
    """Returns the total number of edges (in-degree + out-degree)."""
    return get_indegree(func_addr) + get_outdegree(func_addr)


def get_num_local_vars(func_addr: int) -> int:
    """Returns the number of local variables in a function."""
    frame_id = idc.get_frame_id(func_addr)
    count = 0
    for member in idautils.StructMembers(frame_id):
        if "var" in member[1]:
            count += 1
    return count


def get_function_arguments(func_addr: int) -> int:
    """Attempts to retrieve the number of function arguments."""
    tif = idaapi.tinfo_t()
    funcdata = idaapi.func_type_data_t()
    if idaapi.get_tinfo(tif, func_addr) and tif.get_func_details(funcdata):
        return len(funcdata)
    frame_id = idc.get_frame_id(func_addr)
    count = 0
    for member in idautils.StructMembers(frame_id):
        if "arg" in member[1]:
            count += 1
    return count


def build_call_graph() -> nx.DiGraph:
    """
    Constructs a directed global call graph at the function level.
    For each function, adds edges to its direct callees and callers.
    Additionally, adds edges from each callee to its callees (second-degree)
    to support later extraction of a call graphlet.
    """
    G = nx.DiGraph()
    for func_addr in idautils.Functions():
        func_name = idaapi.get_func_name(func_addr)
        G.add_node(func_addr, name=func_name)
        callees = set(idautils.CodeRefsFrom(func_addr, 0))
        callers = set(idautils.CodeRefsTo(func_addr, 0))
        for callee in callees:
            G.add_edge(func_addr, callee)
        for caller in callers:
            G.add_edge(caller, func_addr)
        # Add second-degree edges: for each direct callee, include its callees.
        for callee in callees:
            second_degree = set(idautils.CodeRefsFrom(callee, 0))
            for sdc in second_degree:
                G.add_edge(callee, sdc)
    return G


def compute_edge_weights(G: nx.DiGraph, func_addr: int) -> Dict[Any, float]:
    """
    Computes edge betweenness centrality within the call graphlet for a given function.
    The call graphlet includes:
      - Direct callers (C₁)
      - Direct callees (C₂)
      - Callees-of-callees (C₃) for each direct callee
      - The target function itself.
    """
    callers: Set[int] = set(idautils.CodeRefsTo(func_addr, 0))
    callees: Set[int] = set(idautils.CodeRefsFrom(func_addr, 0))
    callees_of_callees: Set[int] = set()
    for callee in callees:
        callees_of_callees |= set(idautils.CodeRefsFrom(callee, 0))
    neighbors: Set[int] = callers | callees | callees_of_callees | {func_addr}
    subgraph = G.subgraph(neighbors)
    return nx.edge_betweenness_centrality(subgraph)


def export_function_json(
    func_addr: int,
    G: nx.DiGraph,
    edge_weights: Dict[Any, float],
    output_dir: str,
    file_index: int,
) -> None:
    """
    For a given target function (func_addr), build the JSON representation
    of its call graphlet with the following structure:

    {
      "adjacency": [...],
      "directed": "True",
      "graph": [],
      "multigraph": false,
      "nodes": [
          {
            "id": 0,
            "funcName": "...",
            "functionFeatureSubset": {
                "name": "...",
                "ninstrs": ...,
                "edges": ...,
                "indegree": ...,
                "outdegree": ...,
                "nlocals": ...,
                "nargs": ...,
                "signature": ""
            }
          },
          ...
      ]
    }

    Each node corresponds to a function in the call graphlet.
    The "adjacency" is a list of lists, where each inner list contains dictionaries
    for outgoing edges from that node, with keys "id" and "weight".
    """
    # First, assign each node in the subgraph a new integer id.
    nodes_list = list(G.nodes())
    node_id_map = {addr: idx for idx, addr in enumerate(nodes_list)}

    # For every node, compute its features.
    nodes_json = []
    for addr in nodes_list:
        func_name = idaapi.get_func_name(addr)
        ninstrs = get_instruction_count_bb(addr)
        total_edges = get_total_edges(addr)
        indegree = get_indegree(addr)
        outdegree = get_outdegree(addr)
        nlocals = get_num_local_vars(addr)
        nargs = get_function_arguments(addr)
        # For signature, use empty string (or update as needed)
        signature = ""
        node_json = {
            "id": node_id_map[addr],
            "funcName": func_name,
            "functionFeatureSubset": {
                "name": func_name,
                "ninstrs": ninstrs,
                "edges": total_edges,
                "indegree": indegree,
                "outdegree": outdegree,
                "nlocals": nlocals,
                "nargs": nargs,
                "signature": signature,
            },
        }
        nodes_json.append(node_json)

    # Build the adjacency list.
    # Initialize an empty list for each node.
    adjacency = [[] for _ in range(len(nodes_list))]
    for u, v, data in G.edges(data=True):
        # Use the new integer ids.
        u_id = node_id_map[u]
        v_id = node_id_map[v]
        # Edge weight: if not found in our computed dict, use 0.
        weight = data.get("weight", 0.0)
        adjacency[u_id].append({"id": v_id, "weight": weight})

    # Build the final JSON structure.
    json_obj = {
        "adjacency": adjacency,
        "directed": "True",
        "graph": [],
        "multigraph": False,
        "nodes": nodes_json,
    }

    # Save the JSON file.
    target_name = idaapi.get_func_name(func_addr)
    out_filename = os.path.join(
        output_dir, f"{file_index:04d}-{target_name}.json"
    )
    with open(out_filename, "w") as f:
        json.dump(json_obj, f, indent=None)
    print(f"Saved JSON for function {target_name} to {out_filename}")


def main() -> None:
    """
    Main processing function:
      - Builds the global call graph.
      - For each function (up to MAX_FUNCTIONS), extracts its call graphlet,
        computes edge weights, and exports the graph as a JSON file.
    """
    call_graph = build_call_graph()
    functions = idautils.Functions()
    processed = 0
    file_index = 0

    while processed < MAX_FUNCTIONS:
        func_addr = next(functions, None)
        if func_addr is None:
            break
        try:
            edge_weights = compute_edge_weights(call_graph, func_addr)
            # Extract the call graphlet (neighbors) for the function.
            callers: Set[int] = set(idautils.CodeRefsTo(func_addr, 0))
            callees: Set[int] = set(idautils.CodeRefsFrom(func_addr, 0))
            callees_of_callees: Set[int] = set()
            for callee in callees:
                callees_of_callees |= set(idautils.CodeRefsFrom(callee, 0))
            neighbors: Set[int] = (
                callers | callees | callees_of_callees | {func_addr}
            )
            subgraph = nx.DiGraph(call_graph.subgraph(neighbors).copy())
            # Set the computed edge weights as attributes.
            for u, v in subgraph.edges():
                # Cast the edge attributes to a plain dict so we can update them.
                attr: dict[str, Any] = cast(dict, subgraph[u][v])
                attr["weight"] = edge_weights.get((u, v), 0.0)

            # Export the subgraph as JSON.
            export_function_json(
                func_addr, subgraph, edge_weights, SAVE_PATH, file_index
            )
            file_index += 1
            processed += 1
        except Exception as e:
            print(f"Error processing function at 0x{func_addr:x}: {e}")
            continue


if __name__ == "__main__":
    main()
