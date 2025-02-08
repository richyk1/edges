import datetime
import json
import os
from typing import Any, Dict, Set, cast

import idaapi
import idautils
import idc
import networkx as nx

DATE = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
SAVE_PATH = os.path.join(
    os.path.expanduser("~"), "Github", "edges", "cgn_" + DATE
)
os.makedirs(SAVE_PATH, exist_ok=True)


def demangle_function_name(name: str) -> str:
    """
    Demangles a function name using idaapi.demangle_name.

    This function uses the disable mask obtained via get_inf_attr(INF_SHORT_DN)
    to control the demangling process.

    Args:
        name (str): The mangled function name.

    Returns:
        str: The demangled function name if demangling is successful,
             otherwise the original name.
    """
    # Get the demangling mask from the IDA information.
    disable_mask = idc.get_inf_attr(idc.INF_SHORT_DN)

    # Attempt to demangle the name using the retrieved mask.
    demangled = idaapi.demangle_name(name, disable_mask)

    # If demangling fails, return the original name.
    return demangled if demangled is not None else name


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
        G.add_node(func_addr, name=demangle_function_name(func_name))
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

    # Arbitrary limit to massive call graphlets such as
    # void __cdecl __noreturn __clang_call_terminate(void *)
    if len(neighbors) > 1000:
        raise ValueError("Call graphlet too large.")

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
    of its call graphlet and save it as a JSON file.
    """
    # Assign each node in the subgraph a new integer id.
    nodes_list = list(G.nodes())
    node_id_map = {addr: idx for idx, addr in enumerate(nodes_list)}

    # Compute features for every node.
    nodes_json = []
    for addr in nodes_list:
        func_name = demangle_function_name(idc.get_func_name(addr))
        ninstrs = get_instruction_count_bb(addr)
        total_edges = get_total_edges(addr)
        indegree = get_indegree(addr)
        outdegree = get_outdegree(addr)
        nlocals = get_num_local_vars(addr)
        nargs = get_function_arguments(addr)
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
    adjacency = [[] for _ in range(len(nodes_list))]
    for u, v, data in G.edges(data=True):
        u_id = node_id_map[u]
        v_id = node_id_map[v]
        weight = data.get("weight", 0.0)
        adjacency[u_id].append({"id": v_id, "weight": weight})

    json_obj = {
        "adjacency": adjacency,
        "directed": "True",
        "graph": [],
        "multigraph": False,
        "nodes": nodes_json,
    }

    target_name = demangle_function_name(idc.get_func_name(func_addr))
    out_filename = os.path.join(output_dir, f"{file_index}_{target_name}.json")
    with open(out_filename, "w") as f:
        json.dump(json_obj, f, indent=None)
    print(f"Saved JSON for function {target_name} to {out_filename}")


def main() -> None:
    """
    Main processing function:
      - Builds the global call graph.
      - After each BATCH_SIZE functions.
      - Exports each function's call graphlet as JSON.
    """
    print(f"Saving JSON files to: {SAVE_PATH}")
    call_graph = build_call_graph()

    functions = idautils.Functions()
    file_index = 0
    while True:
        func_addr = next(functions, None)
        if func_addr is None:
            break

        func_name = idc.get_func_name(func_addr)
        print(f"Processing function at 0x{func_addr:x} ({func_name})")

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
                attr: dict[str, Any] = cast(dict, subgraph[u][v])
                attr["weight"] = edge_weights.get((u, v), 0.0)

            export_function_json(
                func_addr, subgraph, edge_weights, SAVE_PATH, file_index
            )
            file_index += 1
        except Exception as e:
            print(f"Error processing function at 0x{func_addr:x}: {e}")
            continue

    print("Processing complete.")


if __name__ == "__main__":
    main()
