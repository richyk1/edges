import os
from typing import Dict, Set

import idaapi
import idautils
import idc
import networkx as nx

# Build the save path using os.path.join for OS independence.
SAVE_PATH = os.path.join(os.path.expanduser("~"), "Github", "edges")
MAX_FUNCTIONS = 100  # Change this constant to process more functions if needed.


def get_instruction_count_bb(func_addr: int) -> int:
    """
    Counts the number of instructions in a function using its basic blocks.
    (Feature: Number of instructions)
    """
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
    """
    Returns the number of times a function is explicitly called.
    (Feature: Total Indegree)
    """
    return sum(1 for _ in idautils.CodeRefsTo(func_addr, 0))


def get_outdegree(func_addr: int) -> int:
    """
    Returns the number of times a function explicitly calls another function.
    (Feature: Total Outdegree)
    """
    return sum(1 for _ in idautils.CodeRefsFrom(func_addr, 0))


def get_total_edges(func_addr: int) -> int:
    """
    Returns the total number of edges (in-degree + out-degree).
    """
    return get_indegree(func_addr) + get_outdegree(func_addr)


def get_num_local_vars(func_addr: int) -> int:
    """
    Returns the number of local variables in a function.
    (Feature: Number of local variables)
    This directly iterates over the structure members of the function's frame.
    """
    frame_id = idc.get_frame_id(func_addr)
    count = 0
    for member in idautils.StructMembers(frame_id):
        if "var" in member[1]:
            count += 1
    return count


def get_function_arguments(func_addr: int) -> int:
    """
    Attempts to retrieve the number of function arguments.
    (Feature: Number of arguments)
    First, it uses type information; if unavailable, it falls back to counting
    structure members that indicate arguments.
    """
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


def compute_edge_weights(G: nx.DiGraph, func_addr: int) -> Dict:
    """
    Computes edge betweenness centrality within the call graphlet for a given function.

    According to the paper, a call graphlet for the target function includes:
      - Its direct callers (C₁)
      - Its direct callees (C₂)
      - The callees-of-callees (C₃) for each direct callee
      - And the target function itself.

    This function extracts that neighborhood and computes the edge betweenness centrality,
    which serves as the weight for each edge in the subgraph.
    """
    # Get direct callers and callees
    callers: Set[int] = set(idautils.CodeRefsTo(func_addr, 0))
    callees: Set[int] = set(idautils.CodeRefsFrom(func_addr, 0))

    # For each direct callee, add its callees (second-degree)
    callees_of_callees: Set[int] = set()
    for callee in callees:
        callees_of_callees |= set(idautils.CodeRefsFrom(callee, 0))

    # Build the call graphlet as defined in the paper.
    neighbors: Set[int] = callers | callees | callees_of_callees | {func_addr}
    subgraph = G.subgraph(neighbors)
    # Compute and return edge betweenness centrality on the subgraph.
    return nx.edge_betweenness_centrality(subgraph)


def get_function_info(func_ea: int, edge_weights: Dict) -> None:
    """
    Retrieves and prints the function features and the corresponding edge weights within
    its call graphlet.

    Features include:
      - Number of instructions
      - Total edges (in-degree + out-degree)
      - Indegree
      - Outdegree
      - Number of local variables
      - Number of arguments

    Also prints each edge weight for the incoming (caller → function) and outgoing
    (function → callee) edges.
    """
    func_name = idaapi.get_func_name(func_ea)
    instr_count = get_instruction_count_bb(func_ea)
    total_edges = get_total_edges(func_ea)
    indegree = get_indegree(func_ea)
    outdegree = get_outdegree(func_ea)
    local_vars = get_num_local_vars(func_ea)
    num_args = get_function_arguments(func_ea)

    print(f"\nFunction: {func_name}")
    print(f"  Num instructions: {instr_count}")
    print(f"  Num edges: {total_edges}")
    print(f"  Total Indegree: {indegree}")
    print(f"  Total Outdegree: {outdegree}")
    print(f"  Num local vars: {local_vars}")
    print(f"  Num args: {num_args}")

    # Print edge weights for incoming edges (caller → function)
    for caller in idautils.CodeRefsTo(func_ea, 0):
        weight = edge_weights.get((caller, func_ea), 0.0)
        print(
            f"  Edge from {idaapi.get_func_name(caller)} → {func_name} | Weight: {weight:.4f}"
        )
    # Print edge weights for outgoing edges (function → callee)
    for callee in idautils.CodeRefsFrom(func_ea, 0):
        weight = edge_weights.get((func_ea, callee), 0.0)
        print(
            f"  Edge from {func_name} → {idaapi.get_func_name(callee)} | Weight: {weight:.4f}"
        )


def main() -> None:
    """
    Main processing function:
      - Builds the global call graph.
      - For each function (up to MAX_FUNCTIONS), extracts its call graphlet,
        computes edge weights using edge betweenness centrality, and prints its features.
    """
    call_graph = build_call_graph()
    functions = idautils.Functions()
    processed = 0

    while processed < MAX_FUNCTIONS:
        func_addr = next(functions, None)
        if func_addr is None:
            break
        try:
            edge_weights = compute_edge_weights(call_graph, func_addr)
            get_function_info(func_addr, edge_weights)
            processed += 1
        except Exception as e:
            print(f"Error processing function at 0x{func_addr:x}: {e}")
            continue


if __name__ == "__main__":
    main()
