#!/usr/bin/env python3

import os
from dotenv import load_dotenv  # type: ignore

load_dotenv()

from headless_ida import HeadlessIda  # type: ignore

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
import hashlib

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
def demangle_function_name(name: str) -> None:
    disable_mask = idc.get_inf_attr(idc.INF_SHORT_DN)
    demangled = idc.demangle_name(name, disable_mask)
    return demangled


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
        logger.warning(f"[-] Error getting local variables for 0x{func_addr:x}: {e}")
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
        logger.warning(f"[-] Error getting arguments for 0x{func_addr:x}: {e}")
        return 0


# ---------------------------------------------------------------------
# Global Call Graph Build/Export/Import
# ---------------------------------------------------------------------
def build_global_call_graph(max_funcs: int = -1) -> rx.PyDiGraph:
    G = rx.PyDiGraph(multigraph=False)
    func_to_node = {}

    all_funcs = list(idautils.Functions())
    if max_funcs > 0:
        all_funcs = all_funcs[:max_funcs]

    total_funcs = len(all_funcs)
    logger.debug(f"Discovered {total_funcs} total functions. Building graph...")

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
    graph_data = orjson.loads(Path(filepath).read_bytes())
    G = rx.PyDiGraph(multigraph=False)

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

    for edge_info in graph_data["edges"]:
        src = old_index_to_new[edge_info["source"]]
        tgt = old_index_to_new[edge_info["target"]]
        G.add_edge(src, tgt, None)

    return G


# ---------------------------------------------------------------------
# Integrated Conversion Logic
# ---------------------------------------------------------------------
def process_and_save_subgraphs(
    G: rx.PyDiGraph, save_path: str, include_stripped: bool
) -> None:
    os.makedirs(save_path, exist_ok=True)
    seen_fingerprints = set()

    file2_to_file1 = {}
    if "cgn/eu4_win" in save_path:
        version = save_path.split("_")[-1]
        common_json = orjson.loads(
            Path(f"string_refs/eu4_shared_{version}_string_refs.json").read_bytes()
        )
        for common in common_json:
            for file2_func in common["file2_functions"]:
                if (
                    file2_func not in file2_to_file1
                ):  # First occurrence takes precedence
                    file2_to_file1[file2_func] = common["file1_functions"][0]

    for subgraph_idx in tqdm(
        G.node_indices(),
        total=G.num_nodes(),
        desc="Generating subgraphs",
        mininterval=3.0,
    ):
        payload = G.get_node_data(subgraph_idx)
        subgraph = extract_call_graphlet(G, subgraph_idx)
        if subgraph.num_edges() == 0:
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

        fingerprint = hashlib.sha256(
            orjson.dumps(graph_data, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()

        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        demangled_name = demangle_function_name(payload["name"]) or file2_to_file1.get(
            f"sub_{payload['addr']:X}", None
        )

        if not demangled_name:
            if include_stripped:
                demangled_name = f"{payload['addr']:X}"
            else:
                continue
        demangled_name = demangled_name.split("(")[0]

        if any(
            ns in demangled_name
            for ns in ["std::", "boost::", "tbb::", "__acrt", "__crt"]
        ):
            continue

        # check if function is already saved
        if os.path.exists(os.path.join(save_path, f"{demangled_name}_subgraph.json")):
            continue

        try:
            filename = os.path.join(save_path, f"{demangled_name}_subgraph.json")
            with open(filename, "wb") as f:
                f.write(orjson.dumps(graph_data))
        except:
            continue


def extract_call_graphlet(G: rx.PyDiGraph, func_idx: int) -> rx.PyDiGraph:
    nodes = {func_idx}
    direct_callers = {pred for pred, _, _ in G.in_edges(func_idx)}
    direct_callees = {nbr for _, nbr, _ in G.out_edges(func_idx)}
    nodes.update(direct_callers)
    nodes.update(direct_callees)

    for callee in direct_callees:
        second_level_callees = {nbr for _, nbr, _ in G.out_edges(callee)}
        nodes.update(second_level_callees)

    return G.subgraph(list(nodes))


# ---------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Manage call graphs for IDA.")
    parser.add_argument(
        "--mode",
        choices=["export", "import", "convert"],
        required=True,
        help="Operation mode: export, import, or convert",
    )
    parser.add_argument(
        "--max-funcs",
        type=int,
        default=-1,
        help="Limit number of functions processed",
    )
    parser.add_argument(
        "--filepath",
        type=str,
        default=None,
        help="Path to global graph JSON (import/convert modes)",
    )
    parser.add_argument(
        "--save-path",
        type=str,
        default=None,
        help="Output directory for subgraphs (export/convert modes)",
    )
    parser.add_argument(
        "--target-func-addr",
        type=lambda x: int(x, 0),
        default=None,
        help="Function address for analysis (import mode)",
    )
    parser.add_argument(
        "--include-stripped",
        action="store_true",
        help="Include stripped function names in subgraphs",
    )

    args = parser.parse_args()

    if args.mode == "export":
        logger.info("[+] Building global call graph...")
        G = build_global_call_graph(max_funcs=args.max_funcs)
        identifier = Path(os.getenv("BINARY_PATH")).stem  # type: ignore

        SAVE_PATH = os.path.join(os.getcwd(), "gcgs")

        output_path = os.path.join(SAVE_PATH, f"gcg_{identifier}.json")
        export_call_graph_to_json(G, output_path)
        logger.info(f"[+] Exported global graph to {output_path}")

    elif args.mode == "convert":
        if not args.filepath or not args.save_path:
            logger.error("[!] Requires --filepath and --save-path")
            return

        logger.info("[+] Converting global graph to subgraphs...")
        G = import_call_graph_from_json(args.filepath)
        logger.info(f"Include stripped is {args.include_stripped}")
        process_and_save_subgraphs(G, args.save_path, args.include_stripped)
        logger.info(f"[+] Saved {len(os.listdir(args.save_path))} subgraphs")

    elif args.mode == "import":
        if not args.filepath or not args.target_func_addr:
            logger.error("[!] Requires --filepath and --target-func-addr")
            return

        logger.info("[+] Analyzing target function...")
        G = import_call_graph_from_json(args.filepath)
        target_func_idx = next(
            (
                idx
                for idx, n in enumerate(G.nodes())
                if n["addr"] == args.target_func_addr
            ),
            None,
        )
        if target_func_idx is None:
            logger.error(f"[!] Function 0x{args.target_func_addr:x} not found")
            return

        subgraph = extract_call_graphlet(G, target_func_idx)
        logger.info(f"[+] Subgraph contains {subgraph.num_nodes()} nodes")


if __name__ == "__main__":

    main()
