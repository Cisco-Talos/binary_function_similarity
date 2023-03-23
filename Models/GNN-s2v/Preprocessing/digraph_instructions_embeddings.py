#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  MIT License                                                               #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  Permission is hereby granted, free of charge, to any person obtaining     #
#  a copy of this software and associated documentation files (the           #
#  "Software"), to deal in the Software without restriction, including       #
#  without limitation the rights to use, copy, modify, merge, publish,       #
#  distribute, sublicense, and/or sell copies of the Software, and to        #
#  permit persons to whom the Software is furnished to do so, subject to     #
#  the following conditions:                                                 #
#                                                                            #
#  The above copyright notice and this permission notice shall be            #
#  included in all copies or substantial portions of the Software.           #
#                                                                            #
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,           #
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF        #
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                     #
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE    #
#  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION    #
#  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION     #
#  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.           #
#                                                                            #
#  digraph_instructions_embeddings.py - Convert each function into a         #
#    NetworkX graph. Normalized instructions are translated into embeddings. #
#                                                                            #
##############################################################################

import click
import json
import networkx as nx
import numpy as np
import os

from collections import defaultdict
from scipy.sparse import coo_matrix
from tqdm import tqdm


def create_graph(node_list, edge_list):
    """
    Create a Networkx direct graph from the list of nodes and edges.

    Args
        node_list: list of nodes
        edge_list: list of edges

    Return
        np.matrix: Numpy adjacency matrix
        list: list of nodes
    """
    G = nx.DiGraph()
    for node in node_list:
        G.add_node(node)
    node_set = set(node_list)
    for edge in edge_list:
        if edge[0] in node_set and edge[1] in node_set:
            G.add_edge(edge[0], edge[1])

    node_list = list(G.nodes())
    adj_mat = nx.to_numpy_matrix(G, nodelist=node_list, dtype=np.int8)
    return adj_mat, node_list


def convert_instructions(node_list, fva_data, ins2id_dict, max_instructions):
    """
    Convert basic block instructions into list of IDs.

    Args
        node_list: list of basic-blocks addresses
        fva_data: dict with features associated to a function
        ins2id_dict: a dictionary that maps instructions to numerical IDs
        max_instructions: maximum number of instructions per basic block

    Return
        str: enocded list of numerical identifiers
    """
    f_mat = list()

    # Iterate over each BBs
    for node_idx, node_fva in enumerate(node_list):
        node_data = fva_data["basic_blocks"].get(str(node_fva), None)
        if not node_data:
            print("[!] cannot find node data for {}".format(str(node_fva)))
            continue
        norm_ids_list = list()
        for ins in node_data["bb_norm"]:
            norm_ids_list.append(ins2id_dict.get(ins, -1))

        # Each ID is an index in the embedding matrix.
        # Note that IDs in ins2id_dict start from -1, but indexes from 0.
        # Add a +1 to convert one to the other.
        norm_ids_list = [x + 1 for x in norm_ids_list][:max_instructions]

        # No padding added
        f_mat.append(";".join(map(str, norm_ids_list)))

    return "::".join(f_mat)


def np_to_scipy_sparse(np_mat):
    """
    Convert the Numpy matrix in input to a Scipy sparse matrix.

    Args
        np_mat: a Numpy matrix

    Return
        str: serialized adj matrix
    """
    cmat = coo_matrix(np_mat)
    # Custom string serialization
    row_str = ";".join([str(x) for x in cmat.row])
    col_str = ";".join([str(x) for x in cmat.col])
    data_str = ";".join([str(x) for x in cmat.data])
    n_row = str(np_mat.shape[0])
    n_col = str(np_mat.shape[1])
    mat_str = "::".join([row_str, col_str, data_str, n_row, n_col])
    return mat_str


def create_functions_dict(input_folder, ins2id_json, max_instructions):
    """
    Generate the adjacency and features matrix.

    Args
        input_folder: a folder with JSON files from IDA_acfg_disasm
        ins2id_dict: a dictionary that maps instructions to numerical IDs
        max_instructions: maximum number of instructions per basic block

    Return
        dict: a dictionary with serialized adj and features matrices
    """
    try:
        ins2id_dict = None
        # Map normalized instructions to indexes in the embedding matrix
        if os.path.isfile(ins2id_json):
            with open(ins2id_json) as f_in:
                ins2id_dict = json.load(f_in)
        if not ins2id_dict:
            print("[!] Error loading {}".format(ins2id_json))
            return dict()

        functions_dict = defaultdict(dict)

        for f_json in tqdm(os.listdir(input_folder)):
            if not f_json.endswith(".json"):
                continue

            json_path = os.path.join(input_folder, f_json)
            with open(json_path) as f_in:
                jj = json.load(f_in)

                idb_path = list(jj.keys())[0]
                print("[D] Processing: {}".format(idb_path))
                j_data = jj[idb_path]
                del j_data["arch"]

                # Iterate over each function
                for fva in j_data:
                    fva_data = j_data[fva]

                    g_mat, nodes = create_graph(fva_data["nodes"], fva_data["edges"])
                    graph_str = np_to_scipy_sparse(g_mat)
                    features_str = convert_instructions(
                        nodes, fva_data, ins2id_dict, max_instructions
                    )

                    functions_dict[idb_path][fva] = {
                        "adj_mat": graph_str,
                        "features_mat": features_str,
                    }
        return functions_dict

    except Exception as e:
        print("[!] Exception in create_functions_dict\n{}".format(e))
        return dict()


def log_instructions_coverage(functions_dict, output_dir):
    """
    Log functions that have more than 50% of UNK instructions.

    Args:
        functions_dict: a dictionary with functions' adj and features mat
        output_dir: output directory
    """
    output_path = os.path.join(output_dir, "log_coverage.txt")
    f_out = open(output_path, "w")

    for idb in functions_dict.keys():
        for fva in functions_dict[idb].keys():
            cc, tot_len = 0, 0
            f_mat = functions_dict[idb][fva]["features_mat"]
            for row in f_mat.split("::"):
                tmp = [0 if int(x) == 0 else 1 for x in row.split(";") if x]
                cc += sum(tmp)
                tot_len += len(tmp)
            coverage = cc / tot_len * 100
            if coverage < 50:
                f_out.write(
                    "[D] {}:{} Low coverage: {}% ({}/{})\n".format(
                        idb, fva, np.around(coverage, 2), cc, tot_len
                    )
                )
    f_out.close()


@click.command()
@click.option("-i", "--input-dir", required=True, help="IDA_acfg_disasm JSON files.")
@click.option(
    "-d",
    "--ins2id-json",
    default="instruction_embeddings/ins2id.json",
    help="The ins2id JSON file.",
)
@click.option(
    "-m",
    "--max-instructions",
    default=200,
    help="Maximum instructions per basic blocks.",
)
@click.option("-o", "--output-dir", required=True, help="Output directory.")
def main(input_dir, ins2id_json, max_instructions, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    o_dict = create_functions_dict(input_dir, ins2id_json, max_instructions)
    o_json = "digraph_instructions_embeddings_{}.json".format(max_instructions)
    output_path = os.path.join(output_dir, o_json)
    with open(output_path, "w") as f_out:
        json.dump(o_dict, f_out)
    log_instructions_coverage(o_dict, output_dir)


if __name__ == "__main__":
    main()
