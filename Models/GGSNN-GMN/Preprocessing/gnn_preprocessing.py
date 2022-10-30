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
#  gnn_preprocessing.py - Convert each function into a graph with            #
#    BB-level features.                                                      #
#                                                                            #
##############################################################################

import click
import json
import networkx as nx
import numpy as np
import os

from collections import Counter
from collections import defaultdict
from scipy.sparse import coo_matrix
from tqdm import tqdm


def get_top_opcodes(input_folder, num_opc):
    """
    Extract the list of most frequent opcodes across the training data.

    Args:
        input_folder: a folder with JSON files from IDA_acfg_disasm
        num_opc: the number of most frequent opcodes to select.

    Return
        dict: map most common opcodes to their ranking.
    """
    opc_cnt = Counter()

    for f_json in tqdm(os.listdir(input_folder)):
        if not f_json.endswith(".json"):
            continue

        json_path = os.path.join(input_folder, f_json)
        with open(json_path) as f_in:
            jj = json.load(f_in)

            idb_path = list(jj.keys())[0]
            # print("[D] Processing: {}".format(idb_path))
            j_data = jj[idb_path]
            del j_data['arch']

            # Iterate over each function
            for fva in j_data:
                fva_data = j_data[fva]
                # Iterate over each basic-block
                for bb in fva_data['basic_blocks']:
                    opc_cnt.update(fva_data['basic_blocks'][bb]['bb_mnems'])

    print("[D] Found: {} mnemonics.".format(len(opc_cnt.keys())))
    print("[D] Top 10 mnemonics: {}".format(opc_cnt.most_common(10)))
    return {d[0]: c for c, d in enumerate(opc_cnt.most_common(num_opc))}


def create_graph(nodes, edges):
    """
    Create a NetworkX direct graph from the list of nodes and edges.

    Args:
        node_list: list of nodes
        edge_list: list of edges

    Return
        np.matrix: Numpy adjacency matrix
        list: nodes in the graph
    """
    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node)
    for edge in edges:
        G.add_edge(edge[0], edge[1])

    nodelist = list(G.nodes())
    adj_mat = nx.to_numpy_matrix(G, nodelist=nodelist, dtype=np.int8)
    return adj_mat, nodelist


def create_features_matrix(node_list, fva_data, opc_dict):
    """
    Create the matrix with numerical features.

    Args:
        node_list: list of basic-blocks addresses
        fva_data: dict with features associated to a function
        opc_dict: selected opcodes.

    Return
        np.matrix: Numpy matrix with selected features.
    """
    f_mat = np.zeros((len(node_list), len(opc_dict)))

    # Iterate over each BBs
    for node_idx, node_fva in enumerate(node_list):
        if str(node_fva) not in fva_data["basic_blocks"]:
            # Skipping node
            continue
        node_data = fva_data["basic_blocks"][str(node_fva)]
        for mnem in node_data["bb_mnems"]:
            if mnem in opc_dict:
                mnem_idx = opc_dict[mnem]
                f_mat[node_idx][mnem_idx] += 1
    # WARNING
    # Forcing the type to np.int8 to limit memory usage.
    #   Use the same when parsing the data!
    return f_mat.astype(np.int8)


def np_to_scipy_sparse(np_mat):
    """
    Convert the Numpy matrix in input to a Scipy sparse matrix.

    Args:
        np_mat: a Numpy matrix

    Return
        str: serialized matrix
    """
    cmat = coo_matrix(np_mat)
    # Custom string serialization
    row_str = ';'.join([str(x) for x in cmat.row])
    col_str = ';'.join([str(x) for x in cmat.col])
    data_str = ';'.join([str(x) for x in cmat.data])
    n_row = str(np_mat.shape[0])
    n_col = str(np_mat.shape[1])
    mat_str = "::".join([row_str, col_str, data_str, n_row, n_col])
    return mat_str


def create_functions_dict(input_folder, opc_dict):
    """
    Convert each function into a graph with BB-level features.

    Args:
        input_folder: a folder with JSON files from IDA_acfg_disasm
        opc_dict: dictionary that maps most common opcodes to their ranking.

    Return
        dict: map each function to a graph and features matrix
    """
    try:
        functions_dict = defaultdict(dict)

        for f_json in tqdm(os.listdir(input_folder)):
            if not f_json.endswith(".json"):
                continue

            json_path = os.path.join(input_folder, f_json)
            with open(json_path) as f_in:
                jj = json.load(f_in)

                idb_path = list(jj.keys())[0]
                # print("[D] Processing: {}".format(idb_path))
                j_data = jj[idb_path]
                del j_data['arch']

                # Iterate over each function
                for fva in j_data:
                    fva_data = j_data[fva]
                    g_mat, nodes = create_graph(
                        fva_data['nodes'], fva_data['edges'])
                    f_mat = create_features_matrix(
                        nodes, fva_data, opc_dict)
                    functions_dict[idb_path][fva] = {
                        'graph': np_to_scipy_sparse(g_mat),
                        'opc': np_to_scipy_sparse(f_mat)
                    }

        return functions_dict

    except Exception as e:
        print("[!] Exception in create_functions_dict\n{}".format(e))
        return dict()


@click.command()
@click.option('-i', '--input-dir', required=True,
              help='IDA_acfg_disasm JSON files.')
@click.option('--training', required=True, is_flag=True,
              help='Process training data')
@click.option('-n', '--num-opcodes',
              default=200,
              help='Number of most frequent opcodes.')
@click.option('-d', '--opcodes-json',
              default="opcodes_dict.json",
              help='JSON with selected opcodes.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(input_dir, training, num_opcodes, opcodes_json, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    if training:
        opc_dict = get_top_opcodes(input_dir, num_opcodes)
        output_path = os.path.join(output_dir, opcodes_json)
        with open(output_path, "w") as f_out:
            json.dump(opc_dict, f_out)
    else:
        if not os.path.isfile(opcodes_json):
            print("[!] Error loading {}".format(opcodes_json))
            return
        with open(opcodes_json) as f_in:
            opc_dict = json.load(f_in)

    if not training and num_opcodes > len(opc_dict):
        print("[!] Num opcodes is greater than training ({} > {})".format(
            num_opcodes, len(opc_dict)))
        return

    o_dict = create_functions_dict(input_dir, opc_dict)
    o_json = "graph_func_dict_opc_{}.json".format(num_opcodes)
    output_path = os.path.join(output_dir, o_json)
    with open(output_path, 'w') as f_out:
        json.dump(o_dict, f_out)


if __name__ == '__main__':
    main()
