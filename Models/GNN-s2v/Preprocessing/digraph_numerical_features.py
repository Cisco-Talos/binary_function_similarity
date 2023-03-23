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
#  digraph_numerical_features.py - Convert each function into a NetworkX     #
#    graph and associate each basic block to the corresponding features.     #
#                                                                            #
##############################################################################

import base64
import click
import itertools
import json
import networkx as nx
import numpy as np
import os

from collections import defaultdict
from multiprocessing import Pool
from scipy.sparse import coo_matrix
from tqdm import tqdm

# Number of numerical features
NUM_ACFG_FEATURES = 8


def create_graph(node_list, edge_list):
    """
    Create a Networkx direct graph from the list of nodes and edges.

    Args
        node_list: list of nodes
        edge_list: list of edges

    Return
        np.matrix: Numpy adjacency matrix
        nx.DiGraph: Networkx direct graph CFG
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
    return adj_mat, G


def get_n_offspring(G, bb_va):
    """
    Return the number of reachable nodes.

    Args
        G: nx.DiGraph CFG
        bb_va: basic block virtual address

    Return
        int: basic block offspring
    """
    return len(nx.descendants(G, bb_va))


def chunks(ll, n):
    """
    Divide a list of nodes `ll` in `n` chunks

    Source: https://networkx.org/documentation/stable/
      auto_examples/algorithms/plot_parallel_betweenness.html
    """
    l_c = iter(ll)
    while 1:
        x = tuple(itertools.islice(l_c, n))
        if not x:
            return
        yield x


def betweenness_centrality_parallel(G, processes=None):
    """
    Parallel betweenness centrality  function

    Source: https://networkx.org/documentation/stable/
      auto_examples/algorithms/plot_parallel_betweenness.html
    """
    bt_sc = []
    with Pool(processes=processes) as p:
        node_divisor = len(p._pool) * 4
        node_chunks = list(
            chunks(G.nodes(), int(G.order() / node_divisor) + 1))
        num_chunks = len(node_chunks)
        bt_sc = p.starmap(
            nx.betweenness_centrality_subset,
            zip(
                [G] * num_chunks,
                node_chunks,
                [list(G)] * num_chunks,
                [True] * num_chunks,
                [None] * num_chunks,
            ),
        )

    # Reduce the partial solutions
    bt_c = bt_sc[0]
    for bt in bt_sc[1:]:
        for n in bt:
            bt_c[n] += bt[n]
    return bt_c


def create_features_matrix(G, fva_data, num_processes):
    """
    Create the matrix with numerical features.

    Args
        G: nx.DiGraph CFG
        fva_data: dict with features associated to a function
        num_processes: number of parallel processes

    Return
        np.array: Numpy matrix with numerical features
    """
    f_mat = list()

    if G.order() > 200:
        betweenness = betweenness_centrality_parallel(
            G, min(int(G.order() / 100), num_processes))
    else:
        betweenness = nx.betweenness_centrality(G)

    # Iterate over each BBs
    for node_idx, node_va in enumerate(list(G.nodes())):
        node_data = fva_data["basic_blocks"][str(node_va)]
        f_mat.append([
            # 'n_string_consts'
            node_data['n_string_consts'],
            # 'n_numeric_consts'
            node_data['n_numeric_consts'],
            # 'n_transfer_instrs'
            node_data['n_transfer_instrs'],
            # 'n_calls'
            node_data['n_call_instrs'],
            # 'n_instructions'
            node_data['n_instructions'],
            # 'n_arith_instrs'
            node_data['n_arith_instrs'],
            # 'n_offspring'
            get_n_offspring(G, node_va),
            # 'betweenness'
            betweenness[node_va]
        ])

    # Here I'm forcing the dtype to float32, to limit memory spaces
    # If you want to change the type (e.g., use float64), be
    # sure to change the parsing method on the respective
    # function.
    return np.array(f_mat, dtype=np.float32)


def np_to_str(np_mat):
    """
    Args
        np.array: numpy matrix

    Return
        str: serialized matrix
    """
    strides = np_mat.strides
    shape = np_mat.shape
    np_str = "{}::{}::{}::{}::{}".format(
        strides[0], strides[1], shape[0], shape[1],
        base64.b64encode(np_mat.tobytes('C')).decode('ascii'))
    return np_str


def np_to_scipy_sparse(np_mat):
    """
    Convert the numpy matrix in input to a scipy coo sparse matrix.

    Args
        np_mat: a Numpy matrix

    Return
        str: serialized adj matrix
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


def create_functions_dict(input_folder, num_processes):
    """
    Args
        input_folder: a folder with JSON files from IDA_acfg_features
        num_processes: number of parallel processes

    Return
        dict: a dictionary with serialized adj and features matrices
    """
    try:
        functions_dict = defaultdict(dict)

        for f_json in tqdm(os.listdir(input_folder)):
            if not f_json.endswith(".json"):
                continue

            f_path = os.path.join(input_folder, f_json)
            with open(f_path) as f_in:
                jj = json.load(f_in)

                idb_path = list(jj.keys())[0]
                print("[D] Processing: {}".format(idb_path))
                j_data = jj[idb_path]

                # Iterate over each function
                for fva in j_data:
                    fva_data = j_data[fva]

                    g_mat, G = create_graph(
                        fva_data['nodes'], fva_data['edges'])
                    f_mat = create_features_matrix(G, fva_data, num_processes)

                    graph_str = np_to_scipy_sparse(g_mat)
                    features_str = np_to_str(f_mat)

                    functions_dict[idb_path][fva] = {
                        'adj_mat': graph_str,
                        'features_mat': features_str
                    }

        return functions_dict
    except Exception as e:
        print("[!] Exception in create_functions_dict\n{}".format(e))
        return dict()


@click.command()
@click.option('-i', '--input-dir', required=True,
              help='IDA_acfg_features JSON files.')
@click.option('-p', '--num-processes',
              default=20,
              help='Maximum number of processes.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(input_dir, output_dir, num_processes):
    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    o_dict = create_functions_dict(input_dir, num_processes)
    output_path = os.path.join(output_dir,
                               'digraph_numerical_features.json')
    with open(output_path, 'w') as f_out:
        json.dump(o_dict, f_out)


if __name__ == '__main__':
    main()
