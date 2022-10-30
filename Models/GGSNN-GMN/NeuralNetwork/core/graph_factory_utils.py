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
#  Gated Graph Sequence Neural Networks (GGSNN) and                          #
#    Graph Matching Networks (GMN) models implementation.                    #
#                                                                            #
#  This implementation contains code from:                                   #
#  https://github.com/deepmind/deepmind-research/blob/master/                #
#    graph_matching_networks/graph_matching_networks.ipynb                   #
#    licensed under Apache License 2.0                                       #
#                                                                            #
##############################################################################

import numpy as np
import tensorflow as tf

from scipy.sparse import coo_matrix
from .graph_factory_base import GraphData

import logging
log = logging.getLogger('gnn')


def str_to_scipy_sparse(mat_str):
    """
    Convert the string in input into a scipy sparse coo matrix. It uses a
    custom str encoding to save space and it's particularly suited for
    sparse matrices, like the graph adjacency matrix.

    Args:
        mat_str: string that encodes a numpy matrix

    Return
        numpy matrix
    """
    row_str, col_str, data_str, n_row, n_col = mat_str.split("::")

    n_row = int(n_row)
    n_col = int(n_col)

    # There are some cases where the BBs are not connected
    # Luckily they are not frequent (~10 among all 10**5 functions)
    if row_str == "" \
            or col_str == "" \
            or data_str == "":
        return np.identity(n_col)

    row = [int(x) for x in row_str.split(";")]
    col = [int(x) for x in col_str.split(";")]
    data = [int(x) for x in data_str.split(";")]
    np_mat = coo_matrix((data, (row, col)),
                        shape=(n_row, n_col)).toarray()
    return np_mat


def pack_batch(graphs, features, use_features, nofeatures_size=1):
    """Pack a batch of graphs into a single `GraphData` instance.

    Args:
      graphs: a list of generated networkx graphs
      features: a list of numpy matrix features.

    Returns:
      graph_data: a `GraphData` instance, with node and edge
        indices properly shifted.
    """
    graphs = tf.nest.flatten(graphs)
    features = tf.nest.flatten(features)
    from_idx = []
    to_idx = []
    node_features = []
    graph_idx = []

    n_total_nodes = 0
    n_total_edges = 0
    for i, d in enumerate(zip(graphs, features)):
        g, f = d[0], d[1]

        n_nodes = g.number_of_nodes()
        n_edges = g.number_of_edges()

        # Bug fix
        #  changed from g.edges() to list(g.edges()) because
        #  there are some cases where the number of nodes == 1
        #  and g.edges() is not iterable
        edges = np.array(list(g.edges()), dtype=np.int32)
        # shift the node indices for the edges
        from_idx.append(edges[:, 0] + n_total_nodes)
        to_idx.append(edges[:, 1] + n_total_nodes)
        node_features.append(f)
        graph_idx.append(np.ones(n_nodes, dtype=np.int32) * i)

        n_total_nodes += n_nodes
        n_total_edges += n_edges

    if use_features:
        # Use features
        node_features = np.concatenate(node_features, axis=0)
    else:
        # No features
        node_features = np.ones(
            (n_total_nodes, nofeatures_size),
            dtype=np.float32)

    return GraphData(
        # from_idx: [n_edges] int tensor, index of the from node for each
        # edge.
        from_idx=np.concatenate(from_idx, axis=0),
        # to_idx: [n_edges] int tensor, index of the to node for each edge.
        to_idx=np.concatenate(to_idx, axis=0),
        # node_features: [n_nodes, node_feat_dim] float tensor.
        node_features=node_features,
        # edge_features: [n_edges, edge_feat_dim] float tensor.
        edge_features=np.ones((n_total_edges, 1), dtype=np.float32),
        # graph_idx: [n_nodes] int tensor, graph id for each node.
        graph_idx=np.concatenate(graph_idx, axis=0),
        # Number of graphs
        n_graphs=len(graphs))
