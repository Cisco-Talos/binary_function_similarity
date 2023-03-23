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
#  Implementation of the models based on Graph Neural Network (GNN)          #
#    and Structure2vec (s2v).                                                #
#                                                                            #
##############################################################################

import base64
import numpy as np

from .pair_factory_base import PairData
from scipy.sparse import coo_matrix

import logging

log = logging.getLogger("s2v")


def str_to_matrix(mat_str):
    """
    Convert the string in input into a numpy matrix. It uses a
    custom ":" and ";" separated encoding to save space.

    Args
        mat_str: string that encodes a python matrix

    Return
        numpy matrix
    """
    matrix = list()
    for v in mat_str.split("::"):
        if len(v) > 0:
            matrix.append([int(x) for x in v.split(";")])
        else:
            matrix.append([])
    max_len = max([len(v) for v in matrix])
    return pad_features_matrix(matrix, max_len)[0]


def str_to_np(np_str):
    """
    Convert the string in input into a numpy matrix. It uses a
    custom "::" separated encoding to save space.

    Args
        np_str: string that encodes a numpy matrix

    Return
        numpy matrix
    """
    st_0, st_1, sh_0, sh_1, b64str = np_str.split("::")

    shape = (int(sh_0), int(sh_1))
    strides = (int(st_0), int(st_1))

    temp = np.frombuffer(base64.b64decode(b64str), dtype=np.float32)
    np_mat = np.lib.stride_tricks.as_strided(temp, shape, strides)
    return np_mat


def str_to_scipy_sparse(mat_str):
    """
    Convert the string in input into a scipy sparse coo matrix. It uses a
    custom str encoding to save space and it's particularly suited for
    sparse matrices, like the graph adjacency matrix.

    Args
        mat_str: string that encodes a numpy matrix

    Return
        numpy matrix
    """
    row_str, col_str, data_str, n_row, n_col = mat_str.split("::")

    n_row = int(n_row)
    n_col = int(n_col)

    # There are some cases where the BBs are not connected
    # Luckily they are not frequent (~10 among all 10**5 functions)
    if row_str == "" or col_str == "" or data_str == "":
        return np.identity(n_col)

    row = [int(x) for x in row_str.split(";")]
    col = [int(x) for x in col_str.split(";")]
    data = [int(x) for x in data_str.split(";")]
    np_mat = coo_matrix((data, (row, col)), shape=(n_row, n_col)).toarray()
    return np_mat


def pad_matrix_list(matrix_list, max_num_vertices, is_adj, network_type):
    """
    Pad all the matrices in the list, so that they have the same number of
    vertices. The output is 3-d numpy matrix.

    Args
        matrix_list: list of numpy adj matrices
        max_num_vertices: maximum number of nodoes (fixed by configuration)
        is_adj: True if it's a list of adjacency matrices.
        network_type: type of NN

    Return
        a numpy ndarray (list of adj matrices), dtype: np.float32
    """
    new_matrix_list = list()
    for mat in matrix_list:
        # If a matrix is bigger than max_num_vertices, downsize it
        mat = mat[:max_num_vertices]

        # If a matrix is smaller than max_num_vertices, calculate the
        # padding size and pad it.
        pad_length_v = max_num_vertices - mat.shape[0]

        # An adj matrix is squared, so #rows is equal to the #columns.
        if is_adj:
            # Adj matrix are squared, so downsize on both rows and columns
            mat = mat[:max_num_vertices, :max_num_vertices]
            # Pad to the correct length.
            mat = np.pad(mat, [(0, pad_length_v), (0, pad_length_v)], mode="constant")
        else:
            # If it's a feature matrix, just pad the rows.
            # Columns are padded using the pad_features_matrix function
            mat = np.pad(mat, [(0, pad_length_v), (0, 0)], mode="constant")
        new_matrix_list.append(mat)

    if is_adj or network_type == "annotations":
        # If it's an ajd matrix of type 'acfg', use np.float32
        # as dtype. It's related to how the TF model is implemented: matrix
        # multiplication requires the matrices to have the same dtype and they
        # are not converted.
        np_ndarray = np.array(new_matrix_list, dtype=np.float32)
    else:
        # Otherwise set to np.int32 - those are indexes for the
        # embeddings lookup.
        np_ndarray = np.array(new_matrix_list, dtype=np.int32)

    return np_ndarray


def pad_vector_list(vector_list, max_num_vertices):
    """
    Pad all the vectors in the list, so that they have the same number of
    vertices. The output is 2-d numpy matrix.

    Args
        vector_list: list of numpy vectors
        max_num_vertices: maximum number of nodoes (fixed by configuration)

    Return
        a numpy ndarray (list of vectors), dtype: np.int32
    """
    new_vector_list = list()

    for v in vector_list:
        # If a vector is bigger than max_num_vertices, downsize it
        v = v[:max_num_vertices]

        # If a vector is smaller than max_num_vertices, calculate the
        # padding size and pad it.
        pad_length_v = max_num_vertices - v.shape[0]
        v = np.pad(v, (0, pad_length_v), mode="constant")
        new_vector_list.append(v)

    new_vector_list = np.array(new_vector_list, dtype=np.int32)
    return new_vector_list


def pad_features_matrix(matrix, max_features):
    """
    Pad the feature matrix to the max_features #columns.

    Args
        matrix: a numpy features matrix
        max_features: maximum number of features (by configuration)
          Usually it refers to the maximum number of instructions per BB

    Return
        numpy columns padded matrix
        an array with the original column length (useful for the RNN model)
    """
    new_matrix = list()
    col_lengths = list()
    for v in matrix:
        v = np.array(v)
        # Cut to max_features
        v = v[:max_features]
        # WARNING: do not change the order of this operation
        # You want to take the length after the cut
        col_lengths.append(v.shape[0])

        pad_length = max_features - v.shape[0]
        v = np.pad(v, [(0, pad_length)], mode="constant", constant_values=0)
        new_matrix.append(v)

    # Note: dtype is not set at this stage, because it depends by the type
    # features.
    np_matrix = np.array(new_matrix)
    np_lengths = np.array(col_lengths, dtype=np.int32)
    return np_matrix, np_lengths


def pack_batch(
    f_list_1,
    f_list_2,
    adj_list_1,
    adj_list_2,
    len_list_1,
    len_list_2,
    max_num_vertices,
    network_type,
):
    """Pack a batch of graphs and features into a single `PairData`
    instance.

    Args
        f_list_1: list of features matrix
        f_list_2: list of features matrix
        adj_list_1: list of adjacency matrix
        adj_list_2: list of adjacency matrix
        len_list_1: list of lengths
        len_list_2: list of lengths
        max_num_vertices: max number of vertices in a graph
        network_type: type of features

    Return
        an instance of `PairData`
    """

    f_list_1 = pad_matrix_list(
        f_list_1, max_num_vertices, is_adj=False, network_type=network_type
    )

    adj_list_1 = pad_matrix_list(
        adj_list_1, max_num_vertices, is_adj=True, network_type=network_type
    )

    len_list_1 = pad_vector_list(len_list_1, max_num_vertices)

    f_list_2 = pad_matrix_list(
        f_list_2, max_num_vertices, is_adj=False, network_type=network_type
    )

    adj_list_2 = pad_matrix_list(
        adj_list_2, max_num_vertices, is_adj=True, network_type=network_type
    )

    len_list_2 = pad_vector_list(len_list_2, max_num_vertices)

    # Pack everything in a PairData structure
    graphs = PairData(
        x_1=f_list_1,
        adj_1=adj_list_1,
        lengths_1=len_list_1,
        x_2=f_list_2,
        adj_2=adj_list_2,
        lengths_2=len_list_2,
    )
    return graphs
