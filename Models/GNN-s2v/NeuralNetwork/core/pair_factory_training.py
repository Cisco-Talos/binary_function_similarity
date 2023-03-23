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

import json
import math
import numpy as np
import pandas as pd

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from collections import defaultdict
from random import Random
from tqdm import tqdm

import logging

log = logging.getLogger("s2v")


class PairFactoryTraining(PairFactoryBase):
    def __init__(
        self,
        func_path,
        feat_path,
        batch_size,
        features_type,
        network_type,
        max_num_vertices,
        length_raw_features,
    ):
        """
        Args
            func_path: CSV file with training functions
            feat_path: JSON file with function features
            batch_size: size of the batch for each iteration
            features_type: used to select the appropriate decoder and data
            max_num_vertices: maximum number of nodes in the adjancey matrix
            length_raw_features: maximum number of raw features for each BB
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (training): {}".format(self._batch_size))

        self._max_num_vertices = max_num_vertices
        self._network_type = network_type

        self._ftype = features_type
        self._length_raw_features = length_raw_features

        # Based on the type of model/features used use a different decoder
        self._decoder = str_to_np
        if self._ftype == "asm":
            self._decoder = str_to_matrix
        # if self._ftype == "opc":
        #     self._decoder = str_to_scipy_sparse

        self._load_data(func_path, feat_path)

        # For reproducibility
        # Do not change the seed
        self._random = Random()
        self._random.seed(11)
        # self._np_random_state = np.random.RandomState(11)

        # Initialize the iterator
        self._get_next_pair_it = self._get_next_pair()

        # Number of pairs for the positive or negative DF.
        # Since this is a random batch generator, this number must be defined.
        # TODO set them to appropriate values for the model
        self._num_func_pairs = 40000
        log.info("Tot num func pairs (training): {}".format(self._num_func_pairs * 2))

        # _get_next_pair() returns 2 pairs (1 positive and 1 negative)
        # _batch_size must be even and >= 2
        # _num_batches is the number of iterations to cover the input data
        # Example:
        #   * 100 Pos + 100 Neg functions. Batch_size = 20; 10 iterations
        #   * 100 Pos + 100 Neg functions. Batch_size = 16; 12 iterations and
        #       8 function pairs discarded
        self._num_batches_in_epoch = math.floor(
            self._num_func_pairs / (self._batch_size / 2)
        )
        log.info(
            "Num batches in epoch (training): {}".format(self._num_batches_in_epoch)
        )

        self._num_pairs_in_epoch = self._num_batches_in_epoch * int(
            self._batch_size / 2
        )
        log.info(
            "Tot num func pairs per epoch (training): {}".format(
                self._num_pairs_in_epoch * 2
            )
        )

    def _load_data(self, func_path, feat_path):
        """
        Load the training data (functions and features)

        Args
            func_path: CSV file with training functions
            feat_path: JSON file with function features
        """
        # Load CSV with the list of functions
        log.debug("Reading {}".format(func_path))
        # Read the CSV and reset the index
        self._df_func = pd.read_csv(func_path, index_col=0)
        self._df_func.reset_index(drop=True, inplace=True)

        # Get the list of indexes associated to each function name
        self._func_name_dict = defaultdict(set)
        for i, f in enumerate(self._df_func.func_name):
            self._func_name_dict[f].add(i)
        # Get the list of unique function name
        self._func_name_list = list(self._func_name_dict.keys())
        log.debug("Found {} functions".format(len(self._func_name_list)))

        # Load the JSON with functions graphs and features
        log.debug("Loading {}".format(feat_path))
        with open(feat_path) as gfd_in:
            self._fdict = json.load(gfd_in)

    def _select_random_function_pairs(self):
        """
        Return
            a tuple (pos_p, neg_p) where pos_p and neg_g are a tuple
            like (['idb_path_1', 'fva_1'], ['idb_path_2', 'fva_2'])
        """
        func_poll_one, func_poll_two = set(), set()

        while 1:
            # Get two random function names
            fn1, fn3 = self._random.sample(self._func_name_list, k=2)

            # Select functions with the same name
            func_poll_one = self._func_name_dict[fn1]

            # Select other functions with the same name
            func_poll_two = self._func_name_dict[fn3]

            # WARNING: there must be at least two binary functions for each
            #  function name, otherwise this will be an infinite loop.
            if len(func_poll_one) >= 2 and len(func_poll_two) >= 1:
                break

        idx1, idx2 = self._random.sample(func_poll_one, k=2)
        idx3 = self._random.sample(func_poll_two, k=1)[0]

        f1 = self._df_func.iloc[idx1][["idb_path", "fva"]]
        f2 = self._df_func.iloc[idx2][["idb_path", "fva"]]
        f3 = self._df_func.iloc[idx3][["idb_path", "fva"]]

        # Create the positive and the negative pairs
        pos_p = f1, f2
        neg_p = f1, f3
        return pos_p, neg_p

    def _get_next_pair(self):
        """The function implements an infinite loop over the input data."""
        while True:
            log.info("Re-initializing the pair generation")
            for _ in range(self._num_pairs_in_epoch):
                ll = list()
                pairs = self._select_random_function_pairs()
                # Pairs contain a positive and a negative pair of functions
                for pair in pairs:
                    # hold the list of graphs
                    g_list = list()
                    # hold the list of features
                    ft_list = list()
                    # Each pair contain a left and right function
                    for func in pair:
                        # Each function is identified via a IDB and FVA
                        idb, fva = func
                        g_list.append(
                            str_to_scipy_sparse(self._fdict[idb][fva]["adj_mat"])
                        )

                        if self._ftype != "none":
                            ft_list.append(
                                self._decoder(self._fdict[idb][fva]["features_mat"])
                            )
                        else:
                            ft_list.append(
                                np.ones(
                                    (self._length_raw_features, self._max_num_vertices),
                                    dtype=np.float32,
                                )
                            )
                    ll.append(tuple(g_list))
                    ll.append(tuple(ft_list))
                yield tuple(ll)

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(
            range(self._num_batches_in_epoch), total=self._num_batches_in_epoch
        ):
            # Store graphs, features, and lengths for the left pairs
            g_list_l, f_list_l, len_list_l = list(), list(), list()
            # ... and right pairs
            g_list_r, f_list_r, len_list_r = list(), list(), list()

            # Ground truth
            batch_labels = list()

            # Fill each batch with half positive and half negative pairs:
            # iterate over the half of _batch_size because positive and
            # negative pairs are added together.
            for _ in range(int(self._batch_size / 2)):
                # Get the next positive and negative pair
                gpair_pos, fpair_pos, gpair_neg, fpair_neg = next(
                    self._get_next_pair_it
                )

                # Pad features
                ft_pos_l, len_pos_l = pad_features_matrix(
                    fpair_pos[0], self._length_raw_features
                )
                ft_pos_r, len_pos_r = pad_features_matrix(
                    fpair_pos[1], self._length_raw_features
                )
                ft_neg_l, len_neg_l = pad_features_matrix(
                    fpair_neg[0], self._length_raw_features
                )
                ft_neg_r, len_neg_r = pad_features_matrix(
                    fpair_neg[1], self._length_raw_features
                )

                # Add first the positive pairs
                g_list_l.append(gpair_pos[0]), g_list_r.append(gpair_pos[1])
                f_list_l.append(ft_pos_l), f_list_r.append(ft_pos_r)
                len_list_l.append(len_pos_l), len_list_r.append(len_pos_r)

                # Then add the negative ones
                g_list_l.append(gpair_neg[0]), g_list_r.append(gpair_neg[1])
                f_list_l.append(ft_neg_l), f_list_r.append(ft_neg_r)
                len_list_l.append(len_neg_l), len_list_r.append(len_neg_r)

                # GT (pos pair: +1, neg pair: -1)
                batch_labels.extend([+1, -1])

            functions_data = pack_batch(
                f_list_1=f_list_l,
                f_list_2=f_list_r,
                adj_list_1=g_list_l,
                adj_list_2=g_list_r,
                len_list_1=len_list_l,
                len_list_2=len_list_r,
                max_num_vertices=self._max_num_vertices,
                network_type=self._network_type,
            )

            labels = np.array(batch_labels, dtype=np.int32)

            yield functions_data, labels
