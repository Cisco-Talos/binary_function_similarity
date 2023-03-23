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

import itertools
import json
import math
import numpy as np
import pandas as pd

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from tqdm import tqdm

import logging

log = logging.getLogger("s2v")


class PairFactoryTesting(PairFactoryBase):
    def __init__(
        self,
        pos_path,
        neg_path,
        feat_path,
        batch_size,
        features_type,
        network_type,
        max_num_vertices,
        length_raw_features,
    ):
        """
        Args
            pos_path: CSV file with positive function pairs
            neg_path: CSV file with negative function pairs
            feat_path: JSON file with function features
            batch_size: size of the batch for each iteration
            features_type: used to select the appropriate decoder and data
            max_num_vertices: maximum number of nodes in the adjancey matrix
            length_raw_features: maximum number of raw features for each BB
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (validation): {}".format(self._batch_size))

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

        # Load positive and negative function pairs
        log.debug("Reading {}".format(pos_path))
        self._func_pos = pd.read_csv(pos_path)
        log.debug("Reading {}".format(neg_path))
        self._func_neg = pd.read_csv(neg_path)

        # Load the JSON with functions graphs and features
        log.debug("Loading {}".format(feat_path))
        with open(feat_path) as gfd_in:
            self._fdict = json.load(gfd_in)

        # Initialize the iterator
        self._get_next_pair_it = self._get_next_pair()

        # Number of positive or negative function pairs
        self._num_func_pairs = min(self._func_pos.shape[0], self._func_neg.shape[0])
        log.info("Tot num func pairs (validation): {}".format(self._num_func_pairs * 2))

        # _get_next_pair() returns 2 pairs (1 positive and 1 negative)
        # _batch_size must be even and >= 2
        # _num_batches is the number of iterations to cover the input data
        # Example:
        #   * 100 Pos + 100 Neg functions. Batch_size = 20; 10 iterations
        #   * 100 Pos + 100 Neg functions. Batch_size = 16; 13 iterations
        self._num_batches = math.ceil(self._num_func_pairs / (self._batch_size / 2))
        log.info("Num batches (validation): {}".format(self._num_batches))

    def get_indexes_by_db_type(self):
        """Get the list of indexes for each test case."""
        if "db_type" not in self._func_pos.columns:
            return list()
        db_type_list = list()
        for db_type in set(self._func_pos.db_type):
            idxs = self._func_pos[self._func_pos["db_type"] == db_type].index
            # We want the indexes for both the positive and negative pairs,
            # as they will be interlaced when the batch in input is processed.
            idx_list = [[x * 2, x * 2 + 1] for x in idxs]
            idx_list = list(itertools.chain(*idx_list))
            db_type_list.append((db_type, idx_list))
        return db_type_list

    def _get_next_pair(self):
        """The function implements an infinite loop over the input data."""
        while True:
            log.info("(Re-)initializing the iterators")
            # (Re-)initialize the iterators
            iterator_pos = self._func_pos.iterrows()
            iterator_neg = self._func_neg.iterrows()

            oones = np.ones(
                (self._length_raw_features, self._max_num_vertices),
                dtype=np.float32,
            )

            for _ in range(self._num_func_pairs):
                # Get the next positive pair
                r_p = next(iterator_pos)[1]
                # Get the next negative pair
                r_n = next(iterator_neg)[1]

                fdict_pl = self._fdict[r_p["idb_path_1"]][r_p["fva_1"]]
                fdict_pr = self._fdict[r_p["idb_path_2"]][r_p["fva_2"]]

                fdict_nl = self._fdict[r_n["idb_path_1"]][r_n["fva_1"]]
                fdict_nr = self._fdict[r_n["idb_path_2"]][r_n["fva_2"]]

                gpair_p = (
                    str_to_scipy_sparse(fdict_pl["adj_mat"]),
                    str_to_scipy_sparse(fdict_pr["adj_mat"]),
                )

                gpair_n = (
                    str_to_scipy_sparse(fdict_nl["adj_mat"]),
                    str_to_scipy_sparse(fdict_nr["adj_mat"]),
                )

                if self._ftype != "none":
                    yield (
                        gpair_p,
                        (
                            self._decoder(fdict_pl["features_mat"]),
                            self._decoder(fdict_pr["features_mat"]),
                        ),
                        gpair_n,
                        (
                            self._decoder(fdict_nl["features_mat"]),
                            self._decoder(fdict_nr["features_mat"]),
                        ),
                    )
                else:
                    yield (
                        gpair_p,
                        (oones, oones),
                        gpair_n,
                        (oones, oones),
                    )

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches), total=self._num_batches):
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
