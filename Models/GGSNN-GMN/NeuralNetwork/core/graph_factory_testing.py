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

import itertools
import json
import math
import networkx as nx
import numpy as np
import pandas as pd

from .graph_factory_base import GraphFactoryBase
from .graph_factory_utils import *
from tqdm import tqdm

import logging
log = logging.getLogger('gnn')


class GraphFactoryTesting(GraphFactoryBase):

    def __init__(self, pos_path, neg_path, feat_path, batch_size,
                 use_features, features_type, bb_features_size):
        """
            Args:
                pos_path: CSV file with positive function pairs
                neg_path: CSV file with negative function pairs
                feat_path: JSON file with function features
                batch_size: size of the batch for each iteration
                use_features: if True, load the graph node features
                features_type: used to select the appropriate decoder and data
                bb_features_size: numer of features at the basic-block level
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (validation): {}".format(self._batch_size))

        self._use_features = use_features
        self._features_type = features_type
        self._bb_features_size = bb_features_size
        self._decoder = str_to_scipy_sparse

        # Load positive and negative function pairs
        log.debug("Reading {}".format(pos_path))
        self._func_pos = pd.read_csv(pos_path)
        log.debug("Reading {}".format(neg_path))
        self._func_neg = pd.read_csv(neg_path)

        # Load function features
        log.debug("Loading {}".format(feat_path))
        with open(feat_path) as gfd_in:
            self._fdict = json.load(gfd_in)

        # Initialize the iterator
        self._get_next_pair_it = self._get_next_pair()

        # Number of positive or negative function pairs
        self._num_func_pairs = min(self._func_pos.shape[0],
                                   self._func_neg.shape[0])
        log.info("Tot num func pairs (validation): {}".format(
            self._num_func_pairs * 2))

        # _get_next_pair() returns 2 pairs (1 positive and 1 negative)
        # _batch_size must be even and >= 2
        # _num_batches is the number of iterations to cover the input data
        # Example:
        #   * 100 Pos + 100 Neg functions. Batch_size = 20; 10 iterations
        #   * 100 Pos + 100 Neg functions. Batch_size = 16; 13 iterations
        self._num_batches = math.ceil(
            self._num_func_pairs / (self._batch_size / 2))
        log.info("Num batches (validation): {}".format(self._num_batches))

    def get_indexes_by_db_type(self):
        """Get the list of indexes for each test case."""
        if 'db_type' not in self._func_pos.columns:
            return list()
        db_type_list = list()
        for db_type in set(self._func_pos.db_type):
            idxs = self._func_pos[self._func_pos['db_type'] == db_type].index
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

            for _ in range(self._num_func_pairs):
                # Get the next positive pair
                pos = next(iterator_pos)[1]
                # Get the next negative pair
                neg = next(iterator_neg)[1]

                f_pl = self._fdict[pos['idb_path_1']][pos['fva_1']]
                f_pr = self._fdict[pos['idb_path_2']][pos['fva_2']]

                f_nl = self._fdict[neg['idb_path_1']][neg['fva_1']]
                f_nr = self._fdict[neg['idb_path_2']][neg['fva_2']]

                if self._use_features:
                    yield (
                        (
                            nx.DiGraph(str_to_scipy_sparse(f_pl['graph'])),
                            nx.DiGraph(str_to_scipy_sparse(f_pr['graph'])),
                        ),
                        (
                            self._decoder(f_pl[self._features_type]),
                            self._decoder(f_pr[self._features_type])
                        ),
                        (
                            nx.DiGraph(str_to_scipy_sparse(f_nl['graph'])),
                            nx.DiGraph(str_to_scipy_sparse(f_nr['graph']))
                        ),
                        (
                            self._decoder(f_nl[self._features_type]),
                            self._decoder(f_nr[self._features_type])
                        )
                    )
                else:
                    yield (
                        (
                            nx.DiGraph(str_to_scipy_sparse(f_pl['graph'])),
                            nx.DiGraph(str_to_scipy_sparse(f_pr['graph']))
                        ),
                        (
                            # No features
                            -1, -1
                        ),
                        (
                            nx.DiGraph(str_to_scipy_sparse(f_nl['graph'])),
                            nx.DiGraph(str_to_scipy_sparse(f_nr['graph']))
                        ),
                        (
                            # No features
                            -1, -1
                        )
                    )

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches),
                      total=self._num_batches):
            batch_graphs = list()
            batch_features = list()
            batch_labels = list()

            # Fill each batch with half positive and half negative pairs:
            # iterate over the half of _batch_size because positive and
            # negative pairs are added together.
            for _ in range(int(self._batch_size / 2)):
                # Get the next positive and negative pair
                g_pos, f_pos, g_neg, f_neg = next(self._get_next_pair_it)

                # Add first the positive pair
                batch_graphs.append((g_pos[0], g_pos[1]))
                batch_features.append((f_pos[0], f_pos[1]))

                # Then, add the negative one.
                batch_graphs.append((g_neg[0], g_neg[1]))
                batch_features.append((f_neg[0], f_neg[1]))

                # GT (pos pair: +1, neg pair: -1)
                batch_labels.extend([+1, -1])

            # Pack everything in a graph data structure
            packed_graphs = pack_batch(batch_graphs,
                                       batch_features,
                                       self._use_features,
                                       nofeatures_size=self._bb_features_size)
            labels = np.array(batch_labels, dtype=np.int32)

            yield packed_graphs, labels

    def triplets(self):
        """ Yields batches of triplet data. For training only."""
        pass
