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

import json
import math
import networkx as nx
import pandas as pd

from .graph_factory_base import GraphFactoryBase
from .graph_factory_utils import *
from tqdm import tqdm

import logging
log = logging.getLogger('gnn')


class GraphFactoryInference(GraphFactoryBase):

    def __init__(self, func_path, feat_path, batch_size,
                 use_features, features_type, bb_features_size):
        """
            Args:
                func_path: CSV file with function pairs
                feat_path: JSON file with function features
                batch_size: size of the batch for each iteration
                use_features: if True, load the graph node features
                features_type: used to select the appropriate decoder and data
                bb_features_size: numer of features at the basic-block level
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (inference): {}".format(self._batch_size))

        self._use_features = use_features
        self._features_type = features_type
        self._bb_features_size = bb_features_size
        self._decoder = str_to_scipy_sparse

        # Load function pairs
        log.debug("Reading {}".format(func_path))
        self._func = pd.read_csv(func_path)

        # Load function features
        log.debug("Loading {}".format(feat_path))
        with open(feat_path) as gfd_in:
            self._fdict = json.load(gfd_in)

        # Initialize the iterator
        self._get_next_pair_it = self._get_next_pair()

        # Number of function pairs
        self._num_func_pairs = self._func.shape[0]
        log.info("Num func pairs (inference): {}".format(self._num_func_pairs))

        # _get_next_pair() returns a pair of functions
        # _batch_size must be even and >= 2
        # _num_batches is the number of iterations to cover the input data
        # Example:
        #   * 100 functions. Batch_size = 20; 5 iterations
        #   * 100 functions. Batch_size = 16; 7 iterations
        self._num_batches = math.ceil(
            self._num_func_pairs / self._batch_size)
        log.info("Num batches (inference): {}".format(self._num_batches))

    def _get_next_pair(self):
        """The function implements an infinite loop over the input data."""
        while True:
            log.info("(Re-)initializing the iterators")
            # (Re-)initialize the iterators
            iterator = self._func.iterrows()

            for _ in range(self._num_func_pairs):
                # Get the next row
                r = next(iterator)[1]
                # Get the features for the left function
                f_l = self._fdict[r['idb_path_1']][r['fva_1']]
                # ... and for the right one
                f_r = self._fdict[r['idb_path_2']][r['fva_2']]

                if self._use_features:
                    yield (
                        (
                            nx.DiGraph(str_to_scipy_sparse(f_l['graph'])),
                            nx.DiGraph(str_to_scipy_sparse(f_r['graph']))
                        ),
                        (
                            self._decoder(f_l[self._features_type]),
                            self._decoder(f_r[self._features_type])
                        )
                    )
                else:
                    yield (
                        (
                            nx.DiGraph(str_to_scipy_sparse(f_l['graph'])),
                            nx.DiGraph(str_to_scipy_sparse(f_r['graph']))
                        ),
                        (
                            -1, -1
                        )
                    )

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches),
                      total=self._num_batches):
            batch_graphs = list()
            batch_features = list()

            for _ in range(self._batch_size):
                g_pair, f_pair = next(self._get_next_pair_it)
                batch_graphs.append((g_pair[0], g_pair[1]))
                batch_features.append((f_pair[0], f_pair[1]))

            # Pack everything in a graph data structure
            packed_graphs = pack_batch(
                batch_graphs,
                batch_features,
                self._use_features,
                nofeatures_size=self._bb_features_size)

            yield packed_graphs

    def triplets(self):
        """ Yields batches of triplet data. For training only."""
        pass
