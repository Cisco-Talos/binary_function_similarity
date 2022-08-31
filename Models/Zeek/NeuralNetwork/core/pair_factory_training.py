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
#  Zeek Neural Network                                                       #
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
log = logging.getLogger('zeek')


class PairFactoryTraining(PairFactoryBase):

    def __init__(self, df_path, feat_path, batch_size, vector_size):
        """
        Args
            df_path: CSV file with functions generic info
            feat_path: JSON with functions features
            batch_size: size of the batch for each iteration
        """
        if batch_size < 4 or batch_size % 4 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        self._load_data(df_path, feat_path)

        # Keep track of which function pairs have been generated
        self._set_pairs = set()

        # For reproducibility
        # Do not change the seed
        self._random = Random()
        self._random.seed(11)
        # self._np_random_state = np.random.RandomState(11)

        # Initialize the iterator and the normalizer
        self._get_pair_iterator = self._get_pairs()

        self._vector_size = vector_size

        # Number of pairs for the positive or negative DF.
        # Since this is a random batch generator, this number must be defined.

        # TODO set them to appropriate values for the model
        self._num_pairs_df = 40000

        # _get_pairs() returns 2 pairs (1 positive and 1 negative)
        # _batch_size must be even and >=2 because it should process
        #   n * _get_pairs at each iteration.
        # _num_iterations_per_epoch is the (largest integer) number
        #   of iterations necessary to iterate over all the data in input
        # _num_pairs_df is the number of positive (or negative) pairs of
        # functions

        # Example:
        # The input of the NN in Siamese configuration is a pair of functions.
        #   * If _num_pairs_df is 100, that is the number of positive (and negative)
        #   pairs is 100, and batch_size is 20, we need 5 iterations for the positive pairs,
        #   and 5 for the negatives. In total we have 200 pairs and we need 10 iterations.
        #   * If _num_pairs_df is 10 and _batch_size is 8, we need 2 iterations
        #   to cover the data in input, but 4 pos/neg pairs will be left out.
        #   math.floor((10 * 2)/8) = 2 --> 20 - 8*2 = 4 pairs left out

        self._num_iterations_per_epoch = math.floor(
            self._num_pairs_df / (self._batch_size / 2))

        self._num_get_pairs_iterations = \
            self._num_iterations_per_epoch * int(self._batch_size / 2)

    def _load_data(self, df_path, feat_path):
        """
        Load the data from the CSV and JSON files.

        Args
            df_path: CSV file with functions generic info
            feat_path: JSON with functions features

        Return
            None
        """
        # Load CSV with function generic info
        log.debug("Reading %s" % df_path)
        # Read the CSV and reset the index
        self._df_func = pd.read_csv(df_path, index_col=0)
        self._df_func.reset_index(drop=True, inplace=True)

        # Create a dictionary with the indexes for the different archs
        dg = self._df_func.groupby(['arch'])
        self._arch_dict = {a: set(ii) for a, ii in dg.groups.items()}
        # Get the list of unique architecture names
        self._arch_name_list = list(self._arch_dict.keys())

        # Get the list of indexes associated to each function name
        self._func_name_dict = defaultdict(set)
        for i, f in enumerate(self._df_func.func_name):
            self._func_name_dict[f].add(i)
        # Get the list of unique function name
        self._func_name_list = list(self._func_name_dict.keys())
        log.debug("Found %d functions", len(self._func_name_list))

        # Load JSON with functions features
        log.debug("Loading %s" % feat_path)
        with open(feat_path) as gfd_in:
            self._features_dict = json.load(gfd_in)

    def get_indexes_by_db_type(self):
        """
        This is an utility test function that returns the list of indexes
        correspoinding to each test case in the input dbs.

        Return
            a list of tuples, where the first element is the name of the db,
            the second is the list of indexes corresponding to that db.
        """
        db_type_list = list()
        return db_type_list

    def _select_random_function_pairs(self):
        """
        Args:
            None

        Return
            a tuple (pos_p, neg_p) where pos_p and neg_g are a tuple
            like (['idb_path_1', 'fva_1'], ['idb_path_2', 'fva_2'])
        """
        func_poll_one, func_poll_two = set(), set()

        while(1):
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

        f1 = self._df_func.iloc[idx1][['idb_path', 'fva']]
        f2 = self._df_func.iloc[idx2][['idb_path', 'fva']]
        f3 = self._df_func.iloc[idx3][['idb_path', 'fva']]

        # Create the positive and the negative pairs
        pos_p = f1, f2
        neg_p = f1, f3

        return pos_p, neg_p

    def _get_pairs(self):
        """
        Implements a Python iterator for a single positive and negative pair.

        Args
            None

        Return
            a tuple with two elements: f_pos, f_neg:
              f_pos is a tuple of (left_func_features, right_func_features)

            f_neg follows the same format as f_pos, but it is related to the
              negative pair, that is a pair of functions that should not match.
        """
        # Restart at the end of each epoch.
        while True:

            # Re-initialize the data structure
            self._set_pairs = set()

            for _ in range(self._num_get_pairs_iterations):
                pos_p, neg_p = self._select_random_function_pairs()

                ll = list()
                # Append a tuple with features info from the left/right func
                for pair in [pos_p, neg_p]:
                    ll.append(tuple(
                        (decode_input_hash(
                            self._features_dict[idb]['hashes'][fva]['sh'],
                            self._vector_size)
                         for idb, fva in [pair[0], pair[1]])))
                yield tuple(ll)

    def pairs(self):
        """Yields batches of pair data."""

        # Iterate _num_iterations_per_epoch times to cover all the inputs
        for _ in tqdm(range(self._num_iterations_per_epoch),
                      total=self._num_iterations_per_epoch):

            # Store concatenated features
            f_list = list()

            # Ground truth
            batch_labels = list()

            # Fill each batch with half positive and half negative pairs:
            # iterate over the half of _batch_size because positive and
            # negative pairs are added together.
            for _ in range(int(self._batch_size / 4)):

                # Get the next positive and negative pair
                f_pos, f_neg = next(self._get_pair_iterator)

                # Add first the positive pairs
                f_list.append(np.concatenate((f_pos[0], f_pos[1]), axis=None))
                # ... then add the negative ones
                f_list.append(np.concatenate((f_neg[0], f_neg[1]), axis=None))
                # ...add the symmetry (order invariant to the NN)
                f_list.append(np.concatenate((f_pos[1], f_pos[0]), axis=None))
                f_list.append(np.concatenate((f_neg[1], f_neg[0]), axis=None))

                # GT
                batch_labels.append(np.array([+1, 0]))
                batch_labels.append(np.array([0, +1]))
                # ... symmetry
                # NB: label order does not change
                #   the +1 in first position means positive
                batch_labels.append(np.array([+1, 0]))
                batch_labels.append(np.array([0, +1]))

            functions = pack_batch(
                f_list=f_list)

            labels = np.array(batch_labels, dtype=np.int32)

            yield functions, labels
