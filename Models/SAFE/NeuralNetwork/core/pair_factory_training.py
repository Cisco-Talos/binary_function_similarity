##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  This program is free software: you can redistribute it and/or modify      #
#  it under the terms of the GNU General Public License as published by      #
#  the Free Software Foundation, either version 3 of the License, or         #
#  (at your option) any later version.                                       #
#                                                                            #
#  This program is distributed in the hope that it will be useful,           #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of            #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
#  GNU General Public License for more details.                              #
#                                                                            #
#  You should have received a copy of the GNU General Public License         #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.    #
#                                                                            #
#  SAFE Neural Network                                                       #
#                                                                            #
#  This implementation contains code from                                    #
#  https://github.com/gadiluna/SAFE licensed under GPL-3.0                   #
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
log = logging.getLogger('safe')


class PairFactoryTraining(PairFactoryBase):

    def __init__(self, func_path, feat_path, batch_size, max_ins):
        """
            Args
                func_path: CSV file with training functions
                feat_path: JSON file with function features
                batch_size: size of the batch for each iteration
                max_ins: maximum number of instructions per function
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (training): {}".format(self._batch_size))
        self._max_ins = max_ins
        self._decoder = str_to_list

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
        log.info("Tot num func pairs (training): {}".format(
            self._num_func_pairs * 2))

        # _get_next_pair() returns 2 pairs (1 positive and 1 negative)
        # _batch_size must be even and >= 2
        # _num_batches is the number of iterations to cover the input data
        # Example:
        #   * 100 Pos + 100 Neg functions. Batch_size = 20; 10 iterations
        #   * 100 Pos + 100 Neg functions. Batch_size = 16; 12 iterations and
        #       8 function pairs discarded
        self._num_batches_in_epoch = math.floor(
            self._num_func_pairs / (self._batch_size / 2))
        log.info("Num batches in epoch (training): {}".format(
            self._num_batches_in_epoch))

        self._num_pairs_in_epoch = \
            self._num_batches_in_epoch * int(self._batch_size / 2)
        log.info("Tot num func pairs per epoch (training): {}".format(
            self._num_pairs_in_epoch * 2))

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

        # Load the JSON with functions features
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

    def _get_next_pair(self):
        """The function implements an infinite loop over the input data."""
        while True:
            log.info("Re-initializing the pair generation")

            for _ in range(self._num_pairs_in_epoch):
                ll = list()
                pairs = self._select_random_function_pairs()
                # Pairs contain a positive and a negative pair of functions
                for pair in pairs:
                    f_list = list()
                    # Each pair contain a left and right function
                    for func in pair:
                        # Each function is identified via a IDB and FVA
                        idb, fva = func
                        f_list.append(self._fdict[idb][fva]["idx_list"])
                    ll.append(tuple(f_list))
                yield tuple(ll)

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches_in_epoch),
                      total=self._num_batches_in_epoch):

            # Store instructions and lengths information for the left pairs
            f_list_l, len_list_l = list(), list()
            # ... and right pairs
            f_list_r, len_list_r = list(), list()

            # Ground truth
            batch_labels = list()

            # Fill each batch with half positive and half negative pairs:
            # iterate over the half of _batch_size because positive and
            # negative pairs are added together.
            for _ in range(int(self._batch_size / 2)):

                # Get the next positive and negative pair
                fpair_pos, fpair_neg = next(self._get_next_pair_it)

                # Add first the positive pairs
                idx_list, idx_len = self._decoder(fpair_pos[0], self._max_ins)
                f_list_l.append(idx_list)
                len_list_l.append(idx_len)

                idx_list, idx_len = self._decoder(fpair_pos[1], self._max_ins)
                f_list_r.append(idx_list)
                len_list_r.append(idx_len)

                # Then, add the negative one.
                idx_list, idx_len = self._decoder(fpair_neg[0], self._max_ins)
                f_list_l.append(idx_list)
                len_list_l.append(idx_len)

                idx_list, idx_len = self._decoder(fpair_neg[1], self._max_ins)
                f_list_r.append(idx_list)
                len_list_r.append(idx_len)

                # GT (pos pair: +1, neg pair: -1)
                batch_labels.extend([+1, -1])

            functions_data = pack_batch(
                f_list_1=f_list_l,
                f_list_2=f_list_r,
                len_list_1=len_list_l,
                len_list_2=len_list_r)

            labels = np.array(batch_labels, dtype=np.int32)

            yield functions_data, labels
