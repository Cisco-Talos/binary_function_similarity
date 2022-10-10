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

import itertools
import json
import math
import numpy as np
import pandas as pd

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from tqdm import tqdm

import logging
log = logging.getLogger('safe')


class PairFactoryTesting(PairFactoryBase):

    def __init__(self, pos_path, neg_path, feat_path, batch_size, max_ins):
        """
            Args
                pos_path: CSV file with positive function pairs
                neg_path: CSV file with negative function pairs
                feat_path: JSON file with function features
                batch_size: size of the batch for each iteration
                max_ins: maximum number of instructions per function
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (validation): {}".format(self._batch_size))
        self._max_ins = max_ins
        self._decoder = str_to_list

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

                ll = list()
                # Get the features from the left/right function for each pair
                for pair in [pos, neg]:
                    f_l = self._fdict[pair['idb_path_1']
                                      ][pair['fva_1']]['idx_list']
                    f_r = self._fdict[pair['idb_path_2']
                                      ][pair['fva_2']]['idx_list']
                    ll.append(tuple((f_l, f_r)))
                yield tuple(ll)

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches),
                      total=self._num_batches):

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
