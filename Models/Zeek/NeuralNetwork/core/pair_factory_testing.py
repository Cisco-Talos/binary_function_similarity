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

import itertools
import json
import math
import numpy as np
import pandas as pd

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from tqdm import tqdm

import logging
log = logging.getLogger('zeek')


class PairFactoryTesting(PairFactoryBase):

    def __init__(self, positive_path, negative_path, feat_path,
                 batch_size, vector_size):
        """
            Args
                positive_path: path of the csv file with positive pairs
                negative_path: path of the csv file with negative pairs
                feat_path: JSON with functions features
                batch_size: size of the batch for each iteration
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size

        # Load positive and negative CSV
        log.debug("Reading %s" % positive_path)
        self._df_pos = pd.read_csv(positive_path)

        log.debug("Reading %s" % negative_path)
        self._df_neg = pd.read_csv(negative_path)

        # Load JSON with functions features
        log.debug("Loading %s" % feat_path)
        with open(feat_path) as gfd_in:
            self._features_dict = json.load(gfd_in)

        self._vector_size = vector_size

        # Initialize the iterator and the normalizer
        self._get_pair_iterator = self._get_pair()

        # Number of pairs for the positive or negative DF.
        # Taking the minimum of the two, but they should have the same length.
        # WARNING: if you change the definition of self._num_pairs_df, you need
        #   to change how _num_iterations_per_epoch_pairs is defined too.
        self._num_pairs_df = min(self._df_pos.shape[0], self._df_neg.shape[0])

        # _get_pairs() returns 2 pairs (1 positive and 1 negative)
        # _batch_size must be even and >=2 because it should process
        #   n * _get_pairs at each iteration.
        # _num_iterations_per_epoch is the (largest integer) number
        #   of iterations necessary to iterate over all the data in input
        # Example:
        # The input of the NN in Siamese configuration is a pair of functions.
        #   * If the number of positive (and negative) pairs is 100, batch_size
        #   is 20, we need 5 iterations for the positive pairs, and 5 for the
        #   negatives. In total we have 200 pairs and we need 10 iterations.
        self._num_iterations_per_epoch = math.ceil(
            self._num_pairs_df / (self._batch_size / 2))

        self._num_get_pairs_iterations = \
            math.floor(self._num_pairs_df / (self._batch_size / 2)) \
            * int(self._batch_size / 2)

        return

    def get_indexes_by_db_type(self):
        """
        This is an utility test function that returns the list of indexes
        correspoinding to each test case in the input dbs.

        Return
            a list of tuples, where the first element is the name of the db,
            the second is the list of indexes corresponding to that db.
        """
        db_type_list = list()

        # Look for the 'db_type' column.
        if 'db_type' not in self._df_pos.columns:
            return list()

        # Iterate over all the different values of 'db_type', in other words
        # over each test case (e.g., compiler, optimizations, ...)
        for db_type in set(self._df_pos.db_type):
            r_index = self._df_pos[self._df_pos['db_type'] == db_type].index

            # We want the indexes for both the positive and negative pairs,
            # as they will be interlaced when the batch in input is processed.
            idx_list = [[x * 2, x * 2 + 1] for x in r_index]
            idx_list = list(itertools.chain(*idx_list))
            db_type_list.append((
                db_type,
                idx_list
            ))
        return db_type_list

    def _get_pair(self):
        """
        WARNING: Do not call it directly.

        The function implements an infinite loop over the input data.
        """
        while True:

            # (Re-)initialize the iterators
            iterator_pos = self._df_pos.iterrows()
            iterator_neg = self._df_neg.iterrows()

            for _ in range(self._num_get_pairs_iterations):
                pos = next(iterator_pos)[1]
                neg = next(iterator_neg)[1]

                ll = list()
                # Append a tuple with features info from the left/right func
                for pair in [pos, neg]:

                    f1 = self._features_dict[
                        pair['idb_path_1']]['hashes'][pair['fva_1']]['sh']
                    f2 = self._features_dict[
                        pair['idb_path_2']]['hashes'][pair['fva_2']]['sh']
                    ll.append(tuple(
                        (
                            decode_input_hash(f1, self._vector_size),
                            decode_input_hash(f2, self._vector_size)
                        )
                    ))
                yield tuple(ll)

    def pairs(self):
        """Yields batches of pair data."""

        # Iterate _num_iterations_per_epoch_pairs times to cover all the inputs
        for _ in tqdm(range(self._num_iterations_per_epoch),
                      total=self._num_iterations_per_epoch):

            # Store concatenated features
            f_list = list()

            # Ground truth
            batch_labels = list()

            # Fill each batch with half positive and half negative pairs:
            # iterate over the half of _batch_size because positive and
            # negative pairs are added together.
            for _ in range(int(self._batch_size / 2)):

                # Get the next positive and negative pair
                f_pos, f_neg = next(self._get_pair_iterator)

                # Add first the positive pairs
                f_list.append(np.concatenate((f_pos[0], f_pos[1]), axis=None))
                # Then add the negative ones
                f_list.append(np.concatenate((f_neg[0], f_neg[1]), axis=None))

                # GT
                batch_labels.append(np.array([+1, 0]))
                batch_labels.append(np.array([0, +1]))

            functions = pack_batch(
                f_list=f_list)

            labels = np.array(batch_labels, dtype=np.int32)

            yield functions, labels
