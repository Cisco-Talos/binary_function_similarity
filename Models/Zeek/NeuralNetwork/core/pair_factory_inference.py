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
import pandas as pd

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from tqdm import tqdm

import logging
log = logging.getLogger('zeek')


class PairFactoryInference(PairFactoryBase):

    def __init__(self, df_path, feat_path, batch_size, vector_size):
        """
            Args
                df_path: CSV file with functions generic info
                feat_path: JSON with functions features
                batch_size: size of the batch for each iteration
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size

        # Load the functions csv.
        log.debug("Reading %s" % df_path)
        self._df = pd.read_csv(df_path)

        # Load JSON with functions features
        log.debug("Loading %s" % feat_path)
        with open(feat_path) as gfd_in:
            self._features_dict = json.load(gfd_in)

        self._vector_size = vector_size

        # Initialize the iterator and the normalizer
        self._get_iterator = self._get_next()

        # Number of pairs for the dataset
        self._num_pairs_df = self._df.shape[0]

        # Number of iterations needed to cover all the samples in
        # input with _batch_size pairs at a time.
        self._num_iterations_per_epoch = math.ceil(
            self._num_pairs_df / self._batch_size)

        self._num_get_pairs_iterations = \
            math.floor(self._num_pairs_df / self._batch_size) \
            * self._batch_size

        return

    def _get_next(self):
        """
        WARNING: Do not call it directly.

        The function implements an infinite loop over the input data.
        """
        while True:
            # (Re-)initialize the iterators
            iterator = self._df.iterrows()

            for _ in range(self._num_get_pairs_iterations):
                data = next(iterator)[1]

                f1 = self._features_dict[
                    data['idb_path_1']]['hashes'][data['fva_1']]['sh']
                f2 = self._features_dict[
                    data['idb_path_2']]['hashes'][data['fva_2']]['sh']

                yield (
                    (
                        decode_input_hash(f1, self._vector_size),
                        decode_input_hash(f2, self._vector_size)
                    )
                )

    def pairs(self):
        """Yields batches of pair data.

        """
        for _ in tqdm(range(self._num_iterations_per_epoch),
                      total=self._num_iterations_per_epoch):

            # Store concatenated features
            f_list = list()

            for _ in range(self._batch_size):
                f_mat = next(self._get_iterator)

                # Add first the positive pairs
                f_list.append(np.concatenate((f_mat[0], f_mat[1]), axis=None))

            functions = pack_batch(
                f_list=f_list)

            yield functions
