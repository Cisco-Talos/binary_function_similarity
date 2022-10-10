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
import pandas as pd

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from tqdm import tqdm

import logging
log = logging.getLogger('safe')


class PairFactoryInference(PairFactoryBase):

    def __init__(self, func_path, feat_path, batch_size, max_ins):
        """
            Args
                func_path: CSV file with function pairs
                feat_path: JSON file with function features
                batch_size: size of the batch for each iteration
                max_ins: maximum number of instructions per function
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (inference): {}".format(self._batch_size))
        self._max_ins = max_ins
        self._decoder = str_to_list

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
                f_l = self._fdict[r['idb_path_1']][r['fva_1']]["idx_list"]
                # ... and for the right one
                f_r = self._fdict[r['idb_path_2']][r['fva_2']]["idx_list"]
                yield ((f_l, f_r))

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches),
                      total=self._num_batches):

            # Store instructions and lengths information for the left pairs
            f_list_l, len_list_l = list(), list()
            # ... and right pairs
            f_list_r, len_list_r = list(), list()

            for _ in range(self._batch_size):
                fpairs = next(self._get_next_pair_it)

                # Add first the left functions
                idx_list, idx_len = self._decoder(fpairs[0], self._max_ins)
                f_list_l.append(idx_list)
                len_list_l.append(idx_len)

                # ... then the right ones.
                idx_list, idx_len = self._decoder(fpairs[1], self._max_ins)
                f_list_r.append(idx_list)
                len_list_r.append(idx_len)

            functions_data = pack_batch(
                f_list_1=f_list_l,
                f_list_2=f_list_r,
                len_list_1=len_list_l,
                len_list_2=len_list_r)

            yield functions_data
