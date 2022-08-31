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

import numpy as np

from .pair_factory_base import JoinedPairData

import logging
log = logging.getLogger('zeek')


def decode_input_hash(encoded_str, vector_size):
    """
    Convert the string in input into a numpy vector. It uses a custom
    encoding based on ":" and ";" to save space.

    Args
        np_str: string that encodes a numpy vector
        (example: 71:2.0;101:5.0;217:2.0;336:3.0)

    Return
        numpy vector
    """
    vector = np.zeros(vector_size)
    try:
        encoded_list = encoded_str.split(";")
        for enc in encoded_list:
            idx, val = enc.split(":")
            vector[int(idx)] = float(val)
        return vector
    except Exception:
        log.error("Hash with all zeros: %s", encoded_str)
        return vector


def pack_batch(f_list):
    """Pack a batch of input hashes into a `JoinedPairData` instance.

    Args
        f_list: list of input features
          (x_left and x_right have already been joined)

    Return
        an instance of `JoinedPairData`
    """
    # Pack everything in a JoinedPairData structure
    pairs = JoinedPairData(
        x=f_list
    )
    return pairs
