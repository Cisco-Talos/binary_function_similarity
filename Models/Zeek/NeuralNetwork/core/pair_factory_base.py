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

import abc
import collections
import six

JoinedPairData = collections.namedtuple('JoinedPairData', ['x'])


@six.add_metaclass(abc.ABCMeta)
class PairFactoryBase(object):
    """Base class for all the siamese similarity learning datasets.

    This class defines some common interfaces a siamese similarity
    dataset can have, in particular the functions that creates
    iterators over pairs.
    """

    @abc.abstractmethod
    def pairs(self):
        """Create an iterator over pairs.

        Note:
          batch_size: int, number of pairs in a batch.

        Yields:
          pairs: a `PairData` instance. The batch of pairs put together.
            Each pair has 2 inputs (x, y). The batch contains `batch_size`
            number of pairs, hence `2*batch_size` many input hashes.
          labels: [batch_size] int labels for each pair, +1 for similar,
            0 for not.
        """
        pass
