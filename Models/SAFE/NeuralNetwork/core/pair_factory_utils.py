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

from .pair_factory_base import PairData

import logging
log = logging.getLogger('safe')


def str_to_list(instruction_list, max_instructions):
    """
    Returns the list of IDs for a function with the length
    accepted by the model
    """
    idx_list = [int(x) for x in instruction_list.split(";")]
    idx_len = len(idx_list)
    idx_list = idx_list[:max_instructions]
    idx_list = idx_list + [0] * (max_instructions - len(idx_list))
    ll = min(idx_len, max_instructions)
    return idx_list, ll


def pack_batch(f_list_1, f_list_2,
               len_list_1, len_list_2):
    """Pack a batch of graphs and features into a single `PairData`
    instance.

    Args
        f_list_1: list of instructions ids
        f_list_2: list of instructions ids
        len_list_1: list of instruction lengths
        len_list_2: list of instruction lengths
        max_instructions: max number of instructions in a function

    Return
        an instance of `GraphData`
    """
    f_list_1 = f_list_1
    len_list_1 = len_list_1
    f_list_2 = f_list_2
    len_list_2 = len_list_2

    # Pack everything in a GraphData structure
    graphs = PairData(
        x_1=f_list_1,
        lengths_1=len_list_1,
        x_2=f_list_2,
        lengths_2=len_list_2,
    )
    return graphs
