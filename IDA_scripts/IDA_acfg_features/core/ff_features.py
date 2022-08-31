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
##############################################################################

import idautils
import idc


def get_func_incoming_calls(fva):
    """
    Get the xref to the current function.

    Args:
        fva: function virtual address

    Return:
        the number of xrefs
    """
    x_ref_list = [x for x in idautils.XrefsTo(fva) if x.iscode]
    return len(x_ref_list)


def get_size_local_vars(fva):
    """
    Get the dimension (size) of local variables.

    Args:
        fva: function virtual address

    Return:
        the size of local variables
    """
    return idc.GetFrameLvarSize(fva)


def f_sum(bbs_dict, key_f):
    """
    Return the sum for "key_f" values in bbs_dict.

    Args:
        bbs_dict: a dictionary with BBs features
        key_f: the name of the feature to sum in each BB

    Return:
        the sum of the selected feature
    """
    return sum([bbs_dict[bb_va][key_f] for bb_va in bbs_dict])


def get_function_features(fva, bbs_dict, len_edges):
    """
    Construction the dictionary with function-level features.

    Args:
        fva: function virtual address
        bbs_dict: a dictionary with all the features, one per BB
        len_eges: number of edges

    Return:
        a dictionary with function-level features
    """
    f_dict = {
        'n_func_calls': f_sum(bbs_dict, 'n_call_instrs'),
        'n_logic_instrs': f_sum(bbs_dict, 'n_logic_instrs'),
        'n_redirections': f_sum(bbs_dict, 'n_redirect_instrs'),
        'n_transfer_instrs': f_sum(bbs_dict, 'n_transfer_instrs'),
        'size_local_variables': get_size_local_vars(fva),
        'n_bb': len(bbs_dict),
        'n_edges': len_edges,
        'n_incoming_calls': get_func_incoming_calls(fva),
        'n_instructions': f_sum(bbs_dict, 'n_instructions')
    }
    return f_dict
