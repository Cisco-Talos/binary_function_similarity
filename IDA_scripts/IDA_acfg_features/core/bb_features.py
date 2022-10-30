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

from .architecture import ARCH_MNEM


def get_bb_strings(bb, string_list):
    """
    Get strings in the basic block.

    Args:
        bb: a 'BasicBlock' instance

    Return:
        the list of strings
    """
    d_from = []
    strings = []
    for h in idautils.Heads(bb.va, bb.va + bb.size):
        for xf in idautils.DataRefsFrom(h):
            d_from.append(xf)
    for k in string_list:
        if k.ea in d_from:
            strings.append(str(k))
    return strings


def get_n_transfer_instrs(mnem_list, arch):
    """
    Get the number of transfer instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of transfer instructions
    """
    return len([m for m in mnem_list if m in ARCH_MNEM[arch]['transfer']])


def get_n_redirect_instrs(mnem_list, arch):
    """
    Get the num of conditional, unconditional, and call instructions.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of redirect instructions
    """
    temp_instrs = ARCH_MNEM[arch]['conditional'] | \
        ARCH_MNEM[arch]['unconditional'] | \
        ARCH_MNEM[arch]['call']

    return len([m for m in mnem_list if m in temp_instrs])


def get_n_call_instrs(mnem_list, arch):
    """
    Get the number of call instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of call instructions
    """
    return len([m for m in mnem_list if m in ARCH_MNEM[arch]['call']])


def get_n_arith_instrs(mnem_list, arch):
    """
    Get the number of arithmetic instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of arithmetic instructions
    """
    return len([m for m in mnem_list if m in ARCH_MNEM[arch]['arithmetic']])


def get_n_logic_instrs(mnem_list, arch):
    """
    Get the number of logic instructions in the basic block.

    Args:
        mnem_list: list of mnemonics
        arch: a value among X, ARM, MIPS

    Return:
        the number of logic instructions
    """
    return len([m for m in mnem_list if m in ARCH_MNEM[arch]['logic']])
