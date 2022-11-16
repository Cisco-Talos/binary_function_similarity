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
#  IDA_acfg_features.py - acfg_features IDA plugin implementation.           #
#                                                                            #
#  This plugin contains code from:                                           #
#  github.com/williballenthin/python-idb/ licensed under Apache License 2.0  #
#                                                                            #
##############################################################################

import idautils
import idc
import json
import os
import time

from capstone import *
from collections import namedtuple
from core import *

BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs'])


def get_bitness():
    """Return 32/64 according to the binary bitness."""
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 64
    elif info.is_32bit():
        return 32


def initialize_capstone(procname, bitness):
    """
    Initialize the Capstone disassembler.

    Original code from Willi Ballenthin (Apache License 2.0):
    https://github.com/williballenthin/python-idb/blob/
    2de7df8356ee2d2a96a795343e59848c1b4cb45b/idb/idapython.py#L874
    """
    md = None
    arch = ""

    # WARNING: mipsl mode not supported here
    if procname == 'mipsb':
        arch = "MIPS"
        if bitness == 32:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
        if bitness == 64:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)

    if procname == "arm":
        arch = "ARM"
        if bitness == 32:
            # WARNING: THUMB mode not supported here
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        if bitness == 64:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    if "pc" in procname:
        arch = "x86"
        if bitness == 32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        if bitness == 64:
            md = Cs(CS_ARCH_X86, CS_MODE_64)

    if md is None:
        raise RuntimeError(
            "Capstone initialization failure ({}, {})".format(
                procname, bitness))

    # Set detail to True to get the operand detailed info
    md.detail = True
    return md, arch


def capstone_disassembly(md, ea, size):
    """Disassemble a basic block using Capstone."""
    try:
        # Define a fixed constant to extract immediates
        max_imm = 4096

        bb_heads = list()
        bb_mnems = list()
        bb_disasm = list()
        bb_numerics = list()

        # Get the binary data corresponding to the instruction.
        binary_data = idc.get_bytes(ea, size)

        # Iterate over each instruction in the BB
        for i_inst in md.disasm(binary_data, ea):
            # Get the address
            bb_heads.append(i_inst.address)
            # Get the mnemonic
            bb_mnems.append(i_inst.mnemonic)
            # Get the disasm
            bb_disasm.append("{} {}".format(
                i_inst.mnemonic,
                i_inst.op_str))

            # Iterate over the operands
            for op in i_inst.operands:
                # Type immediate
                if (op.type == 2):
                    if op.imm <= max_imm:
                        bb_numerics.append(op.imm)

        return bb_heads, bb_mnems, bb_disasm, bb_numerics

    except Exception as e:
        print("[!] Capstone exception", e)
        return list(), list(), list(), list()


def get_basic_blocks(fva):
    """Return the list of BasicBlock for a given function."""
    bb_list = list()
    func = idaapi.get_func(fva)
    if func is None:
        return bb_list
    for bb in idaapi.FlowChart(func):
        # WARNING: this function includes the BBs with size 0
        # This is different from what IDA_acfg_disasm does.
        # if bb.end_ea - bb.start_ea > 0:
        bb_list.append(
            BasicBlock(
                va=bb.start_ea,
                size=bb.end_ea - bb.start_ea,
                succs=[x.start_ea for x in bb.succs()]))
    return bb_list


def get_bb_disasm(bb, md):
    """Wrapper around a basic block disassembly."""
    bb_bytes = idc.get_bytes(bb.va, bb.size)
    bb_heads, bb_mnems, bb_disasm, bb_numerics = \
        capstone_disassembly(md, bb.va, bb.size)
    return bb_bytes, bb_heads, bb_mnems, bb_disasm, bb_numerics


def get_bb_features(bb, string_list, md, arch):
    """Extract the features associated to a BB."""
    features_dict = dict()

    # Corner case
    if bb.size == 0:
        features_dict = dict(
            bb_len=0,
            # BB list-type features
            bb_numerics=list(),
            bb_strings=list(),
            # BB numerical-type features
            n_numeric_consts=0,
            n_string_consts=0,
            n_instructions=0,
            n_arith_instrs=0,
            n_call_instrs=0,
            n_logic_instrs=0,
            n_transfer_instrs=0,
            n_redirect_instrs=0
        )
        return features_dict

    # Get the BB bytes, disassembly, mnemonics and other features
    bb_bytes, bb_heads, bb_mnems, bb_disasm, bb_numerics = \
        get_bb_disasm(bb, md)

    # Get static strings from the BB
    bb_strings = get_bb_strings(bb, string_list)

    features_dict = dict(
        bb_len=bb.size,
        # BB list-type features
        bb_numerics=bb_numerics,
        bb_strings=bb_strings,
        # BB numerical-type features
        n_numeric_consts=len(bb_numerics),
        n_string_consts=len(bb_strings),
        n_instructions=len(bb_mnems),
        n_arith_instrs=get_n_arith_instrs(bb_mnems, arch),
        n_call_instrs=get_n_call_instrs(bb_mnems, arch),
        n_logic_instrs=get_n_logic_instrs(bb_mnems, arch),
        n_transfer_instrs=get_n_transfer_instrs(bb_mnems, arch),
        n_redirect_instrs=get_n_redirect_instrs(bb_mnems, arch)
    )
    return features_dict


def run_acfg_features(idb_path, fva_list, output_dir):
    """Extract the features from each function. Save results to JSON."""
    print("[D] Processing: %s" % idb_path)

    # Create output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_dict = dict()
    output_dict[idb_path] = dict()

    procname = idaapi.get_inf_structure().procName.lower()
    bitness = get_bitness()
    md, arch = initialize_capstone(procname, bitness)

    # Get the list of Strings for the IDB
    string_list = list(idautils.Strings())

    # Iterate over each function
    for fva in fva_list:
        try:
            start_time = time.time()
            nodes_set, edges_set = set(), set()
            bbs_dict = dict()

            for bb in get_basic_blocks(fva):
                # CFG
                nodes_set.add(bb.va)
                for dest_ea in bb.succs:
                    edges_set.add((bb.va, dest_ea))
                # BB-level features
                bbs_dict[bb.va] = get_bb_features(bb, string_list, md, arch)

            # Function-level features
            function_features = get_function_features(
                fva, bbs_dict, len(edges_set))

            elapsed_time = time.time() - start_time

            func_dict = {
                'nodes': list(nodes_set),
                'edges': list(edges_set),
                'features': function_features,
                'basic_blocks': bbs_dict,
                'elapsed_time': elapsed_time,
            }
            output_dict[idb_path][hex(fva)] = func_dict

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    out_name = os.path.basename(idb_path.replace(".i64", "_acfg_features.json"))
    with open(os.path.join(output_dir, out_name), "w") as f_out:
        json.dump(output_dict, f_out)


if __name__ == '__main__':
    if not idaapi.get_plugin_options("acfg_features"):
        print("[!] -Oacfg_features option is missing")
        idaapi.qexit(1)

    plugin_options = idaapi.get_plugin_options("acfg_features").split(":")
    if len(plugin_options) != 3:
        print("[!] -Oacfg_features:INPUT_JSON:IDB_PATH:OUTPUT_DIR is required")
        idaapi.qexit(1)

    input_json = plugin_options[0]
    idb_path = plugin_options[1]
    output_dir = plugin_options[2]

    with open(input_json) as f_in:
        selected_functions = json.load(f_in)

    if idb_path not in selected_functions:
        print("[!] Error! IDB path (%s) not in %s" % (idb_path, input_json))
        idaapi.qexit(1)

    fva_list = selected_functions[idb_path]
    print("[D] Found %d addresses" % len(fva_list))

    run_acfg_features(idb_path, fva_list, output_dir)
    idaapi.qexit(0)
