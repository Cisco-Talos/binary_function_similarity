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
#  IDA_acfg_disasm.py - acfg_disasm IDA plugin implementation.               #
#                                                                            #
#  This plugin contains code from:                                           #
#  github.com/williballenthin/python-idb/ licensed under Apache License 2.0  #
#                                                                            #
##############################################################################

import base64
import idaapi
import idc
import json
import os
import time

from capstone import *
from collections import namedtuple

BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs'])


def convert_procname_to_str(procname, bitness):
    """Convert the arch and bitness to a std. format."""
    if procname == 'mipsb':
        return "mips-{}".format(bitness)
    if procname == "arm":
        return "arm-{}".format(bitness)
    if "pc" in procname:
        return "x86-{}".format(bitness)
    raise RuntimeError(
        "[!] Arch not supported ({}, {})".format(
            procname, bitness))


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
    prefix = "UNK_"

    # WARNING: mipsl mode not supported here
    if procname == 'mipsb':
        prefix = "M_"
        if bitness == 32:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
        if bitness == 64:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)

    if procname == "arm":
        prefix = "A_"
        if bitness == 32:
            # WARNING: THUMB mode not supported here
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        if bitness == 64:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    if "pc" in procname:
        prefix = "X_"
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
    return md, prefix


def capstone_disassembly(md, ea, size, prefix):
    """Return the BB (normalized) disassembly, with mnemonics and BB heads."""
    try:
        bb_heads, bb_mnems, bb_disasm, bb_norm = list(), list(), list(), list()

        # Iterate over each instruction in the BB
        for i_inst in md.disasm(idc.get_bytes(ea, size), ea):
            # Get the address
            bb_heads.append(i_inst.address)
            # Get the mnemonic
            bb_mnems.append(i_inst.mnemonic)
            # Get the disasm
            bb_disasm.append("{} {}".format(
                i_inst.mnemonic,
                i_inst.op_str))

            # Compute the normalized code. Ignore the prefix.
            # cinst = prefix + i_inst.mnemonic
            cinst = i_inst.mnemonic

            # Iterate over the operands
            for op in i_inst.operands:

                # Type register
                if (op.type == 1):
                    cinst = cinst + " " + i_inst.reg_name(op.reg)

                # Type immediate
                elif (op.type == 2):
                    imm = int(op.imm)
                    if (-int(5000) <= imm <= int(5000)):
                        cinst += " " + str(hex(op.imm))
                    else:
                        cinst += " " + str('HIMM')

                # Type memory
                elif (op.type == 3):
                    # If the base register is zero, convert to "MEM"
                    if (op.mem.base == 0):
                        cinst += " " + str("[MEM]")
                    else:
                        # Scale not available, e.g. for ARM
                        if not hasattr(op.mem, 'scale'):
                            cinst += " " + "[{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.disp))
                        else:
                            cinst += " " + "[{}*{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.scale),
                                str(op.mem.disp))

                if (len(i_inst.operands) > 1):
                    cinst += ","

            # Make output looks better
            cinst = cinst.replace("*1+", "+")
            cinst = cinst.replace("+-", "-")

            if "," in cinst:
                cinst = cinst[:-1]
            cinst = cinst.replace(" ", "_").lower()
            bb_norm.append(str(cinst))

        return bb_heads, bb_mnems, bb_disasm, bb_norm

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
        # WARNING: this function DOES NOT include the BBs with size 0
        # This is different from what IDA_acfg_features does.
        # if bb.end_ea - bb.start_ea > 0:
        if bb.end_ea - bb.start_ea > 0:
            bb_list.append(
                BasicBlock(
                    va=bb.start_ea,
                    size=bb.end_ea - bb.start_ea,
                    succs=[x.start_ea for x in bb.succs()]))
    return bb_list


def get_bb_disasm(bb, md, prefix):
    """Return the (nomalized) disassembly for a BasicBlock."""
    b64_bytes = base64.b64encode(idc.get_bytes(bb.va, bb.size)).decode()
    bb_heads, bb_mnems, bb_disasm, bb_norm = \
        capstone_disassembly(md, bb.va, bb.size, prefix)
    return b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm


def run_acfg_disasm(idb_path, fva_list, output_dir):
    """Disassemble each function. Extract the CFG. Save output to JSON."""
    print("[D] Processing: %s" % idb_path)

    # Create output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_dict = dict()
    output_dict[idb_path] = dict()

    procname = idaapi.get_inf_structure().procname.lower()
    bitness = get_bitness()
    output_dict[idb_path]['arch'] = convert_procname_to_str(procname, bitness)
    md, prefix = initialize_capstone(procname, bitness)

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
                if bb.size:
                    b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = \
                        get_bb_disasm(bb, md, prefix)
                    bbs_dict[bb.va] = {
                        'bb_len': bb.size,
                        'b64_bytes': b64_bytes,
                        'bb_heads': bb_heads,
                        'bb_mnems': bb_mnems,
                        'bb_disasm': bb_disasm,
                        'bb_norm': bb_norm
                    }
                else:
                    bbs_dict[bb.va] = {
                        'bb_len': bb.size,
                        'b64_bytes': "",
                        'bb_heads': list(),
                        'bb_mnems': list(),
                        'bb_disasm': list(),
                        'bb_norm': list()
                    }
            elapsed_time = time.time() - start_time
            func_dict = {
                'nodes': list(nodes_set),
                'edges': list(edges_set),
                'elapsed_time': elapsed_time,
                'basic_blocks': bbs_dict
            }
            output_dict[idb_path][hex(fva)] = func_dict

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    out_name = os.path.basename(idb_path.replace(".i64", "_acfg_disasm.json"))
    with open(os.path.join(output_dir, out_name), "w") as f_out:
        json.dump(output_dict, f_out)


if __name__ == '__main__':
    if not idaapi.get_plugin_options("acfg_disasm"):
        print("[!] -Oacfg_disasm option is missing")
        idaapi.qexit(1)

    plugin_options = idaapi.get_plugin_options("acfg_disasm").split(":")
    if len(plugin_options) != 3:
        print("[!] -Oacfg_disasm:INPUT_JSON:IDB_PATH:OUTPUT_DIR is required")
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

    run_acfg_disasm(idb_path, fva_list, output_dir)
    idaapi.qexit(0)
