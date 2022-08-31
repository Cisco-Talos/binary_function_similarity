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
#  IDA_fss.py - Run the FSS IDA plugin                                       #
#                                                                            #
#  This plugin contains code from:                                           #
#  github.com/williballenthin/python-idb/ licensed under Apache License 2.0  #
#  googleprojectzero/functionsimsearch licensed under Apache License 2.0     #
#                                                                            #
##############################################################################

import idaapi
import idautils
import idc
import json
import ntpath
import os
import traceback

from capstone import *


def get_bitness():
    """Return 32/64 according to the binary bitness."""
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return 64
    elif info.is_32bit():
        return 32


def initialize_capstone():
    """
    Initialize the Capstone disassembler.

    Original code from Willi Ballenthin (Apache License 2.0):
    https://github.com/williballenthin/python-idb/blob/
    2de7df8356ee2d2a96a795343e59848c1b4cb45b/idb/idapython.py#L874
    """
    procname = idaapi.get_inf_structure().procName.lower()
    bitness = get_bitness()
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


def get_call_mnemonics():
    """Return different call instructions based on the arch."""
    procname = idaapi.get_inf_structure().procName.lower()
    print('[D] procName = {}'.format(procname))

    # Default choice
    call_mnemonics = {"call"}

    # MIPS
    if procname == "mipsr" \
            or procname == "mipsb" \
            or procname == "mipsrl" \
            or procname == "mipsl":
        call_mnemonics = {
            "jal",
            "jalrc16",
            "jalrc.hb",
            "jalrc",
            "jalr",
            "jalr.hb",
            "jalx",
            "jal"
        }

    # ARM
    if procname == "arm" \
            or procname == "armb":
        call_mnemonics = {"bl", "blx"}
    return call_mnemonics


def capstone_disassembly(md, ea, size, prefix):
    """Return a list of tuples: (address, mnemonic, [operands])."""
    try:
        bb_inss = list()

        # Get the binary data corresponding to the instruction.
        binary_data = idc.get_bytes(ea, size)
        if binary_data is None:
            return bb_inss

        # Iterate over each instruction in the BB
        for i_inst in md.disasm(binary_data, ea):
            # Iterate over the operands
            ins_operands = []
            use_fallback = False
            for op in i_inst.operands:
                ins_op = None

                # Type register
                if (op.type == 1):
                    ins_op = i_inst.reg_name(op.reg)

                # Type immediate
                elif (op.type == 2):
                    ins_op = '#' + str(hex(op.imm))

                # Type memory
                elif (op.type == 3):
                    # If the base register is zero, convert to "MEM"
                    if (op.mem.base == 0):
                        ins_op = '[MEM]'
                    else:
                        # Scale not available, e.g. for ARM
                        if not hasattr(op.mem, 'scale'):
                            ins_op = "[{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.disp))
                        else:
                            ins_op = "[{}*{}+{}]".format(
                                str(i_inst.reg_name(op.mem.base)),
                                str(op.mem.scale),
                                str(op.mem.disp))

                if ins_op is None:
                    use_fallback = True
                    break

                assert ins_op is not None
                ins_operands.append(ins_op)

            if use_fallback:
                ins_operands = i_inst.op_str.split(', ')

            # make the operands look nicer
            ins_operands = tuple(
                [op.replace("*1+", "+").replace("+-", "-")
                 for op in ins_operands])

            ins = (i_inst.address, i_inst.mnemonic, ins_operands)
            bb_inss.append(ins)

        return bb_inss

    except Exception as e:
        print("[!] Capstone exception", e)
        print('tb: {}'.format(traceback.format_exc()))
        return list()


def split_instruction_list(instructions):
    """
    Takes a sequence of instructions of the form:
    [ (address, "mnem", ("op1", ..., "opN")), ... ]
    and returns multiple lists of such instructions, split after each
    instruction where "mnem" is equal to split_mnemonic.

    Can be re-used for other disassemblers that do not split basic blocks after
    a CALL.

    Original code from Thomas Dullien (Apache License 2.0):
    https://github.com/googleprojectzero/functionsimsearch/blob/
    master/pybindings/ida_example.py#L30
    """
    split_mnemonics = get_call_mnemonics()
    results = []
    index = 0
    results.append([])
    while index < len(instructions):
        # Appends the current instruction under consideration to the last list in the
        # list-of-lists 'results'.
        results[-1].append(instructions[index])
        # Checks if the right mnemonic to 'split' on is encountered.
        if (instructions[index][1] in split_mnemonics):
            # Time to split. Simply appends an empty list to 'results'.
            results.append([])
        index = index + 1
    # It is possible to have appended an empty list if the instruction-to-split-on
    # was the last instruction of the block. Remove it if this happens.
    if len(results[-1]) == 0:
        results.pop()
    return results


def get_flowgraph_from(address, use_capstone):
    """
    Return the set of nodes, edges and features for a given func.

    Original code from Thomas Dullien (Apache License 2.0):
    https://github.com/googleprojectzero/functionsimsearch/blob/
    master/pybindings/ida_example.py#L58
    """
    md, prefix = None, None
    if use_capstone:
        md, prefix = initialize_capstone()

    ida_flowgraph = idaapi.FlowChart(idaapi.get_func(address))
    nodes_set, edges_set = set(), set()
    instructions_dict = dict()

    for block in ida_flowgraph:
        # From the original code:
        # Add all the ida-flowgraph-basic blocks. We do this up-front so we can
        # more easily add edges later, and adding a node twice does not hurt.
        nodes_set.add(block.start_ea)

    for block in ida_flowgraph:
        instructions = list()
        if use_capstone:
            size = block.end_ea - block.start_ea
            if not size:
                continue
            instructions.extend(
                capstone_disassembly(md, block.start_ea, size, prefix))
        else:
            for ii in idautils.Heads(block.start_ea, block.end_ea):
                instructions.append((
                    ii,
                    idc.GetMnem(ii),
                    # FIXME: only two operands?
                    # It's ok for x86/64 but it will not work on other archs.
                    (idc.print_operand(ii, 0).replace("+var_", "-0x"),
                     idc.print_operand(ii, 1).replace("+var_", "-0x"))
                ))

        if not len(instructions):
            continue

        small_blocks = split_instruction_list(instructions)
        for small_block in small_blocks:
            node = small_block[0][0]
            nodes_set.add(node)
            small_block_instructions = \
                tuple(instruction[1:] for instruction in small_block)
            instructions_dict[node] = small_block_instructions

        for index in range(len(small_blocks) - 1):
            edges_set.add((
                small_blocks[index][0][0],
                small_blocks[index + 1][0][0]))

        for successor_block in block.succs():
            edges_set.add((
                small_blocks[-1][0][0],
                successor_block.start_ea))

    return nodes_set, edges_set, instructions_dict


def run_fss(idb_path, fva_list, output_dir, use_capstone):
    """Extract the flowgraph for each function. Save output to JSON."""
    print("[D] Processing: %s" % idb_path)
    j_out = dict()

    # Create the output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    out_json_name = ntpath.basename(idb_path.replace(".i64", ""))
    out_json_name += "_Capstone_{}_fss.json".format(use_capstone)
    out_json_path = os.path.join(output_dir, out_json_name)

    # For each function in the list
    for fva in fva_list:
        try:
            nodes_set, edges_set, instructions_dict = \
                get_flowgraph_from(fva, use_capstone)

            j_out[hex(fva)] = {
                'nodes': list(nodes_set),
                'edges': list(edges_set),
                'instructions': instructions_dict,
            }

        except Exception:
            print("[!] Exception: skipping function fva: %d" % fva)
            print('tb: {}'.format(traceback.format_exc()))

    with open(out_json_path, "w") as f_out:
        json.dump({idb_path: j_out}, f_out)


if __name__ == '__main__':
    if not idaapi.get_plugin_options("fss"):
        print("[!] -Ofss option is missing")
        idc.Exit(1)

    plugin_options = idaapi.get_plugin_options("fss").split(":")
    if len(plugin_options) != 4:
        print("[!] -Ofss:INPUT_JSON:IDB_PATH:OUTPUT_DIR:USE_CAPSTONE")
        idc.Exit(1)

    input_json = plugin_options[0]
    idb_path = plugin_options[1]
    output_dir = plugin_options[2]
    use_capstone_str = plugin_options[3]

    use_capstone = False
    if use_capstone_str == 'True':
        use_capstone = True

    with open(input_json) as f_in:
        selected_functions = json.load(f_in)

    if idb_path not in selected_functions:
        print("[!] Error! IDB path (%s) not in %s" % (idb_path, input_json))
        idc.Exit(1)

    fva_list = selected_functions[idb_path]
    print("[D] Found %d addresses" % len(fva_list))

    run_fss(idb_path, fva_list, output_dir, use_capstone)
    idc.Exit(0)
