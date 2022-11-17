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
#  IDA_codeCMR.py - codeCMR IDA plugin implementation.                       #
#                                                                            #
#  This plugins contains code from:                                          #
#  https://github.com/binaryai/sdk/ licensed under GPL-3.0                   #
#                                                                            #
##############################################################################

import ctypes
import hashlib
import idaapi
import idautils
import idc
import json
import networkx as nx
import os
import pickle
import time

M_MAX = 0x49  # first unused opcode


def get_idb_info():
    """
    Original code from BinaryAI (GPL-3.0):

    https://github.com/binaryai/sdk/blob/
    efcea6b27b36326f3de9ab6bfa0f668d3513e6c7/binaryai/ida/ida_feature.py#L56
    """
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = '64'
    elif info.is_32bit():
        bits = '32'
    else:
        bits = ''

    return ''.join([info.procname, bits])


class CtreeFeature(idaapi.ctree_visitor_t):
    """
    Original code from BinaryAI (GPL-3.0):

    https://github.com/binaryai/sdk/blob/
    efcea6b27b36326f3de9ab6bfa0f668d3513e6c7/binaryai/ida/ida_feature.py#L68
    """

    def __init__(self, state, expr, num, stri, strlist):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.state = state
        self.expr = expr
        self.num = num
        self.stri = stri
        self.strlist = strlist

    def visit_expr(self, item):
        self.expr.append(item.op)
        if item.op == idaapi.cot_num:
            self.num.append(ctypes.c_long(item.n._value).value)
        elif item.op == idaapi.cot_obj:
            addr = item.obj_ea
            if addr in self.strlist:
                string = idc.get_strlit_contents(addr)
                if string is not None:
                    self.stri.append(string)
        elif item.op == idaapi.cot_str:
            self.stri.append(item.string)

        return 0

    def visit_insn(self, item):
        self.state.append(item.op)
        return 0


def parse_minsn(minsn, micro_int, ins=None):
    """
    Original code from BinaryAI (GPL-3.0):

    https://github.com/binaryai/sdk/blob/
    efcea6b27b36326f3de9ab6bfa0f668d3513e6c7/binaryai/ida/ida_feature.py#L96
    """
    ins = [] if ins is None else ins
    ins.append(minsn.opcode)
    for op in [minsn.l, minsn.r, minsn.d]:
        if op.t == idaapi.mop_d:
            parse_minsn(op.d, micro_int, ins)
        elif op.t == idaapi.mop_f:
            for arg in op.f.args:
                if arg.t == idaapi.mop_d:
                    parse_minsn(arg.d, micro_int, ins)
                else:
                    ins.append(arg.t + M_MAX)
        else:
            ins.append(op.t + M_MAX)
            if op.t == idaapi.mop_n:
                micro_int.append(ctypes.c_long(op.nnn.value).value)
    return ins


def parse_func(pfn, strlist):
    """
    Original code from BinaryAI (GPL-3.0):

    https://github.com/binaryai/sdk/blob/
    efcea6b27b36326f3de9ab6bfa0f668d3513e6c7/binaryai/ida/ida_feature.py#L115
    """
    try:
        hf = idaapi.hexrays_failure_t()
        cfunc = idaapi.decompile(pfn.start_ea, hf)
        mbr = idaapi.mba_ranges_t(pfn)
        mba = idaapi.gen_microcode(
            mbr,
            hf,
            None,
            idaapi.DECOMP_NO_WAIT,
            idaapi.MMAT_GLBOPT3
        )
    except Exception:
        return None
    if mba is None:
        return None

    G = nx.DiGraph()
    ctree_state, ctree_expr, \
        ctree_int, ctree_str, \
        micro_int = [], [], [], [], []

    # node level
    for i in range(mba.qty):
        mb = mba.get_mblock(i)
        minsn = mb.head
        blk = []
        while minsn:
            ins = parse_minsn(minsn, micro_int)
            blk.append(ins)
            minsn = minsn.next

        G.add_node(mb.serial, feat=blk)
        for succ in mb.succset:
            G.add_edge(mb.serial, succ)
    G.remove_nodes_from([n for n, feat in G.nodes.data('feat') if not feat])

    if G.number_of_nodes() == 0:
        return None, None

    # graph level
    ctree_fea = CtreeFeature(ctree_state, ctree_expr,
                             ctree_int, ctree_str, strlist)
    ctree_fea.apply_to(cfunc.body, None)

    G.graph['c_state'], \
        G.graph['c_expr'], \
        G.graph['c_int'], \
        G.graph['c_str'], \
        G.graph['m_int'] = ctree_state, \
        ctree_expr, ctree_int, \
        ctree_str, micro_int
    G.graph['arg_num'] = len(cfunc.argidx)

    func_bytes = b''
    for start, end in idautils.Chunks(pfn.start_ea):
        fb = idaapi.get_bytes(start, end - start)
        func_bytes += fb
    G.graph['func_bytes'] = func_bytes.hex()
    G.graph['hash'] = hashlib.md5(func_bytes).hexdigest()
    return G, cfunc


def run_codeCMR(idb_path, fva_list, output_dir):
    """Extract codeCMR features from each function. Save output to pickle."""
    print("[D] Processing: %s" % idb_path)

    # Create the output directory if it does not exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    output_name = os.path.basename(
        idb_path.replace(".i64", "").replace(".idb", ""))
    output_name += "_codeCMR.pkl"
    output_path = os.path.join(output_dir, output_name)

    features_dict = dict()
    strlist = [i.ea for i in idautils.Strings()]
    arch = get_idb_info()

    # For each function in the list
    for fva in fva_list:
        try:
            start_time = time.time()
            pfn = idaapi.get_func(fva)
            G, cfunc = parse_func(pfn, strlist)
            if G is None:
                continue
            G.graph['arch'] = arch
            func_name = idaapi.get_func_name(fva)
            G.graph['name'] = func_name
            G.graph['file'] = idb_path
            G.graph['pseudocode'] = str(cfunc)
            features_dict[func_name] = G
            elapsed_time = time.time() - start_time
            print("[D] elapsed_time: (%s, %s)" % (fva, elapsed_time))

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    with open(output_path, 'wb') as f_out:
        pickle.dump(features_dict, f_out)


if __name__ == '__main__':
    if not idaapi.get_plugin_options("codeCMR"):
        print("[!] -OcodeCMR option is missing")
        idc.Exit(1)

    plugin_options = idaapi.get_plugin_options("codeCMR").split(":")
    if len(plugin_options) != 3:
        print("[!] -Ofss:INPUT_JSON:IDB_PATH:OUTPUT_DIR")
        idc.Exit(1)

    input_json = plugin_options[0]
    idb_path = plugin_options[1]
    output_dir = plugin_options[2]

    with open(input_json) as f_in:
        selected_functions = json.load(f_in)

    if idb_path not in selected_functions:
        print("[!] Error! IDB path (%s) not in %s" % (idb_path, input_json))
        idc.Exit(1)

    fva_list = selected_functions[idb_path]
    print("[D] Found %d addresses" % len(fva_list))

    run_codeCMR(idb_path, fva_list, output_dir)
    idaapi.qexit(0)
