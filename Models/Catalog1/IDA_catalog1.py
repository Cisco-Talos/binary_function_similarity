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
#  IDA_catalog1.py - Catalog1 IDA plugin implementation.                     #
#                                                                            #
##############################################################################

import ida_bytes
import idaapi
import idc
import json
import os
import time

from catalog1.catalog_fast import sign
from collections import namedtuple

COLUMNS = ['path', 'address', 'size', 'catalog_hash_list', 'time']
BasicBlock = namedtuple('BasicBlock', ['va', 'size'])


def get_basic_blocks(fva):
    """Return the list of BasicBlock for a given function."""
    bb_list = list()
    func = idaapi.get_func(fva)
    if func is None:
        return bb_list
    for bb in idaapi.FlowChart(func):
        # NOTE: a BB may have size 0.
        bb_list.append(
            BasicBlock(
                va=bb.start_ea,
                size=bb.end_ea - bb.start_ea))
    return bb_list


def run_catalog1(idb_path, fva_list, sig_size, output_csv):
    """Compute the Catalog1 hash for each selected function."""
    csv_out = None
    if os.path.isfile(output_csv):
        # Found. Open the file in append mode
        csv_out = open(output_csv, "a")
    else:
        csv_out = open(output_csv, "w")
        # Not found. Write the column names to CSV
        csv_out.write(",".join(COLUMNS) + "\n")

    print("[D] Output CSV: %s" % output_csv)

    # For each function in the list
    for fva in fva_list:
        try:
            func_binary_data = ""
            for bb in sorted(get_basic_blocks(fva)):
                bb_data = ida_bytes.get_bytes(bb.va, bb.size)
                if bb_data:
                    func_binary_data += bb_data

            # Log the time to compute Catalog1 signatures only
            start_time = time.time()

            if len(func_binary_data) < 4:
                catalog1_signature = ["min_function_size_error"]
            else:
                catalog1_list = sign(func_binary_data, sig_size)
                catalog1_signature = ';'.join([str(x) for x in catalog1_list])

            elapsed_time = time.time() - start_time
            data = [idb_path,
                    hex(fva).strip("L"),
                    len(func_binary_data),
                    catalog1_signature,
                    elapsed_time]

            # Write the result to the CSV
            csv_out.write(",".join([str(x) for x in data]) + "\n")

        except Exception as e:
            print("[!] Exception: skipping function fva: %d" % fva)
            print(e)

    csv_out.close()
    return


if __name__ == '__main__':
    if not idaapi.get_plugin_options("catalog1"):
        print("[!] -Ocatalog1 option is missing")
        idaapi.qexit(1)

    plugin_options = idaapi.get_plugin_options("catalog1").split(':')
    if len(plugin_options) != 4:
        print("[!] -Ocatalog1:INPUT_JSON:IDB_PATH:SIG_SIZE:OUTPUT_CSV is required")
        idaapi.qexit(1)

    input_json = plugin_options[0]
    idb_path = plugin_options[1]
    sig_size = int(plugin_options[2])
    output_csv = plugin_options[3]

    with open(input_json) as f_in:
        selected_functions = json.load(f_in)

    if idb_path not in selected_functions:
        print("[!] Error! IDB path (%s) not in %s" % (idb_path, input_json))
        idaapi.qexit(1)

    fva_list = selected_functions[idb_path]
    print("[D] Found %d addresses" % len(fva_list))

    run_catalog1(idb_path, fva_list, sig_size, output_csv)
    idaapi.qexit(0)
