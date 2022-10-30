#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
#  safe-preprocessing.py - Create list of instructions embeddings.           #
#                                                                            #
##############################################################################

import click
import json
import numpy as np
import os

from collections import defaultdict
from tqdm import tqdm


def convert_instructions(node_list, fva_data, ins2id_dict, max_instructions):
    """
    Convert function assembly instructions into numerical identifiers.

    Args
        node_list: list of basic-blocks addresses
        fva_data: dict with features associated to a function
        ins2id_dict: a dictionary that maps instructions to numerical IDs
        max_instructions: maximum number of instructions per basic block

    Return
        str: encoded list of numerical identifiers
    """
    norm_idx_list = list()

    # Iterate over each BBs
    for node_fva in node_list:
        node_data = fva_data["basic_blocks"][str(node_fva)]
        for ni in node_data["bb_norm"]:
            if ni in ins2id_dict:
                norm_idx_list.append(ins2id_dict[ni])
            else:
                norm_idx_list.append(-1)
        if len(norm_idx_list) >= max_instructions:
            break

    # Add a +1, since all the indexes in the emb. matrices are +1
    # compared to the value stored in the ins2id_dict dict.
    norm_idx_list = [x + 1 for x in norm_idx_list]
    return ';'.join(map(str, norm_idx_list))


def create_functions_dict(input_folder, ins2id_json, max_instructions):
    """
    Create a features vector for each selected function.

    Args
        input_folder: a folder with JSON files from IDA_acfg_disasm
        ins2id_dict: a dictionary that maps instructions to numerical IDs
        max_instructions: maximum number of instructions per basic block

    Return
        dict: map each function to a list of instructions' ID
    """
    try:
        ins2id_dict = None
        # Map normalized instructions to indexes in the embedding matrix
        if os.path.isfile(ins2id_json):
            with open(ins2id_json) as f_in:
                ins2id_dict = json.load(f_in)
        if not ins2id_dict:
            print("[!] Error loading {}".format(ins2id_json))
            return dict()

        functions_dict = defaultdict(dict)

        for f_json in tqdm(os.listdir(input_folder)):
            if not f_json.endswith(".json"):
                continue

            json_path = os.path.join(input_folder, f_json)
            with open(json_path) as f_in:
                jj = json.load(f_in)

                idb_path = list(jj.keys())[0]
                print("[D] Processing: {}".format(idb_path))
                j_data = jj[idb_path]
                del j_data['arch']

                # Iterate over each function
                for fva in j_data:
                    fva_data = j_data[fva]
                    node_list = sorted(fva_data["nodes"])
                    functions_dict[idb_path][fva] = {
                        "idx_list": convert_instructions(
                            node_list, fva_data, ins2id_dict, max_instructions)
                    }

        return functions_dict

    except Exception as e:
        print("[!] Exception in create_functions_dict\n{}".format(e))
        return dict()


def log_instructions_coverage(functions_dict, output_dir):
    """
    Log functions that have more than 50% of UNK instructions.

    Args:
        functions_dict: map each function to a list of instructions' ID
        output_dir: output directory
    """
    output_path = os.path.join(output_dir, "log_coverage.txt")
    f_out = open(output_path, "w")

    for idb in functions_dict.keys():
        for fva in functions_dict[idb].keys():
            a_list = functions_dict[idb][fva]["idx_list"]
            unk = [0 if int(x) == 0 else 1 for x in a_list.split(";")]
            coverage = sum(unk) / len(unk) * 100
            if coverage < 50:
                f_out.write(
                    "[D] {}:{} Low coverage: {}% ({}/{})\n".format(
                        idb, fva, np.around(coverage, 2), sum(unk), len(unk)))
    f_out.close()


@click.command()
@click.option('-i', '--input-dir', required=True,
              help='IDA_acfg_disasm JSON files.')
@click.option('-d', '--ins2id-json',
              default="/instruction_embeddings/ins2id.json",
              help='The ins2id JSON file.')
@click.option('-m', '--max-instructions',
              default=250,
              help='Maximum instructions per function.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(input_dir, ins2id_json, max_instructions, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    o_dict = create_functions_dict(input_dir, ins2id_json, max_instructions)
    o_json = "instructions_embeddings_list_{}.json".format(max_instructions)
    output_path = os.path.join(output_dir, o_json)
    with open(output_path, 'w') as f_out:
        json.dump(o_dict, f_out)
    log_instructions_coverage(o_dict, output_dir)


if __name__ == '__main__':
    main()
