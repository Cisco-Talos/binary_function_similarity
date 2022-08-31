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
#  Trex generate function traces                                             #
#                                                                            #
##############################################################################

import click
import json
import os
import re

from collections import defaultdict
from tqdm import tqdm

MAX_INS = 512


def tokenize_instruction(ins):
    """
    Tokenize the instruction in input.

    Args
        ins: a string representin an assemly instruction

    Return
        list: a list of tokens.
    """
    ins = ins.replace(',', ' , ')
    ins = ins.replace('[', ' [ ')
    ins = ins.replace(']', ' ] ')
    ins = ins.replace(':', ' : ')
    ins = ins.replace('*', ' * ')
    ins = ins.replace('(', ' ( ')
    ins = ins.replace(')', ' ) ')
    ins = ins.replace('{', ' { ')
    ins = ins.replace('}', ' } ')
    ins = ins.replace('#', '')
    ins = ins.replace('$', '')
    ins = ins.replace('!', ' ! ')
    ins = re.sub(r'-(0[xX][0-9a-fA-F]+)', r'- \1', ins)
    ins = re.sub(r'-([0-9a-fA-F]+)', r'- \1', ins)
    return ins.split()


def generate_function_traces(input_dir, output_dir):
    """
    Extract the features that Trex requires in input.

    Args
        input_dir: a folder with JSON files from IDA_acfg_disasm
        output_dir: where the JSON in output is saved
    """
    try:
        traces_dict = defaultdict(dict)
        for f_json in tqdm(os.listdir(input_dir)):
            if not f_json.endswith(".json"):
                continue

            f_path = os.path.join(input_dir, f_json)
            with open(f_path) as f_in:
                jj = json.load(f_in)

            idb = list(jj.keys())[0]
            print("[D] Processing: {}".format(idb))

            j_data = jj[idb]
            if j_data['arch'] == 'arm-32':
                arch = 'arm'
            elif j_data['arch'] == 'arm-64':
                arch = 'arm'
            elif j_data['arch'] == 'mips-32':
                arch = 'mips'
            elif j_data['arch'] == 'mips-64':
                arch = 'mips'
            elif j_data['arch'] == 'x86-32':
                arch = 'x86'
            elif j_data['arch'] == 'x86-64':
                arch = 'x64'
            else:
                raise Exception("[!] Arch not supported.")
            del j_data['arch']

            # Iterate over each function
            for fva in j_data:
                fva_data = j_data[fva]
                instruction_list = list()
                for node_fva in sorted(fva_data["nodes"]):
                    instruction_list.extend(
                        fva_data["basic_blocks"][str(node_fva)]["bb_disasm"])
                code = list()
                inst_idx = list()
                token_idx = list()
                for inst_index, inst in enumerate(instruction_list):
                    tokens = tokenize_instruction(inst)
                    for token_index, token in enumerate(tokens):
                        if '0x' in token.lower():
                            code.append('hexvar')
                        elif token.lower().isdigit():
                            code.append('num')
                        else:
                            code.append(token.lower())
                        inst_idx.append(inst_index)
                        token_idx.append(token_index)

                code_str = " ".join([str(x) for x in code[:MAX_INS]])
                arch_str = " ".join([arch] * len(code[:MAX_INS]))
                inst_pos_str = " ".join([str(x) for x in inst_idx[:MAX_INS]])
                op_pos_str = " ".join([str(x) for x in token_idx[:MAX_INS]])

                traces_dict[idb][fva] = {
                    'code': code_str,
                    'arch_emb': arch_str,
                    'inst_pos_emb': inst_pos_str,
                    'op_pos_emb': op_pos_str
                }

        tmp_out = os.path.join(output_dir, 'trex_traces.json')
        with open(tmp_out, 'w') as f_out:
            json.dump(traces_dict, f_out)

    except Exception as e:
        print("[!] Exception in generate_function_traces\n{}".format(e))


@click.command()
@click.option('-i', '--input-dir', required=True,
              help='IDA_acfg_disasm JSON files.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(input_dir, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    generate_function_traces(input_dir, output_dir)


if __name__ == '__main__':
    main()
