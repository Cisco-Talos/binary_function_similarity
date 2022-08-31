#!/usr/bin/env python3

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
#  fss_simhasher.py - Compute the simhash for all the  functions in input.   #
#                                                                            #
##############################################################################

import click
import functionsimsearch
import json
import os
import tempfile
import time
import traceback

from os.path import isdir
from os.path import join

CSV_COLUMNS = [
    'path',
    'address',
    'num_nodes',
    'branching_nodes',
    'hashes0',
    'hashes1',
    'time']


def construct_flowgraph(nodes, edges, instructions_dict):
    """Construct a functionsimsearch flowgraph."""
    flowgraph = functionsimsearch.FlowgraphWithInstructions()

    # Add the nodes
    for node_ea in nodes:
        flowgraph.add_node(int(node_ea))

    # Add the instructions
    for node_ea, ins in instructions_dict.items():
        ins_t = tuple([(v[0], tuple(v[1])) for v in ins])
        flowgraph.add_instructions(int(node_ea), ins_t)

    # Add the edges
    for edge in edges:
        flowgraph.add_edge(edge[0], edge[1])

    return flowgraph


def compute_simhashes(input_dir, output_dir, imm_w, mnem_w, graph_w):
    """Compute the simhash for all the functions in input."""
    # Initialize the simhasher with a given weight configuration
    sim_hasher = functionsimsearch.SimHasher(
        immediate_weight=imm_w,
        mnem_weight=mnem_w,
        graphlet_weight=graph_w,
    )

    # Iterate over the input JSONs
    for json_name in os.listdir(input_dir):

        if not json_name.endswith('_fss.json'):
            continue

        json_path = join(input_dir, json_name)

        csv_name = json_name.replace(
            '_fss.json',
            f'_IMM:{imm_w:.2f}_MNEM:{mnem_w:.2f}_GRAPH:{graph_w:.2f}.csv')
        csv_path = join(output_dir, csv_name)
        print(f'[D] Processing {json_path} => {csv_path}')

        with open(json_path) as f_in:
            j_in = json.load(f_in)

        f_out = open(csv_path, "w")

        # Write CSV header
        f_out.write(",".join(CSV_COLUMNS) + "\n")

        # Iterate over different "IDBs". Usually, 1 JSON -> 1 IDB.
        for idb_path in j_in.keys():
            # Iterate over each function
            for fva in j_in[idb_path].keys():
                try:
                    j_data = j_in[idb_path][fva]
                    nodes = j_data.get('nodes')
                    edges = j_data.get('edges')
                    instructions_dict = j_data.get('instructions')

                    start_time = time.time()

                    # Get the flowgraph for the current function
                    flowgraph = construct_flowgraph(
                        nodes,
                        edges,
                        instructions_dict)

                    flowgraph_size = flowgraph.size()
                    branching_nodes = flowgraph.number_of_branching_nodes()
                    hashes = sim_hasher.calculate_hash(flowgraph)
                    elapsed_time = time.time() - start_time

                    # Save the simhash to a CSV file
                    columns = [idb_path,
                               fva,
                               flowgraph_size,
                               branching_nodes,
                               hashes[0],
                               hashes[1],
                               elapsed_time]
                    f_out.write(",".join([str(x) for x in columns]) + "\n")

                except Exception:
                    print("[!] Exception: skipping function: {}".format(fva))
                    print('tb: {}'.format(traceback.format_exc()))

        f_out.close()


@click.command()
@click.option('-i', 'input_dir', default='/input')
@click.option('-o', 'output_dir', default='/output')
def main(input_dir, output_dir):
    """Compute the simhash for different weight configs."""
    if not isdir(input_dir):
        print("[!] Error: {} does not exist".format(input_dir))
        return

    if not isdir(output_dir):
        print("[!] Error: {} does not exist".format(input_dir))
        return

    print(f'[D] Input dir: {input_dir}')
    print(f'[D] Output dir: {output_dir}')

    configurations = [
        # immediate, mnemonic, graphlet
        (4, 0.05, 1),
        (0, 0, 1),
        (0, 1, 1),
        (1, 1, 1),
    ]

    # Iterate over the weight configurations
    for imm_w, mnem_w, graph_w in configurations:
        with tempfile.TemporaryDirectory() as t_output_dir:
            compute_simhashes(input_dir, t_output_dir, imm_w, mnem_w, graph_w)

            # aggregate all csvs in one
            output_csv_lines = []
            for temp_csv_name in os.listdir(t_output_dir):
                with open(join(t_output_dir, temp_csv_name)) as f:
                    lines = list(
                        filter(lambda x: x.strip(), f.read().split('\n')))
                    if not len(output_csv_lines):
                        # copy header of the CSV
                        output_csv_lines.append(lines[0])
                    output_csv_lines.extend(lines[1:])

            output_csv_path = join(
                output_dir,
                f'IMM:{imm_w:.2f}_MNEM:{mnem_w:.2f}_GRAPH:{graph_w:.2f}.csv')

            with open(output_csv_path, 'w') as f:
                f.write('\n'.join(output_csv_lines))


if __name__ == '__main__':
    main()
