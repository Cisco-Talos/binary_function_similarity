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
#  PVDM / PVDBOW / Asm2vec preprocessing                                     #
#                                                                            #
##############################################################################


import argparse
import coloredlogs
import json
import logging
import multiprocessing
import networkx as nx
import os
import random
import re

from collections import Counter
from collections import defaultdict
from tqdm import tqdm

log = None
# FIXED PARAM
random.seed(11)


INST_SPLITTER = re.compile(r"[#,\{\}\+\-\*\\\[\]:\(\)\s]")


def set_logger(debug, outputdir):
    """
    Set logger level, syntax, and logfile.

    Args
        debug: if True, set the log level to DEBUG
        outputdir: path of the output directory for the logfile
    """
    LOG_NAME = 'i2v_preprocessing'

    global log
    log = logging.getLogger(LOG_NAME)

    fh = logging.FileHandler(os.path.join(
        outputdir, '{}.log'.format(LOG_NAME)))
    fh.setLevel(logging.DEBUG)

    fmt = '%(asctime)s %(levelname)s:: %(message)s'
    formatter = coloredlogs.ColoredFormatter(fmt)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        loglevel = 'DEBUG'
    else:
        loglevel = 'INFO'
    coloredlogs.install(fmt=fmt,
                        datefmt='%H:%M:%S',
                        level=loglevel,
                        logger=log)


def generate_random_walks(G, num_rwalks, max_walk_len):
    """
    Generate random walks on the CFG in input.

    Args
        G: a nx.DiGraph representing a function CFG
        num_rwalks: number of random walks
        max_walk_len: max number of BB in the random walk

    Return
        a list of (num_rwalks X) lists of BBs
    """
    list_rwalks = list()

    # Graph is empty
    if len(G.nodes) == 0:
        log.warning("Graph doesn't contain any node")
        return list_rwalks

    # Graph contains one node only:
    if len(G.nodes) == 1:
        log.warning("Graph contains 1 node only")
        return [[list(G.nodes)[0]] for x in range(num_rwalks)]

    for _ in range(num_rwalks):
        rwalk = list()
        rwalk_set = set()

        # Start from one node with no incoming edges if exists
        starting_nodes = [n for n in G.nodes if G.in_degree(n) == 0]
        if len(starting_nodes) > 0:
            # Pick-up a random node among those in the list
            current_node = random.sample(starting_nodes, k=1)[0]
        else:
            # If could not find a node with in_degree == 0,
            # take the node at the lowest address
            current_node = min(list(G.nodes))

        # Update the current walk
        rwalk_set.add(current_node)
        rwalk.append(current_node)

        # Update the list of successors
        # If there is a loop, do not take the same node multiple times
        successors = set(G.successors(current_node)) - rwalk_set

        # Iterate until there is still a successor and the len
        #   of the list does not exceed the maximum length.
        while (len(successors) > 0) \
                and (len(rwalk) < max_walk_len):

            # Pick up a random successor node
            current_node = random.choice(list(successors))

            # Update the current random walk
            rwalk_set.add(current_node)
            rwalk.append(current_node)

            # Update the list of successors
            successors = set(G.successors(current_node)) - rwalk_set

        # log.debug("New random walk of size: %d" % len(rwalk))
        list_rwalks.append(rwalk)
    return list_rwalks


def instruction_splitter(instruction):
    """
    Split an instruction into simpler components. If you are using IDA
    "print_operand", you may want to exclude the dummy names
    (https://www.hex-rays.com/products/ida/support/idadoc/609.shtml)

    This function expect the output from Capstone disassembler.

    Args
        instruction: the ASM instruction

    Return
        a list of (valid) splits
    """
    return [x for x in INST_SPLITTER.split(instruction) if x]


def generate_instruction_sequences(random_walk, blocks_dict, max_walk_tokens):
    """
    Convert the list of basic blocks into a list of instructions.

    Args
        random_walk: a list of basic blocks
        blocks_dict: a dictionary with the BBs of the function
        max_walk_tokens: maximum number of tokens per rand walk
          (here it is used to limit the max number of instructions!)

    Return
        the list of tokens (mnemonic and operands)
    """
    instructions_list = list()

    for b_id in random_walk:
        if not str(b_id) in blocks_dict:
            continue
        # Get the corresponding BB
        bb_disasm = blocks_dict[str(b_id)]['bb_disasm']

        for instruction in bb_disasm:
            instruction = instruction.lower()
            # log.debug("Instruction (pre split) %s", instruction)
            instruction = instruction_splitter(instruction)
            # log.debug("Instruction (post split) %s", instruction)
            instructions_list.append(instruction)

            # max_walk_tokens is the upper limit
            if len(instructions_list) > max_walk_tokens:
                break

    return instructions_list


def generate_CFG(nodes, edges):
    """
    Construct a nx.Digraph (CFG) from the list of nodes and edges.

    Args
        nodes: list of BB nodes
        edges: list of BB edges

    Return
        nx.DiGraph of the function CFG
    """
    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node)
    for edge in edges:
        G.add_edge(edge[0], edge[1])
    return G


def get_tokens_count(functions_dict):
    """
    Count the number of occurrences for tokens in the random_walks.

    Args
        functions_dict: map functions to random walks

    Return
        Counter: the frequency of each token in the rand walks
    """
    c = Counter()
    for random_walks in functions_dict.values():

        # Each function is associated with several random walks
        for instructions_list in random_walks:
            for ins in instructions_list:
                c.update(ins)
    return c


def select_tokens(counter_dict, min_frequency, vocabulary=None):
    """
    Count the number of occurrences for each token.

    Args
        counter_dict: a dict that maps each token to a frequency counter
        min_frequency: minimum tokens frequency
        vocabulary: the set of tokens in the vocabulary

    Return
        set: tokens to keep
        set: tokens to discard
        dict: a dict that maps each token to a frequency counter
    """
    log.info("[*] Tokens selection started")
    log.info("\tFound {} total tokens".format(len(counter_dict.keys())))

    if not vocabulary:
        log.info("\tGenerating tokens vocabulary")
        # If the vocabulary is not defined (i.e., training dataset)
        new_counter_dict = {x: y for x,
                            y in counter_dict.items() if y >= min_frequency}
        selected_tokens = new_counter_dict.keys()
        dropped_tokens = counter_dict.keys() - selected_tokens

    else:
        log.info("\tUsing existing tokens vocabulary")
        # If the vocabulary is defined (i.e., testing dataset)
        selected_tokens = counter_dict.keys() & vocabulary
        new_counter_dict = {x: counter_dict[x]
                            for x in (selected_tokens)}
        dropped_tokens = counter_dict.keys() - selected_tokens

    log.info("\t{} dropped tokens".format(len(dropped_tokens)))
    log.info("\t{} selected tokens".format(len(selected_tokens)))

    return selected_tokens, dropped_tokens, new_counter_dict


def load_vocabulary_from_file(input_path):
    """
    Load the vocabulary of tokens from file. Tokens are saved one per line.

    Args
        input_path: path of the vocabulary file

    Return
        vocabulary_set: the set of words in the vocabulary
    """
    log.info("[*] Loading vocabulary form: {}".format(input_path))
    with open(input_path) as f_in:
        vocabulary_set = set(f_in.read().splitlines())

    log.info("[*] Loaded {} tokens.".format(len(vocabulary_set)))
    return vocabulary_set


def save_vocabulary_to_file(selected_tokens, output_path):
    """
    Save to file the vocabulary of selected tokens, one per line.

    Args
        selected_tokens: the set of tokens (words) selected for training
        output_path: the path of the file in output
    """
    with open(output_path, "w") as f_out:
        f_out.write("\n".join(list(selected_tokens)))

    log.info("[*] Vocabulary saved to: {}".format(output_path))


def save_counter_dict_to_file(counter_dict, output_path):
    """
    Save to file the dictionary with the tokens count.

    Args
        counter_dict: a dictionary with the count associated to each token
        output_path: the path of the JSON file
    """
    with open(output_path, "w") as f_out:
        json.dump(counter_dict, f_out)

    log.info("[*] Tokens counter saved to: {}".format(output_path))


def save_rwalks_to_file_inner(asm2vec, max_tokens, functions_dict,
                              id2func, func2id, f_out, vocabulary, max_id):
    """
    Dump to file the selected list of tokens for each function.

    Args
        asm2vec: if True, save the tokens for the same instruction all together
        max_tokens: max number of tokens for each random walk
        functions_dict: dict that maps functions to random walks
        id2func: dict that maps numerical IDS to function names (idb + fva)
        func2id: the opposite of id2func
        f_out: fp for the output file
        vocabulary: selected vocabulary
        max_id: starting counter for the functions identifiers
    """
    # Map functions to id and vice versa
    for _id, func in enumerate(functions_dict.keys()):
        id2func[_id + max_id] = func
        func2id[func] = _id + max_id

    # Iterate over all the functions
    for func, rand_walks in functions_dict.items():
        _id = func2id[func]

        # Iterate over each random walk associated to the function
        for rand_walk in rand_walks:

            new_rand_walk = list()

            # Count the number of tokens for each random walk
            cnt_rand_walk = 0

            # Iterate over the instructions of the random walk
            for ins in rand_walk:
                new_ins = [
                    x if x in vocabulary else 'UNK' for x in ins]
                if asm2vec:
                    new_rand_walk.append('::'.join(new_ins))
                else:
                    new_rand_walk.extend(new_ins)

                # Approximated (the length can be a bit higher than max_tokens)
                cnt_rand_walk += len(new_ins)
                if cnt_rand_walk > max_tokens:
                    break

            f_out.write("{},{}\n".format(_id, ";".join(new_rand_walk)))


def save_rwalks_to_file(queue_funcs_dict, config, vocabulary,
                        outputdir, tot_iterations):
    """
    Wrapper function that save tokens to file

    Args
        queue_funcs_dict: queue with results from workers
        config: configuration dictionary (model name, random walk length...)
        vocabulary: set of the vocabulary tokens (can be None)
        outputdir: output directory to save the results
        tot_iterations: this is used to update the progress bar
    """
    log.info("[*] Saving random walks to file")
    id2func = dict()
    func2id = dict()

    asm2vec = False
    if config['model'] == 'a2v':
        asm2vec = True

    # Save random walks to file
    output_path = os.path.join(
        outputdir, "random_walks_{}.csv".format(config['model']))
    f_out = open(output_path, "w")
    f_out.write("func_id,random_walk\n")

    # Collect the fdict results
    pbar = tqdm(total=tot_iterations)
    while not queue_funcs_dict.empty():
        f_dict = queue_funcs_dict.get()

        save_rwalks_to_file_inner(
            asm2vec=asm2vec,
            max_tokens=config['max_walk_tokens'],
            functions_dict=f_dict,
            id2func=id2func,
            func2id=func2id,
            f_out=f_out,
            vocabulary=vocabulary,
            max_id=len(id2func))
        pbar.update(1)
    pbar.close()

    f_out.close()
    log.info("\trandom_walks saved to: {}".format(output_path))

    # Save the id2func mapping to file
    output_path = os.path.join(outputdir, "id2func.json")
    with open(output_path, "w") as f_out:
        json.dump(id2func, f_out)
    log.info("\tid2func saved to: {}".format(output_path))


def worker_func(queue_counter_dict, queue_funcs_dict, j_path, config):
    """
    Random walks and tokens extraction for each function.

    Args:
        queue_counter_dict: multiprocess queue to collect the results
        queue_funcs_dict: multiprocess queue to collect the results
        j_path: path of the mldisasm JSON file in input
        config: configuration dictionary

    Return:
        functions_dict: a dict that maps functions to random walks.
    """
    functions_dict = defaultdict(list)

    with open(j_path) as f_in:
        jj = json.load(f_in)

    idb_path = list(jj.keys())[0]
    print("[D] Processing: {}".format(idb_path))
    j_data = jj[idb_path]
    del j_data['arch']
    # num_functions = len(j_data.keys())

    # Iterate over each function
    for cnt, fva in enumerate(j_data):
        # print("[D] Processing: {}:{} ({}/{})".format(
        #     idb_path, fva, cnt + 1, num_functions))

        fva_data = j_data[fva]

        # Generate a nx.Digraph for the function
        nodes = fva_data['nodes']
        edges = fva_data['edges']
        G = generate_CFG(nodes, edges)

        random_walks = list()

        # In the first visit use the original instructions order
        random_walks.append(list(fva_data['nodes']))
        num_rwalks = config['num_rwalks'] - 1

        # Add the other visits in random order
        if num_rwalks > 0:
            random_walks.extend(generate_random_walks(
                G, num_rwalks=num_rwalks,
                max_walk_len=config['max_walk_len']))

        # Convert a visit into a list of instructions
        for random_walk in random_walks:
            instructions_list = generate_instruction_sequences(
                random_walk,
                fva_data['basic_blocks'],
                config['max_walk_tokens'])

            # functions_dict contains a list of random walks for each function
            #   Each random_walk is a list of instructions
            #   Each instruction is a list of mnemonic and operands
            functions_dict["{}:{}".format(idb_path, fva)].append(
                instructions_list)

    # Save the results in the queue
    queue_counter_dict.put(get_tokens_count(functions_dict))
    queue_funcs_dict.put(functions_dict)


def preprocess_inputs(config, inputdir, outputdir,
                      vocabulary_set, num_workers):
    """
    Run the workers to process the input data.

    Args
        config: a dictionay with the configuration parameters
        inputdir: a directory with the IDA_acfg_disasm files
        outputdir: the output directory
        vocabulary_set: the set of tokens in the vocabulary
        workers: number of workers for parallel execution
    """
    c_dict_glob = Counter()

    pool_results = list()
    log.info("[*] Creating a new Pool (num_workers: {})".format(num_workers))
    pool = multiprocessing.Pool(processes=num_workers, maxtasksperchild=50)

    # Creating two queues: one to for the tokens counter,
    #   the other for the functions random walks.
    m = multiprocessing.Manager()
    queue_counter_dict = m.Queue()
    queue_funcs_dict = m.Queue()

    # Iterate over each JSON file (each JSON corresponds to an IDB)
    for f_name in tqdm(os.listdir(inputdir)):
        if not f_name.endswith(".json"):
            continue

        j_path = os.path.join(inputdir, f_name)
        res = pool.apply_async(worker_func, args=(
            queue_counter_dict, queue_funcs_dict, j_path, config,))
        pool_results.append(res)

    log.info("[*] Waiting for processes to finish")

    # Close the pool
    pool.close()
    pool.join()

    # Wait for all the async tasks to finish
    for res in pool_results:
        res.get()
    log.info("[*] All processes finished")

    # Collect the results from queue_counter_dict
    log.info("[*] Collecting results from counter_dict")

    pbar = tqdm(total=len(pool_results))
    while not queue_counter_dict.empty():
        c_dict_glob += queue_counter_dict.get()
        pbar.update(1)
    pbar.close()

    # Evaluation and test data use the same tokens as in the vocabulary
    selected_tokens = vocabulary_set
    dropped_tokens = None
    new_counter_dict = None

    if not vocabulary_set:
        # Select which tokens to filter-out based on their frequency
        selected_tokens, dropped_tokens, new_counter_dict = select_tokens(
            counter_dict=c_dict_glob,
            min_frequency=config['min_frequency'],
            vocabulary=vocabulary_set)

    # Save random walks to file
    save_rwalks_to_file(queue_funcs_dict, config,
                        selected_tokens, outputdir, len(pool_results))

    if not vocabulary_set:
        output_file = "vocabulary.csv"
        output_path = os.path.join(outputdir, output_file)
        save_vocabulary_to_file(selected_tokens, output_path)

        output_file = "vocabulary_dropped.csv"
        output_path = os.path.join(outputdir, output_file)
        save_vocabulary_to_file(dropped_tokens, output_path)

        output_file = "counter_dict.json"
        output_path = os.path.join(outputdir, output_file)
        save_counter_dict_to_file(new_counter_dict, output_path)


def main():
    parser = argparse.ArgumentParser(
        prog='i2v_preprocessing',
        description='i2v_preprocessing',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Log level debug')

    parser.add_argument('-i', '--inputdir', required=True,
                        help='Input dir with mldisasm JSONs files')

    group0 = parser.add_mutually_exclusive_group(required=True)
    group0.add_argument('-d2v', '--doc2vec', dest='model',
                        action='store_const', const='d2v',
                        help='Use it for the PV-DM or PV-DBOW model')
    group0.add_argument('-a2v', '--asm2vec', dest='model',
                        action='store_const', const='a2v',
                        help='Use it for the asm2vec model version')

    parser.add_argument('--num_rwalks', type=int, default=10,
                        help="Number of random walks")

    parser.add_argument('--max_walk_len', type=int, default=500,
                        help="Max number of BBs in each random_walk")

    parser.add_argument('--max_walk_tokens', type=int, default=50000,
                        help="Max number of tokens for each random_walk")

    parser.add_argument('--min_frequency', type=int, default=3,
                        help="Min tokens counter for selection")

    parser.add_argument('-v', '--vocabulary',
                        help='Path of an existing vocabulary')

    parser.add_argument('-w', '--workers', type=int, default=2,
                        help='Number of workers to process the input')

    parser.add_argument('-o', '--outputdir', required=True,
                        help='Output dir for logs and checkpoints')
    args = parser.parse_args()

    # Create the output directory
    if args.outputdir:
        if not os.path.isdir(args.outputdir):
            os.mkdir(args.outputdir)
            print("[*] Created outputdir: {}".format(args.outputdir))

    # Create logger
    set_logger(args.debug, args.outputdir)

    log.info(args.model)

    config = {
        'model': args.model,
        'num_rwalks': int(args.num_rwalks),
        'max_walk_len': int(args.max_walk_len),
        'max_walk_tokens': int(args.max_walk_tokens),
        'min_frequency': int(args.min_frequency),
    }

    vocabulary_set = None
    if args.vocabulary:
        log.info("[*] Fixed vocabulary: use with TEST data only")
        vocabulary_set = load_vocabulary_from_file(args.vocabulary)
    else:
        log.info("[*] New vocabulary: use with TRAINING data only")

    preprocess_inputs(config=config,
                      inputdir=args.inputdir,
                      outputdir=args.outputdir,
                      vocabulary_set=vocabulary_set,
                      num_workers=args.workers)


if __name__ == '__main__':
    main()
