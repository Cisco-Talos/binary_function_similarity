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
#  safe_pretraining.py                                                       #
#                                                                            #
##############################################################################

import click
import json
import numpy as np
import os

from collections import Counter
from gensim.models import Word2Vec
from gensim.models.callbacks import CallbackAny2Vec
from gensim.models.word2vec import Text8Corpus
from tqdm import tqdm


PRETRAINING_NAME = "pretraining.txt"
PRETRAINING_UNK_NAME = "pretraining_unk.txt"
INS2ID_NAME = "ins2id.json"
INS2COUNT_NAME = "ins2count.json"
MATRIX_NAME = "embeddings.npy"

# [!] Possible improvement
# Instead of using a generic UNK keyword only, use one specific for each arch.
UNK_KEYWORD = "UNK"
MIN_OCCURRENCES = 8
EMBEDDING_SIZE = 100


def create_training_file(input_dir, output_dir):
    """
    Create a training file starting from the normalized assembly.

    Args
        input_dir: a folder with JSON files from IDA_acfg_disasm
        output_dir: the folder where to store the training data
    """
    pretraining_fp = os.path.join(output_dir, PRETRAINING_NAME)
    f_out = open(pretraining_fp, "w")

    for fname in tqdm(os.listdir(input_dir)):
        if not fname.endswith(".json"):
            continue

        with open(os.path.join(input_dir, fname)) as f_in:
            jj = json.load(f_in)

        idb_path = list(jj.keys())[0]
        print("[D] Processing: {}".format(idb_path))
        j_data = jj[idb_path]
        del j_data['arch']

        # Iterate over each function
        for fva in j_data:
            norm_ins_list = list()
            fva_data = j_data[fva]
            # Iterate over each BBs
            for node_fva in sorted(fva_data["nodes"]):
                node_data = fva_data["basic_blocks"][str(node_fva)]
                norm_ins_list.extend(node_data["bb_norm"])
            # Write the normalized assembly of the function to file
            f_out.write(" ".join(norm_ins_list) + "\n")
    f_out.close()

    # Count words frequency
    ins2cnt = Counter()
    for words in Text8Corpus(pretraining_fp):
        ins2cnt.update(Counter(words))

    ins2cnt_fp = os.path.join(output_dir, INS2COUNT_NAME)
    with open(ins2cnt_fp, "w") as f_out:
        json.dump(ins2cnt, f_out)
    print("[D] ins2cnt saved to {}".format(ins2cnt_fp))

    print("[D] Unique instructions: {}".format(len(ins2cnt.keys())))

    filtered_out = [v[0] for v in ins2cnt.items() if v[1] < MIN_OCCURRENCES]
    print("[D] Discarded instructions: {}".format(len(filtered_out)))

    selected = set(ins2cnt.keys()) - set(filtered_out)
    print("[D] Selected instructions: {}".format(len(selected)))

    # Write to a new file the training data with UNK keyword
    pretraining_unk_fp = os.path.join(output_dir, PRETRAINING_UNK_NAME)
    with open(pretraining_unk_fp, "w") as f_out:
        for words in Text8Corpus(pretraining_fp):
            tmp = [w if w in selected else UNK_KEYWORD for w in words]
            f_out.write(" ".join(tmp))


class EpochLogger(CallbackAny2Vec):
    """
    Callback to log information about training
    """

    def __init__(self):
        self.epoch = 0

    def on_epoch_begin(self, model):
        print("Training epoch #{} start".format(self.epoch))

    def on_epoch_end(self, model):
        print("Training epoch #{} end".format(self.epoch))
        self.epoch += 1


def train_instruction_embeddings(output_dir, num_workers):
    """
    Train instruction embeddings using Gensim Word2Vec.

    Args
        output_dir: the folder where to store the training data
        num_workers: number of parallel workers
    """
    print("[D] Training started")
    epoch_logger = EpochLogger()
    pretraining_unk_fp = os.path.join(output_dir, PRETRAINING_UNK_NAME)

    # [!] From the SAFE paper:
    # The model that we use for i2v (for both versions AMD64 and ARM)
    # is the skip-gram implementation of word2vec provided in [28].
    # We used as parameters: embedding size 100, window size 8
    # and word frequency 8.
    gs_model = Word2Vec(Text8Corpus(pretraining_unk_fp),
                        # Size of the word vectors.
                        size=EMBEDDING_SIZE,
                        # Maximum distance between the current and
                        # predicted word within a sentence.
                        window=8,
                        # Ignores all words with lower total frequency.
                        min_count=MIN_OCCURRENCES,
                        # The initial learning rate.
                        alpha=0.025,
                        # If > 0, negative sampling will be used.
                        negative=25,
                        # Threshold to select words to randomly down sample.
                        sample=1e-3,
                        # sg ({0, 1}): 1 for skip-gram; otherwise CBOW.
                        sg=1,
                        # Number of iterations (epochs)
                        iter=15,
                        workers=num_workers,
                        callbacks=[epoch_logger])

    print("[D] Training time: {}".format(gs_model.total_train_time))

    words_dict = {w: gs_model.wv[w] for w in list(gs_model.wv.vocab)}
    print("[D] Found %d words in the vocabulary" % len(words_dict.keys()))

    vector_list = list()
    word_list = list()

    # [!] For compatibility with the original SAFE code,
    # add an array with all 0s at position 0
    vector_list.append(np.zeros(EMBEDDING_SIZE))

    for w, v in words_dict.items():
        word_list.append(w)
        vector_list.append(v)

    ins2id_dict = {x: c for c, x in enumerate(word_list)}
    ins2id_fp = os.path.join(output_dir, INS2ID_NAME)
    with open(ins2id_fp, "w") as f_out:
        json.dump(ins2id_dict, f_out)
    print("[D] ins2id_dict saved to {}".format(ins2id_fp))

    vector_list = np.array(vector_list)
    matrix_fp = os.path.join(output_dir, MATRIX_NAME)
    with open(matrix_fp, "wb") as f_out:
        np.save(f_out, vector_list)
    print("[D] embedding_matrix saved to {}".format(matrix_fp))
    return


@click.command()
@click.option('-i', '--input-dir', required=True,
              help='IDA_acfg_disasm JSON files.')
@click.option('--num-workers',
              default=20,
              help='Number of workers for parallel execution')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(input_dir, num_workers, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    create_training_file(input_dir, output_dir)
    train_instruction_embeddings(output_dir, num_workers)


if __name__ == '__main__':
    main()
