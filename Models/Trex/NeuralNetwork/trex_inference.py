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
#  Trex neural network inference                                             #
#                                                                            #
##############################################################################

import click
import json
import ntpath
import os
import pandas as pd
import torch

from fairseq.models.trex import TrexModel
from tqdm import tqdm


def transform(f_dict):
    new_dict = dict()
    new_dict['static'] = f_dict['code']
    new_dict['inst_pos_emb'] = f_dict['inst_pos_emb']
    new_dict['op_pos_emb'] = f_dict['op_pos_emb']
    new_dict['arch_emb'] = f_dict['arch_emb']
    new_dict['byte1'] = " ".join(["##"] * len(new_dict['arch_emb'].split()))
    new_dict['byte2'] = " ".join(["##"] * len(new_dict['arch_emb'].split()))
    new_dict['byte3'] = " ".join(["##"] * len(new_dict['arch_emb'].split()))
    new_dict['byte4'] = " ".join(["##"] * len(new_dict['arch_emb'].split()))
    return new_dict


@click.command()
@click.option('--input-pairs', required=True,
              help='Input CSV with function pairs.')
@click.option('--input-traces', required=True,
              help='Input JSON with Trex traces.')
@click.option('--model-checkpoint-dir', required=True,
              help='Input model checkpoint directory.')
@click.option('--data-bin-dir', required=True,
              help='Input data-bin directory.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(input_pairs, input_traces, model_checkpoint_dir,
         data_bin_dir, output_dir):
    if output_dir:
        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)
            print("[D] Created outputdir: {}".format(output_dir))

    print("[D] Loading function traces")
    with open(input_traces) as f_in:
        func_traces = json.load(f_in)

    print("[D] Loading Trex model")
    trex = TrexModel.from_pretrained(
        model_checkpoint_dir,
        checkpoint_file='checkpoint_best.pt',
        data_name_or_path=data_bin_dir,
        seq_combine='sum',
        drop_field=None)

    # print("[D] Running Trex on GPU")
    # trex.cuda()
    trex.eval()

    print("[D] Proccessing: {}".format(input_pairs))
    df = pd.read_csv(input_pairs, index_col=0)

    cs_list = list()
    iterator = df.iterrows()
    for _ in tqdm(range(df.shape[0])):
        p_row = next(iterator)[1]

        feat_a = func_traces[p_row['idb_path_1']][p_row['fva_1'].strip("L")]
        feat_b = func_traces[p_row['idb_path_2']][p_row['fva_2'].strip("L")]

        emb_a = trex.predict('similarity', trex.encode(transform(feat_a)))
        emb_b = trex.predict('similarity', trex.encode(transform(feat_b)))

        cs_list.append(torch.cosine_similarity(emb_a, emb_b)[0].item())

    # Saving the cosine similarity in the 'sim' column
    df['sim'] = cs_list[:df.shape[0]]

    pairs_fname = ntpath.basename(input_pairs)
    df_out = os.path.join(output_dir, "{}.trex_out.csv".format(pairs_fname))
    df.to_csv(df_out)
    print("[D] Results df saved to {}".format(df_out))


if __name__ == '__main__':
    main()
