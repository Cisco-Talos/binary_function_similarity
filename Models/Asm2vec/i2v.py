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
#  PVDM / PVDBOW / Asm2vec neural network                                    #
#                                                                            #
##############################################################################


import argparse
import coloredlogs
import json
import logging
import os
import pandas as pd
import sys

from scipy.spatial.distance import cosine
from sklearn import metrics
from tqdm import tqdm
from gensim.models.asm2vec import Asm2Vec
from gensim.models.asm2vec import Function
from gensim.models.asm2vec import Instruction
from gensim.models.callbacks import CallbackAny2Vec
from gensim.models.doc2vec import Doc2Vec
from gensim.models.doc2vec import TaggedDocument

log = None
doc_keys = None


def set_logger(debug, outputdir):
    """
    Set logger level, syntax, and logfile.

    Args
        debug: if True, set the log level to DEBUG
        outputdir: path of the output directory for the logfile
    """
    LOG_NAME = 'i2v'

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


def load_model_checkpoint(checkpoint_dir, config):
    """
    Load the Gensim checkpoint.

    Args
       checkpoint_dir: the dir with the model checkpoint
       config: model configuration dictionary

    Retun
        the Gensim model
    """
    checkpoint_path = os.path.join(
        checkpoint_dir,
        "{}_checkpoint".format(config['model_name'])
    )

    log.info("[*] Loading model from {}".format(checkpoint_path))
    if not os.path.isfile(checkpoint_path):
        raise Exception("Checkpoint {} not found".format(
            checkpoint_path))

    if config['model_name'] == 'asm2vec':
        return Asm2Vec.load(checkpoint_path)

    return Doc2Vec.load(checkpoint_path)


def write_model_checkpoint(model, model_name, output_dir):
    """
    Checkpoint (backup) of the Gensim model.

    Args
        model: the Gensim model (Asm2Vec or Doc2Vec)
        model_name: asm2vec of PV-*
        output_dir: where to save the model checkpoint
    """
    output_path = os.path.join(output_dir, "{}_checkpoint".format(model_name))
    model.save(output_path)
    log.info("[*] Gensim model saved to {}".format(output_path))


class GensimLogCallback(CallbackAny2Vec):
    """Log data after each (training) epoch."""

    def __init__(self, config, func2id, run_validation=False):
        self._time = None
        self._epoch_counter = 0
        self._config = config
        self._func2id = func2id
        self._run_validation = run_validation

    def on_epoch_begin(self, model):
        log.info("[*] Epoch {} started".format(self._epoch_counter))
        if self._run_validation:
            run_model_validation(
                self._config,
                model,
                self._func2id,
                self._config['validation']['positive_path'],
                self._config['validation']['negative_path'])

    def on_epoch_end(self, model):
        log.info("[*] Epoch {} ended".format(self._epoch_counter))
        self._epoch_counter += 1
        if not self._time:
            log.info("\tTraining time: {}s".format(model.total_train_time))
        else:
            log.info("\tTraining time: {}s".format(
                model.total_train_time - self._time))
        self._time = model.total_train_time


def run_gensim_training_doc2vec(doc_list, config, func2id, tokens_freq):
    """
    Gensim training with Doc2Vec.

    Args
        doc_list: list of Gensim.TaggedDocument
        config: model configuration dictionary
        func2id: a dictionary that maps functions to numerical IDs
        tokens_freq: a dictionary with tokens frequency information

    Return
        Gensim Doc2Vec model
    """
    log.info("[*] Creating Doc2Vec model")
    model = Doc2Vec(
        None,
        dm=config['dm'],
        vector_size=config['vector_size'],
        window=config['window'],
        min_count=config['min_count'],
        epochs=config['epochs'],
        seed=config['seed'],
        workers=config['workers'],
        dm_mean=config['dm_mean'],
        # dm_concat by default is set to "not concatenating".
        #  If dm_concat is set to 1 (concatenating), it will affect
        #  the amount of memory (RAM) required (bigger inner layer).
        hs=config['hs'],
        negative=config['negative'],
        # Logs model data
        compute_loss=True,
        callbacks=[GensimLogCallback(config, func2id)])

    log.info("[*] Building vocabulary")
    model.build_vocab_from_freq(
        word_freq=tokens_freq,
        keep_raw_vocab=False,
        corpus_count=len(tokens_freq))

    log.info("[*] Training started")
    model.train(
        documents=doc_list,
        corpus_file=None,
        total_examples=model.corpus_count,
        total_words=None,
        epochs=config['epochs'],
        start_alpha=model.alpha,
        end_alpha=model.min_alpha,
        callbacks=[GensimLogCallback(config, func2id)])

    log.info(" ")
    log.info("[*] Training finished")
    log.info("\tTotal training time: {}s".format(model.total_train_time))
    log.info("\tAlpha: {}".format(model.alpha))
    log.info("\tDoc-vector size: {}".format(model.docvecs.vector_size))
    log.info("\tNum of doc vv: {}".format(len(model.docvecs.vectors_docs)))
    log.info("\tNum of word vv: {}".format(len(model.wv.vectors)))
    log.info(" ")
    model.comment = config['model_name']
    log.info("\t{}".format(model))
    log.info(" ")
    return model


def run_gensim_training_asm2vec(func_list, config, func2id, tokens_freq):
    """
    Gensim training with Asm2Vec.

    Args
        func_list: list of Gensim.Function
        config: model configuration dictionary
        func2id: a dictionary that maps functions to numerical IDs
        tokens_freq: a dictionary with tokens frequency information

    Return
        Gensim Asm2Vec model
    """
    log.info("[*] Creating Asm2Vec model")
    model = Asm2Vec(None,
                    # config['vector_size'] is the token vector size
                    #   The document size is the double.
                    vector_size=config['vector_size'],
                    window=config['window'],
                    min_count=config['min_count'],
                    epochs=config['epochs'],
                    seed=config['seed'],
                    workers=config['workers'],
                    dm_mean=config['dm_mean'],
                    negative=config['negative'],
                    # Logs model data
                    compute_loss=True,
                    callbacks=[GensimLogCallback(config, func2id)])

    log.info("[*] Building vocabulary")
    model.build_vocab_from_freq(
        word_freq=tokens_freq,
        keep_raw_vocab=False,
        corpus_count=len(tokens_freq))

    log.info("[*] Training started")
    model.train(
        documents=func_list,
        corpus_file=None,
        total_examples=model.corpus_count,
        total_words=None,
        epochs=config['epochs'],
        start_alpha=model.alpha,
        end_alpha=model.min_alpha,
        callbacks=[GensimLogCallback(config, func2id)])

    log.info(" ")
    log.info("[*] Training finished")
    log.info("\tTotal training time: {}s".format(model.total_train_time))
    log.info("\tAlpha: {}".format(model.alpha))
    log.info("\tDoc-vector size: {}".format(model.docvecs.vector_size))
    log.info("\tNum of doc vv: {}".format(len(model.docvecs.vectors_docs)))
    log.info("\tNum of word vv: {}".format(len(model.wv.vectors)))
    log.info(" ")
    model.comment = config['model_name']
    log.info("\t{}".format(model))
    log.info(" ")
    return model


def run_gensim_inference_doc2vec(doc_list, config,
                                 func2id, checkpoint_model):
    """
    Run Doc2vec inference.

    Args
        doc_list: list of Gensim.TaggedDocument
        config: model configuration dictionary
        func2id: a dictionary that maps functions to numerical IDs
        checkpoint_model: the trained model

    Return
        Gensim.Doc2Vec: the (new) model after inference
    """
    log.info("[*] Creating Doc2Vec inference model")
    new_model = Doc2Vec(
        None,
        dm=config['dm'],
        vector_size=config['vector_size'],
        window=config['window'],
        min_count=config['min_count'],
        epochs=config['epochs'],
        seed=config['seed'],
        workers=config['workers'],
        dm_mean=config['dm_mean'],
        # dm_concat by default is set to "not concatenating".
        #  If dm_concat is set to 1 (concatenating), it will affect
        #  the amount of memory (RAM) required (bigger inner layer).
        hs=config['hs'],
        negative=config['negative'],
        # Logs model data
        compute_loss=True,
        callbacks=[GensimLogCallback(config, func2id)])

    log.info("[*] Copying checkpoint data to the inference model")
    new_model.reset_model_for_fast_inference(
        checkpoint_model,
        len(func2id))

    # self.quick_inference
    log.info("[D] quick_inference: {}".format(new_model.quick_inference))
    log.info("[D] len(func2id): {}".format(len(func2id)))
    log.info("[D] docvecs.count: {}".format(new_model.docvecs.count))

    log.info("[*] Started inference")
    new_model.train(
        documents=doc_list,
        corpus_file=None,
        total_examples=checkpoint_model.corpus_count,
        total_words=None,
        epochs=config['epochs'],
        start_alpha=new_model.alpha,
        end_alpha=new_model.min_alpha,
        callbacks=[GensimLogCallback(config, func2id)])

    log.info(" ")
    log.info("[*] Training finished")
    log.info("\tTotal training time: {}s".format(new_model.total_train_time))
    log.info("\tAlpha: {}".format(new_model.alpha))
    log.info("\tDoc-vector size: {}".format(new_model.docvecs.vector_size))
    log.info("\tNum of doc vv: {}".format(len(new_model.docvecs.vectors_docs)))
    log.info("\tNum of word vv: {}".format(len(new_model.wv.vectors)))
    log.info(" ")
    new_model.comment = config['model_name']
    log.info("\t{}".format(new_model))
    log.info(" ")
    return new_model


def run_gensim_inference_asm2vec(func_list, config, func2id, checkpoint_model):
    """
    Run Asm2vec inference.

    Args
        func_list: list of Gensim.Function
        config: model configuration dictionary
        func2id: a dictionary that maps functions to numerical IDs
        checkpoint_model: the trained model

    Return
        Gensim.Doc2Vec: the (new) model after inference
    """
    log.info("[*] Creating Asm2Vec inference model")
    new_model = Asm2Vec(None,
                        # config['vector_size'] is the token vector size
                        #   The document size is the double.
                        vector_size=config['vector_size'],
                        window=config['window'],
                        min_count=config['min_count'],
                        epochs=config['epochs'],
                        seed=config['seed'],
                        workers=config['workers'],
                        dm_mean=config['dm_mean'],
                        negative=config['negative'],
                        # Logs model data
                        compute_loss=True,
                        callbacks=[GensimLogCallback(config, func2id)])

    log.info("[*] Copying checkpoint data to the inference model")
    new_model.reset_model_for_fast_inference(
        checkpoint_model,
        len(func2id))

    # self.quick_inference
    log.info("[D] quick_inference: {}".format(new_model.quick_inference))
    log.info("[D] len(func2id): {}".format(len(func2id)))
    log.info("[D] docvecs.count: {}".format(new_model.docvecs.count))

    log.info("[*] Started inference")
    new_model.train(
        documents=func_list,
        corpus_file=None,
        total_examples=checkpoint_model.corpus_count,
        total_words=None,
        epochs=config['epochs'],
        start_alpha=new_model.alpha,
        end_alpha=new_model.min_alpha,
        callbacks=[GensimLogCallback(config, func2id)])

    log.info(" ")
    log.info("[*] Training finished")
    log.info("\tTotal training time: {}s".format(new_model.total_train_time))
    log.info("\tAlpha: {}".format(new_model.alpha))
    log.info("\tDoc-vector size: {}".format(new_model.docvecs.vector_size))
    log.info("\tNum of doc vv: {}".format(len(new_model.docvecs.vectors_docs)))
    log.info("\tNum of word vv: {}".format(len(new_model.wv.vectors)))
    log.info(" ")
    new_model.comment = config['model_name']
    log.info("\t{}".format(new_model))
    log.info(" ")
    return new_model


def read_rand_walks_csv(rand_walks_path):
    """
    Read random walks data and convert to a Pandas dataframe.

    Args
        rand_walks_path: path of the CSV file with random walks data

    Return
        pandas.DataFrame
    """
    log.info("[*] Loading random walks data: {}".format(rand_walks_path))
    df_random_walks = pd.read_csv(rand_walks_path, index_col=0)

    log.info("\tdf_random_walks shape: {}".format(df_random_walks.shape))
    # Remove missing values
    df_random_walks.dropna(inplace=True)
    log.info("\tdf_random_walks shape: {}".format(df_random_walks.shape))
    return df_random_walks


def create_tagged_documents(df_random_walks):
    """
    Transorm the random walks into a list of Gensim.TaggedDocument.

    Args
        df_random_walks: a Pandas dataframe with random walks

    Return
        list: a list of Gensim.TaggedDocument
    """
    log.info("[*] Creating TaggedDocument list")
    doc_list = list()
    for func_id, row in tqdm(df_random_walks.iterrows(),
                             total=df_random_walks.shape[0]):
        tokens = row['random_walk'].split(";")
        doc_list.append(TaggedDocument(tokens, [int(func_id)]))

    log.info("\tProcessed {} random walks.".format(len(doc_list)))
    return doc_list


def create_gensim_functions_list(df_random_walks):
    """
    Transorm the random walks into a list of Gensim.Functions.

    Args
        df_random_walks: a Pandas dataframe with random walks

    Return
        list: a list of Gensim.Functions
    """
    log.info("[*] Creating a list of Gensim.Functions")
    func_list = list()
    for func_id, row in tqdm(df_random_walks.iterrows(),
                             total=df_random_walks.shape[0]):
        f = list()
        instructions = row['random_walk'].split(";")
        for ins in instructions:
            ins_splits = ins.split("::")
            f.append(Instruction(ins_splits[0], ins_splits[1:]))
        # Function is a custom class that operates similarly to TaggedDocument
        func_list.append(Function(f, [int(func_id)]))

    log.info("\tProcessed {} random walks.".format(len(func_list)))
    return func_list


def cosine_similarity(e1, e2):
    return 1 - cosine(e1, e2)


def get_indexes_by_db_type(df_input):
    """
    Divide rows based on the test time.

    Args
        df_input: a Pandas.Dataframe with pairs of functions

    Return
        list: a list of tuples, where the first element is test case,
          the second is the list of indexes corresponding to that test.
    """
    db_type_list = list()

    # Look for the 'db_type' column.
    if 'db_type' not in df_input.columns:
        return db_type_list

    # Iterate over all the different values of 'db_type', in other words
    # over each test case (e.g., compiler, optimizations, ...)
    for db_type in set(df_input.db_type):
        idx_list = list(df_input[df_input['db_type'] == db_type].index)

        db_type_list.append((
            db_type,
            idx_list
        ))
    return db_type_list


def run_model_validation(config, model, func2id, df_pos_path, df_neg_path):
    """
    Run model validation.

    Args
        config: model configuration
        model: the trained model
        func2id: a dictionary that maps functions to numerical IDs
        df_pos_path: similar function pairs
        df_neg_path: different function pairs
    """
    log.info("[*] Starting model validation")
    if not (df_pos_path and df_neg_path):
        log.info("\t[!] Missing validation data")
        return

    log.info("\tReading evaluation DBs")
    df_pos = pd.read_csv(df_pos_path, index_col=0)
    df_neg = pd.read_csv(df_neg_path, index_col=0)

    for db_type, idx_list in get_indexes_by_db_type(df_pos):
        gt_list = list()
        pred_list = list()
        for idx in idx_list:
            row_pos = df_pos.iloc[idx]
            row_neg = df_neg.iloc[idx]

            idx_1 = func2id["{}:{}".format(
                row_pos['idb_path_1'],
                row_pos['fva_1'])]
            idx_2 = func2id["{}:{}".format(
                row_pos['idb_path_2'],
                row_pos['fva_2'])]

            pred_list.append(cosine_similarity(
                model.docvecs[int(idx_1)],
                model.docvecs[int(idx_2)]))
            gt_list.append(1)

            idx_1 = func2id["{}:{}".format(
                row_neg['idb_path_1'],
                row_neg['fva_1'])]
            idx_2 = func2id["{}:{}".format(
                row_neg['idb_path_2'],
                row_neg['fva_2'])]

            pred_list.append(cosine_similarity(
                model.docvecs[int(idx_1)],
                model.docvecs[int(idx_2)]))
            gt_list.append(0)

        # fpr, tpr, thresholds = metrics.roc_curve(gt_list, pred_list)
        roc_auc = metrics.roc_auc_score(gt_list, pred_list)
        log.info("\tAUC {} = {:.2}".format(db_type, roc_auc))


def model_training(config, func2id, args):
    """
    Train the model. Run validation (optional).

    Args
        config: model configuration dictionary
        func2id: a dictionary that maps functions to numerical IDs
        args: command line arguments
    """
    with open(config['training']['tokens_counter_path']) as f_in:
        tokens_freq = json.load(f_in)
    df_random_walks = read_rand_walks_csv(config['rwalks_path'])

    if config['model_name'] != 'asm2vec':
        # doc2vec
        rwalks_list = create_tagged_documents(df_random_walks)
        model = run_gensim_training_doc2vec(
            rwalks_list, config, func2id, tokens_freq)
    else:
        # asm2vec
        functions = create_gensim_functions_list(df_random_walks)
        model = run_gensim_training_asm2vec(
            functions, config, func2id, tokens_freq)

    # Save the results
    write_model_checkpoint(
        model,
        config['model_name'],
        args.outputdir)

    # Run validation
    run_model_validation(
        config, model, func2id,
        config['validation']['positive_path'],
        config['validation']['negative_path'])


def write_embeddings_to_file(emb_dict, outputdir):
    """
    Write function embeddings to file

    Args
        emb_dict: the dictionary of embeddings
        outputdir: where to save the embeddings
    """
    output_path = os.path.join(outputdir, "embeddings.csv")
    with open(output_path, "w") as f_out:

        f_out.write("idb_path,fva,embeddings\n")
        for key in emb_dict.keys():
            splits = key.split(":")
            idb_path = splits[0]
            fva = splits[1]
            embedding = ';'.join([str(x) for x in emb_dict[key]])
            f_out.write("{},{},{}\n".format(idb_path, fva, embedding))

    log.info("[*] Document embeddings saved to {}".format(output_path))


def model_inference(config, func2id, args):
    """
    Test the model.

    Args
        config: model configuration dictionary
        func2id: a dictionary that maps functions to numerical IDs
        args: command line arguments
    """
    if not args.checkpoint_dir:
        log.error("--checkpoint requied for evaluation")
        sys.exit(1)

    # Restore model data
    checkpoint_model = load_model_checkpoint(args.checkpoint_dir, config)

    df_random_walks = read_rand_walks_csv(config['rwalks_path'])
    if config['model_name'] != 'asm2vec':
        # doc2vec
        rwalks_list = create_tagged_documents(df_random_walks)
        inference_model = run_gensim_inference_doc2vec(
            rwalks_list, config, func2id, checkpoint_model)
    else:
        # asm2vec
        functions = create_gensim_functions_list(df_random_walks)
        inference_model = run_gensim_inference_asm2vec(
            functions, config, func2id, checkpoint_model)

    # Convert from int to func name.
    result_dict = dict()
    for func in func2id.keys():
        result_dict[func] = inference_model.docvecs[func2id[func]]

    write_embeddings_to_file(
        emb_dict=result_dict,
        outputdir=args.outputdir)


def main():
    parser = argparse.ArgumentParser(
        prog='i2v.py',
        description='i2v.py - Gensim version',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Log level debug')
    parser.add_argument('--inputdir', required=True,
                        help='Input directory with random_walk data')
    parser.add_argument('-c', '--checkpoint', dest="checkpoint_dir",
                        help='Load model from checkpoint path')

    group0 = parser.add_mutually_exclusive_group(required=True)
    group0.add_argument('--pvdm', action='store_true',
                        help='Distributed Memory')
    group0.add_argument('--pvdbow', action='store_true',
                        help='Distributed Bag Of Words')
    group0.add_argument('--asm2vec', action='store_true',
                        help='asm2vec model version')

    group0 = parser.add_mutually_exclusive_group(required=True)
    group0.add_argument('--train', action='store_true',
                        help='Run model training')
    group0.add_argument('--inference', action='store_true',
                        help='Run model inference')

    parser.add_argument('-e', '--epochs', type=int, default=1,
                        help='Number of training epochs')

    parser.add_argument('-w', '--workers', type=int, default=2,
                        help='Number of workers to process the input')

    parser.add_argument('-o', '--outputdir', required=True,
                        help='Output dir for logs and checkpoints')

    args = parser.parse_args()

    # Create the output directory
    if args.outputdir:
        if not os.path.isdir(args.outputdir):
            os.mkdir(args.outputdir)
            print("Created outputdir: {}".format(args.outputdir))

    # Create logger
    set_logger(args.debug, args.outputdir)

    config = {
        # FIXED PARAM
        # Max distance from the center to the left-right instruction or token
        'window': 1,

        # Frequency filtering is already done in i2v_preprocessing.py
        'min_count': 1,

        # Number of epochs for training / inference
        'epochs': args.epochs,

        # FIXED PARAM
        # Do the average instead of the SUM
        # If 0, use the sum of the context word vectors. If 1, use the mean.
        #    Only applies when `dm` is set to "not concatenating".
        'dm_mean': 1,

        # FIXED PARAM
        # Negative sampling
        'negative': 25,

        # FIXED PARAM
        # INFO: In a real world setup use Gensim default value = 1
        # To replicate results
        'seed': 11,

        # Number of parallel  workers
        'workers': args.workers,

        # Map each selected function to a numerical ID
        'id2func_path': os.path.join(args.inputdir, "id2func.json"),

        # Random walks over the selected functions
        'rwalks_path': os.path.join(args.inputdir, "random_walks_{}.csv"),

        'training': {
            # Map each token to its frequency counter
            'tokens_counter_path': os.path.join(
                args.inputdir, "counter_dict.json"),
        },
        'validation': dict(
            # CSV with function pairs for validation
            positive_path=None,
            negative_path=None
        )
    }

    if args.pvdm:
        # If `dm=1`, 'distributed memory' (PV-DM) is used.
        config['dm'] = 1
        # Use 'negative sampling'.
        config['hs'] = 0
        config['model_name'] = 'PV-DM'
        # FIXED PARAM
        # Embedding size: doc and word dimensions are equal
        config['vector_size'] = 200
        config['rwalks_path'] = config['rwalks_path'].format("d2v")

    if args.pvdbow:
        # If `dm=0`,`distributed bag of words` (PV-DBOW) is used.
        config['dm'] = 0
        # Use 'negative sampling'.
        config['hs'] = 0
        config['model_name'] = 'PV-DBOW'
        # FIXED PARAM
        # Embedding size: doc and word dimensions are equal
        config['vector_size'] = 200
        config['rwalks_path'] = config['rwalks_path'].format("d2v")

    if args.asm2vec:
        config['model_name'] = 'asm2vec'
        # FIXED PARAM
        # Word vector dimension. Doc vector is the double.
        config['vector_size'] = 100
        config['rwalks_path'] = config['rwalks_path'].format("a2v")

    log.info("[*] Model configuration:")
    print(json.dumps(config, sort_keys=True, indent=4))

    # Map functions to IDs
    with open(config['id2func_path']) as f_in:
        id2func = json.load(f_in)
    func2id = {y: int(x) for x, y in id2func.items()}

    if args.train:
        log.info("[*] Run model training")
        model_training(config, func2id, args)

    if args.inference:
        log.info("[*] Run model inference")
        model_inference(config, func2id, args)


if __name__ == '__main__':
    main()
