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
#  Implementation of the models based on Graph Neural Network (GNN)          #
#    and Structure2vec (s2v).                                                #
#                                                                            #
##############################################################################

import argparse
import coloredlogs
import logging
import os
import sys

from core import S2VModel
from core import dump_config_to_json
from core import get_config

log = None


def set_logger(debug, outputdir):
    """
    Set logger level, syntax, and log file

    Args
        debug: if True, set the log level to DEBUG
        outputdir: path of the output directory for the log file
    """
    LOG_NAME = "s2v"

    global log
    log = logging.getLogger(LOG_NAME)

    fh = logging.FileHandler(os.path.join(outputdir, "{}.log".format(LOG_NAME)))
    fh.setLevel(logging.DEBUG)

    fmt = "%(asctime)s %(levelname)s:: %(message)s"
    formatter = coloredlogs.ColoredFormatter(fmt)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        loglevel = "DEBUG"
    else:
        loglevel = "INFO"
    coloredlogs.install(fmt=fmt, datefmt="%H:%M:%S", level=loglevel, logger=log)
    return


def model_train(config, restore):
    """
    Train the model

    Args
        config: model configuration dictionary
        restore: boolean. If True, continue the training from the latest
          checkpoint
    """
    s2v_model = S2VModel(config)
    s2v_model.model_train(restore)
    return


def model_validate(config):
    """
    Evaluate the model on validation dataset

    Args
        config: model configuration dictionary
    """
    s2v_model = S2VModel(config)
    s2v_model.model_validate()
    return


def model_test(config):
    """
    Test the model

    Args
        config: model configuration dictionary
    """
    s2v_model = S2VModel(config)
    s2v_model.model_test()
    return


def main():
    parser = argparse.ArgumentParser(
        prog="s2v",
        description="GNN-s2v - Graph Neural Network with Structure2vec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-d", "--debug", action="store_true", help="Log level debug")

    group0 = parser.add_mutually_exclusive_group(required=True)
    group0.add_argument("--train", action="store_true", help="Train the model")
    group0.add_argument("--validate", action="store_true", help="Run model validation")
    group0.add_argument("--test", action="store_true", help="Run model test")

    parser.add_argument(
        "--network_type",
        required=True,
        choices=["annotations", "arith_mean", "attention_mean", "rnn"],
        help="Select the type of neural network",
    )

    parser.add_argument(
        "--features_type",
        required=True,
        # choices=["none", "numerical", "asm", "opc"],
        choices=["none", "numerical", "asm"],
        help="Select the type of BB features",
    )

    parser.add_argument(
        "--featuresdir",
        default="/preprocessing",
        help="Path to the Preprocessing directory",
    )

    # Ignored if network_type == annotations
    parser.add_argument(
        "--embedding_matrix",
        default="/instruction_embeddings/embeddings.npy",
        help="Path to the embeddings matrix",
    )

     # Ignored if network_type == annotations
    parser.add_argument(
        "--max_instructions",
        type=int, default=200,
        help="Max num of instructions list per basic block")

    # Ignored if network_type == annotations
    parser.add_argument(
        "--random_embeddings",
        action="store_true",
        default=False,
        help="Use random embeddings",
    )

    # Ignored if network_type == annotations
    parser.add_argument(
        "--trainable_embeddings",
        action="store_true",
        default=False,
        help="Train instruction embeddings",
    )

    parser.add_argument(
        "--max_num_vertices",
        type=int,
        default=150,
        help="Max number of vertices in the graph",
    )

    parser.add_argument(
        "--num_epochs",
        type=int,
        required=False,
        default=2,
        help="Number of training epochs",
    )

    parser.add_argument(
        "--restore",
        action="store_true",
        default=False,
        help="Continue the training from the last checkpoint",
    )

    parser.add_argument(
        "--dataset",
        required=True,
        choices=["one", "two", "vuln"],
        help="Choose the dataset to use for the train or test",
    )

    parser.add_argument(
        "-c",
        "--checkpointdir",
        required=True,
        help="Path to the model checkpoint (input/output)",
    )

    parser.add_argument("-o", "--outputdir", required=True, help="Output dir")

    args = parser.parse_args()

    # Check on features_type
    if args.network_type == "annotations" and not args.features_type:
        print("NN annotations requires to select a features_type.")
        sys.exit(1)

    if (
        args.features_type == "none"
        or args.features_type == "numerical"
        # or args.features_type == "opc"
    ) and args.network_type != "annotations":
        print("features_type incompatible with network_type.")
        sys.exit(1)

    if args.features_type == "asm" and args.network_type == "annotations":
        print("features_type incompatible with network_type.")
        sys.exit(1)

    # Check on embeddings matrix
    if args.network_type != "annotations" and not args.embedding_matrix:
        print("Embeddings matrix is required.")
        sys.exit(1)

    # Create the output directory
    if args.outputdir:
        if not os.path.isdir(args.outputdir):
            os.mkdir(args.outputdir)
            print("Created outputdir: {}".format(args.outputdir))

    if args.featuresdir:
        if not os.path.isdir(args.featuresdir):
            print("[!] Non existing directory: {}".format(args.featuresdir))
            return

    if args.checkpointdir:
        if not os.path.isdir(args.checkpointdir):
            os.mkdir(args.checkpointdir)
            print("Created checkpointdir: {}".format(args.checkpointdir))

    # Create logger
    set_logger(args.debug, args.outputdir)

    # Load the model configuration and save to file
    config = get_config(args)
    dump_config_to_json(config, args.outputdir)

    if args.train:
        log.info("Running model training")
        model_train(config, restore=args.restore)

    if args.validate:
        log.info("Running model validation")
        model_validate(config)

    if args.test:
        log.info("Running model testing")
        model_test(config)


if __name__ == "__main__":
    main()
