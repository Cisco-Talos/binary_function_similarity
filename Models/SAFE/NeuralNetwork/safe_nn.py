#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
#  SAFE Neural Network                                                       #
#                                                                            #
#  This implementation contains code from                                    #
#  https://github.com/gadiluna/SAFE licensed under GPL-3.0                   #
#                                                                            #
##############################################################################

import argparse
import coloredlogs
import logging
import os

from core import SAFEModel
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
    LOG_NAME = 'safe'

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
    return


def model_train(config, restore):
    """
    Train the model

    Args
        config: model configuration dictionary
        restore: boolean. If True, continue the training from the latest
          checkpoint
    """
    safe_model = SAFEModel(config)
    safe_model.model_train(restore)
    return


def model_validate(config):
    """
    Evaluate the model on validation dataset

    Args
        config: model configuration dictionary
    """
    safe_model = SAFEModel(config)
    safe_model.model_validate()
    return


def model_test(config):
    """
    Test the model

    Args
        config: model configuration dictionary
    """
    safe_model = SAFEModel(config)
    safe_model.model_test()
    return


def main():
    parser = argparse.ArgumentParser(
        prog='safe',
        description='SAFE: Self-Attentive Function Embeddings',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Log level debug')

    group0 = parser.add_mutually_exclusive_group(required=True)
    group0.add_argument('--train', action='store_true',
                        help='Train the model')
    group0.add_argument('--validate', action='store_true',
                        help='Run model validation')
    group0.add_argument('--test', action='store_true',
                        help='Run model testing')

    parser.add_argument("--featuresdir",
                        default="/preprocessing",
                        help="Path to the Preprocessing dir")

    parser.add_argument("--embedding_matrix",
                        default="/instruction_embeddings/embeddings.npy",
                        help="Path to the embeddings matrix")

    parser.add_argument("--random_embeddings",
                        action="store_true", default=False,
                        help="Use random embeddings")

    parser.add_argument("--trainable_embeddings",
                        action="store_true", default=False,
                        help="Train instruction embeddings")

    parser.add_argument("--max_instructions",
                        type=int, default=150,
                        help="Max num of instructions per function")

    parser.add_argument('--num_epochs', type=int,
                        required=False, default=2,
                        help='Number of training epochs')

    parser.add_argument('--restore',
                        action='store_true', default=False,
                        help='Continue the training from the last checkpoint')

    parser.add_argument('--dataset', required=True,
                        choices=['one', 'two', 'vuln'],
                        help='Choose the dataset to use for the train or test')

    parser.add_argument('-c', '--checkpointdir', required=True,
                        help='Input/output for model checkpoint')

    parser.add_argument('-o', '--outputdir', required=True,
                        help='Output dir')

    args = parser.parse_args()

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

    return


if __name__ == '__main__':
    main()
